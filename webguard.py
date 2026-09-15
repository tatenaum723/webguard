"""Filtered web access for everything on this box that reaches the internet.

Shared by the Signal bridge (chat model + sandboxed omp tasks) and by Claude Code
(a PreToolUse hook). One allowlist, one set of feeds, one place to say yes or no:
an approval given over Signal also applies in Claude Code, and the other way round.

  webguard check <url>     what would happen, and why
  webguard fetch <url>     fetch it through the guard
  webguard allow|deny <domain> [--days N]
  webguard list [--pending]
  webguard status
  webguard update-feeds    (systemd timer runs this daily)


Every fetch goes through `WebGuard.check(url)`, layer by layer:

  1. SSRF: http(s) with a real public hostname only -- no credentials, no raw IPs,
     no internal names, and it must not resolve to loopback/private/link-local/
     metadata addresses. The resolved address is re-checked at connect time too
     (defeats DNS rebinding).
  2. Deny-list: paste / request-capture / tunnel sites (easy exfiltration channels).
  3. Owner decisions (!allow / !deny) -- these override everything below.
  4. Open threat-intel feeds, refreshed daily, no key needed:
       HaGeZi Threat Intelligence Feeds (wildcard), abuse.ch URLhaus, OpenPhish.
  5. Protective DNS, live, no key needed: Cloudflare 1.1.1.2 (answers 0.0.0.0 for
     malware/phishing) and Quad9 9.9.9.9 (NXDOMAIN while unfiltered 9.9.9.10 resolves).
  6. Allowlist cache (domain level, 30-day expiry) from earlier clean verdicts.
  7. Established domains: Tranco top-N list (research ranking) -> allow for 30 days.
  8. Reputation provider if a key is configured (VirusTotal domain lookup, no submissions).
  9. Otherwise PENDING -- the owner approves with !allow <domain>.

Layers 4-5 run on every fetch, including cached domains, so a domain that goes
bad inside its 30 days is still caught. Fetches are GET-only, size/time limited,
text-only, and every redirect hop is re-checked. Fetched content is returned as
text for the model and must be treated as untrusted input.
"""
import html.parser
import http.client
import ipaddress
import json
import os
import re
import socket
import random
import sqlite3
import ssl
import struct
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
import io

STATE_DIR = os.path.expanduser(os.environ.get("WEBGUARD_STATE", "~/.local/state/webguard"))
CONFIG_PATH = os.path.expanduser(os.environ.get("WEBGUARD_CONFIG", "~/.config/webguard/config.toml"))
DEFAULTS = {"state_dir": STATE_DIR, "key_file": "~/.config/webguard/virustotal.key", "protective_dns": True,
            "auto_allow_top": 20000, "deny": []}

ALLOW_TTL = 30 * 86400
BLOCK_TTL = 30 * 86400
MAX_BYTES = 2 * 1024 * 1024
MAX_TEXT = 12000
TIMEOUT = 15
MAX_REDIRECTS = 5
TEXT_TYPES = ("text/", "application/json", "application/xml", "application/xhtml", "application/rss", "application/atom")

DEFAULT_DENY = {
    # paste / file drop / request capture / tunnels: easy exfiltration or staging channels
    "pastebin.com", "paste.ee", "hastebin.com", "ghostbin.co", "rentry.co", "privatebin.net", "controlc.com",
    "webhook.site", "requestbin.com", "pipedream.net", "beeceptor.com", "hookbin.com", "requestcatcher.com",
    "ngrok.io", "ngrok-free.app", "ngrok.app", "trycloudflare.com", "localtunnel.me", "loca.lt", "serveo.net",
    "transfer.sh", "file.io", "anonfiles.com", "gofile.io", "catbox.moe", "temp.sh", "bashupload.com",
    "interact.sh", "oast.fun", "oast.pro", "oast.live", "burpcollector.net", "canarytokens.com", "dnslog.cn",
}

# Minimal multi-label public suffixes so "bbc.co.uk" is the registrable domain, not "co.uk".
MULTI_SUFFIXES = {"co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au", "co.nz", "co.jp", "com.br",
                  "com.cn", "com.mx", "co.in", "co.za", "com.sg", "com.tr", "github.io", "gitlab.io", "pages.dev",
                  "vercel.app", "netlify.app", "herokuapp.com", "blogspot.com", "azurewebsites.net",
                  "cloudfront.net", "amazonaws.com", "web.app", "firebaseapp.com"}


class Blocked(Exception):
    pass


class Pending(Exception):
    """Domain needs owner approval (!allow <domain>)."""
    def __init__(self, domain, reason):
        super().__init__(f"{domain}: {reason}")
        self.domain, self.reason = domain, reason


def registrable_domain(host):
    labels = host.lower().rstrip(".").split(".")
    if len(labels) >= 3 and ".".join(labels[-2:]) in MULTI_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:]) if len(labels) >= 2 else host.lower()


def _bad_ip(ip):
    ip = ipaddress.ip_address(ip)
    if ip.version == 6 and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved
            or ip.is_unspecified or str(ip).startswith("100.64.") or str(ip) == "169.254.169.254")


def validate_url(url, resolver=socket.getaddrinfo):
    """Return (normalized_url, host) or raise Blocked."""
    try:
        u = urllib.parse.urlsplit(url.strip())
    except ValueError:
        raise Blocked("not a valid URL")
    if u.scheme not in ("http", "https"):
        raise Blocked("only http and https URLs are allowed")
    if u.username or u.password:
        raise Blocked("URLs with embedded credentials are not allowed")
    host = (u.hostname or "").lower()
    if not host or "." not in host:
        raise Blocked("URL needs a public hostname")
    try:
        ipaddress.ip_address(host)
        raise Blocked("raw IP addresses are not allowed; use a hostname")
    except ValueError:
        pass
    if host.endswith((".local", ".internal", ".lan", ".home", ".localhost", ".arpa")):
        raise Blocked("internal hostnames are not allowed")
    try:
        infos = resolver(host, u.port or (443 if u.scheme == "https" else 80), proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        raise Blocked(f"{host} does not resolve")
    for info in infos:
        if _bad_ip(info[4][0]):
            raise Blocked(f"{host} resolves to an internal address")
    return urllib.parse.urlunsplit((u.scheme, u.netloc.lower(), u.path or "/", u.query, "")), host


# --------------------------------------------------------------------------- threat feeds
FEEDS = {
    # name: (url, format, wildcard) -- wildcard entries also block every subdomain
    "hagezi-tif": ("https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/tif-onlydomains.txt", "domains", True),
    "urlhaus": ("https://urlhaus.abuse.ch/downloads/hostfile/", "hosts", False),
    "openphish": ("https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt", "urls", False),
}
TRANCO_URL = "https://tranco-list.eu/top-1m.csv.zip"
FEED_MAX_BYTES = 120 * 1024 * 1024
FEED_REFRESH = 86400
_HOST_RE = re.compile(r"^[a-z0-9_]([a-z0-9_-]{0,62}\.)+[a-z0-9-]{2,63}$")


def _download(url):
    req = urllib.request.Request(url, headers={"User-Agent": "signal-bridge-feeds/1.0"})
    with urllib.request.urlopen(req, timeout=120) as r:
        data = r.read(FEED_MAX_BYTES + 1)
    if len(data) > FEED_MAX_BYTES:
        raise ValueError(f"{url} is larger than {FEED_MAX_BYTES} bytes")
    return data


def parse_feed(data, fmt):
    for line in data.decode("utf-8", "replace").splitlines():
        line = line.strip()
        if not line or line[0] in "#!;":
            continue
        if fmt == "hosts":
            parts = line.split()
            line = parts[1] if len(parts) >= 2 else ""
        elif fmt == "urls":
            try:
                line = urllib.parse.urlsplit(line).hostname or ""
            except ValueError:
                continue
        host = line.lower().rstrip(".")
        if _HOST_RE.match(host):
            yield host


def parse_tranco(data, top_n):
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        name = z.namelist()[0]
        with z.open(name) as f:
            for i, line in enumerate(io.TextIOWrapper(f, "utf-8")):
                if i >= top_n:
                    break
                rank, _, domain = line.strip().partition(",")
                yield domain.lower(), int(rank)


class ThreatFeeds:
    """Local copy of the open feeds in sqlite (millions of rows; not kept in RAM)."""

    def __init__(self, path, top_n=20000):
        self.path, self.top_n = path, top_n
        self.lock = threading.Lock()
        self.db = None
        if os.path.exists(path):
            self._open()

    def _open(self):
        self.db = sqlite3.connect(f"file:{self.path}?mode=ro", uri=True, check_same_thread=False)

    def age(self):
        try:
            return time.time() - os.stat(self.path).st_mtime
        except OSError:
            return None

    def refresh(self, downloader=_download, log=lambda m: None):
        """Download every feed into a new db, then swap it in atomically. A feed that fails keeps
        its previous rows so one outage doesn't open a hole."""
        tmp = self.path + ".new"
        if os.path.exists(tmp):
            os.remove(tmp)
        new = sqlite3.connect(tmp)
        new.execute("CREATE TABLE threats (host TEXT, source TEXT, wildcard INTEGER, PRIMARY KEY (host, source)) WITHOUT ROWID")
        new.execute("CREATE TABLE popular (domain TEXT PRIMARY KEY, rank INTEGER) WITHOUT ROWID")
        new.execute("CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT)")
        counts = {}
        for name, (url, fmt, wild) in FEEDS.items():
            try:
                rows = ((h, name, int(wild)) for h in parse_feed(downloader(url), fmt))
                new.executemany("INSERT OR IGNORE INTO threats VALUES (?,?,?)", rows)
                counts[name] = new.execute("SELECT COUNT(*) FROM threats WHERE source=?", (name,)).fetchone()[0]
            except Exception as e:
                log(f"feed {name} failed: {e}; keeping previous copy")
                if self.db:
                    with self.lock:
                        old = self.db.execute("SELECT host, source, wildcard FROM threats WHERE source=?", (name,)).fetchall()
                    new.executemany("INSERT OR IGNORE INTO threats VALUES (?,?,?)", old)
                counts[name] = f"failed ({e.__class__.__name__})"
        try:
            new.executemany("INSERT OR IGNORE INTO popular VALUES (?,?)", parse_tranco(downloader(TRANCO_URL), self.top_n))
            counts["tranco"] = new.execute("SELECT COUNT(*) FROM popular").fetchone()[0]
        except Exception as e:
            log(f"tranco failed: {e}; keeping previous copy")
            if self.db:
                with self.lock:
                    old = self.db.execute("SELECT domain, rank FROM popular").fetchall()
                new.executemany("INSERT OR IGNORE INTO popular VALUES (?,?)", old)
            counts["tranco"] = f"failed ({e.__class__.__name__})"
        new.execute("INSERT INTO meta VALUES ('updated', ?)", (time.strftime("%F %T"),))
        new.execute("INSERT INTO meta VALUES ('counts', ?)", (json.dumps(counts),))
        new.commit()
        new.close()
        with self.lock:
            if self.db:
                self.db.close()
            os.replace(tmp, self.path)
            self._open()
        return counts

    def threat(self, host):
        """Return the feed name that lists this host (or a parent domain, for wildcard feeds), else None."""
        if not self.db:
            return None
        labels = host.split(".")
        with self.lock:
            row = self.db.execute("SELECT source FROM threats WHERE host=?", (host,)).fetchone()
            if row:
                return row[0]
            for i in range(1, len(labels) - 1):
                row = self.db.execute("SELECT source FROM threats WHERE host=? AND wildcard=1",
                                      (".".join(labels[i:]),)).fetchone()
                if row:
                    return row[0]
        return None

    def rank(self, domain):
        if not self.db:
            return None
        with self.lock:
            row = self.db.execute("SELECT rank FROM popular WHERE domain=?", (domain,)).fetchone()
        return row[0] if row else None

    def info(self):
        if not self.db:
            return "threat feeds not downloaded yet"
        with self.lock:
            meta = dict(self.db.execute("SELECT key, value FROM meta").fetchall())
        return f"feeds updated {meta.get('updated')}: {meta.get('counts')}"


# --------------------------------------------------------------------------- protective DNS
def dns_query(server, name, timeout=2.0):
    """Minimal A-record lookup. Returns ("ok", [ips]) / ("nxdomain", []) / ("error", [])."""
    qid = random.getrandbits(16)
    q = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0)
    q += b"".join(bytes([len(p)]) + p.encode("idna") for p in name.split(".")) + b"\0" + struct.pack(">HH", 1, 1)
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            s.sendto(q, (server, 53))
            for _ in range(5):
                data, addr = s.recvfrom(4096)
                if addr[0] == server and len(data) >= 12 and struct.unpack(">H", data[:2])[0] == qid:
                    break
            else:
                return "error", []
    except (OSError, UnicodeError):
        return "error", []
    _, flags, qd, an, _, _ = struct.unpack(">HHHHHH", data[:12])
    rcode = flags & 0xF
    if rcode == 3:
        return "nxdomain", []
    if rcode != 0:
        return "error", []
    pos = 12

    def skip_name(pos):
        while True:
            n = data[pos]
            if n & 0xC0 == 0xC0:
                return pos + 2
            if n == 0:
                return pos + 1
            pos += n + 1
    try:
        for _ in range(qd):
            pos = skip_name(pos) + 4
        ips = []
        for _ in range(an):
            pos = skip_name(pos)
            rtype, _, _, rdlen = struct.unpack(">HHIH", data[pos:pos + 10])
            pos += 10
            if rtype == 1 and rdlen == 4:
                ips.append(socket.inet_ntoa(data[pos:pos + 4]))
            pos += rdlen
    except (IndexError, struct.error):
        return "error", []
    return "ok", ips


class ProtectiveDNS:
    """Ask resolvers that refuse to resolve known malware/phishing domains."""

    def __init__(self, query=dns_query):
        self.query = query

    def check(self, host):
        """Return a reason string if a protective resolver blocks this host, else None.
        Resolver outages never block (the other layers still apply)."""
        status, ips = self.query("1.1.1.2", host)
        if status == "ok" and "0.0.0.0" in ips:
            return "Cloudflare malware DNS (1.1.1.2) blocks it"
        status, _ = self.query("9.9.9.9", host)
        if status == "nxdomain":
            plain, ips = self.query("9.9.9.10", host)
            if plain == "ok" and ips:
                return "Quad9 threat DNS (9.9.9.9) blocks it"
        return None


# --------------------------------------------------------------------------- reputation
class VirusTotal:
    """Domain reputation via VirusTotal v3. Lookups only: nothing is submitted for scanning,
    so no URL is shared. Free tier: 4 requests/minute, 500/day (enforced here)."""
    name = "virustotal"

    def __init__(self, api_key, state_path):
        self.key = api_key
        self.state_path = state_path
        self.lock = threading.Lock()

    def _quota(self):
        with self.lock:
            now = time.time()
            try:
                st = json.load(open(self.state_path))
            except (OSError, ValueError):
                st = {"minute": [], "day": time.strftime("%F"), "count": 0}
            st["minute"] = [t for t in st["minute"] if now - t < 60]
            if st["day"] != time.strftime("%F"):
                st["day"], st["count"] = time.strftime("%F"), 0
            if len(st["minute"]) >= 4 or st["count"] >= 500:
                return False
            st["minute"].append(now)
            st["count"] += 1
            json.dump(st, open(self.state_path, "w"))
            return True

    def check(self, domain):
        if not self._quota():
            return "unknown", "VirusTotal quota reached (4/min, 500/day)"
        req = urllib.request.Request(f"https://www.virustotal.com/api/v3/domains/{urllib.parse.quote(domain)}",
                                     headers={"x-apikey": self.key, "accept": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=20) as r:
                data = json.load(r)["data"]["attributes"]
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return "unknown", "VirusTotal has never seen this domain"
            return "unknown", f"VirusTotal error HTTP {e.code}"
        except Exception as e:
            return "unknown", f"VirusTotal unreachable: {type(e).__name__}"
        stats = data.get("last_analysis_stats") or {}
        mal, sus, harmless = stats.get("malicious", 0), stats.get("suspicious", 0), stats.get("harmless", 0)
        rep = data.get("reputation", 0)
        detail = f"VT: {mal} malicious, {sus} suspicious, {harmless} harmless, reputation {rep}"
        if mal >= 1 or sus >= 2 or rep <= -10:
            return "bad", detail
        if not stats or sum(stats.values()) == 0:
            return "unknown", "VirusTotal has no analysis for this domain"
        return "clean", detail


# --------------------------------------------------------------------------- store + policy
class WebGuard:
    def __init__(self, db_path, provider=None, deny=None, resolver=socket.getaddrinfo, feeds=None, dns=None,
                 auto_allow_top=20000):
        self.db = sqlite3.connect(db_path, check_same_thread=False)
        self.db.execute("CREATE TABLE IF NOT EXISTS domains (domain TEXT PRIMARY KEY, verdict TEXT, source TEXT, "
                        "detail TEXT, checked REAL, expires REAL)")
        self.db.execute("CREATE TABLE IF NOT EXISTS quota (key TEXT, day TEXT, count INTEGER, PRIMARY KEY (key, day))")
        self.db.execute("CREATE TABLE IF NOT EXISTS pending (domain TEXT PRIMARY KEY, who TEXT, url TEXT, reason TEXT, asked REAL)")
        self.db.commit()
        self.lock = threading.Lock()
        self.provider = provider
        self.deny = set(DEFAULT_DENY) | set(deny or ())
        self.resolver = resolver
        self.feeds, self.dns, self.auto_allow_top = feeds, dns, auto_allow_top

    def _get(self, domain):
        with self.lock:
            row = self.db.execute("SELECT verdict, source, detail, expires FROM domains WHERE domain=?", (domain,)).fetchone()
        if row and (row[3] is None or row[3] > time.time()):
            return row
        return None

    def set_domain(self, domain, verdict, source, detail="", ttl=None):
        exp = None if ttl is None else time.time() + ttl
        self.clear_pending(domain)
        with self.lock:
            self.db.execute("INSERT OR REPLACE INTO domains VALUES (?,?,?,?,?,?)",
                            (domain, verdict, source, detail, time.time(), exp))
            self.db.commit()

    def remove(self, domain):
        with self.lock:
            self.db.execute("DELETE FROM domains WHERE domain=?", (domain,))
            self.db.commit()

    def note_pending(self, domain, who, url, reason):
        """Record an unknown domain someone wanted. Returns True the first time (so front ends
        only ping the owner once per domain)."""
        with self.lock:
            first = not self.db.execute("SELECT 1 FROM pending WHERE domain=?", (domain,)).fetchone()
            self.db.execute("INSERT OR REPLACE INTO pending VALUES (?,?,?,?,?)", (domain, who, url, reason, time.time()))
            self.db.commit()
        return first

    def pending(self):
        with self.lock:
            return self.db.execute("SELECT domain, who, url, reason, asked FROM pending ORDER BY asked DESC").fetchall()

    def clear_pending(self, domain):
        with self.lock:
            self.db.execute("DELETE FROM pending WHERE domain=?", (domain,))
            self.db.commit()

    def listing(self):
        with self.lock:
            return self.db.execute("SELECT domain, verdict, source, expires FROM domains ORDER BY verdict, domain").fetchall()

    def take_quota(self, key, limit):
        day = time.strftime("%F")
        with self.lock:
            row = self.db.execute("SELECT count FROM quota WHERE key=? AND day=?", (key, day)).fetchone()
            count = row[0] if row else 0
            if count >= limit:
                return False
            self.db.execute("INSERT OR REPLACE INTO quota VALUES (?,?,?)", (key, day, count + 1))
            self.db.commit()
            return True

    def check(self, url):
        """Return (url, host, domain, how) if allowed; raise Blocked or Pending."""
        url, host = validate_url(url, self.resolver)
        domain = registrable_domain(host)
        if domain in self.deny or host in self.deny:
            raise Blocked(f"{domain} is on the deny-list (paste/tunnel/request-capture sites)")
        cached = self._get(domain)
        if cached and cached[1] == "owner":
            if cached[0] == "allow":
                return url, host, domain, "allowed by owner"
            raise Blocked(f"{domain} is blocked by the owner")
        if self.feeds:
            src = self.feeds.threat(host)
            if src:
                raise Blocked(f"{host} is listed in the {src} threat feed")
        if self.dns:
            why = self.dns.check(host)
            if why:
                raise Blocked(f"{host}: {why}")
        if cached:
            verdict, source, detail, _ = cached
            if verdict == "allow":
                return url, host, domain, f"allowlisted ({source})"
            raise Blocked(f"{domain} is blocked ({source}: {detail})")
        rank = self.feeds.rank(domain) if self.feeds else None
        if rank and rank <= self.auto_allow_top:
            self.set_domain(domain, "allow", "tranco", f"Tranco rank {rank}, clean on threat feeds + DNS", ALLOW_TTL)
            return url, host, domain, f"established site (Tranco #{rank}), threat checks clean"
        if not self.provider:
            raise Pending(domain, "not an established site and not on the allowlist (threat feeds and DNS were clean)")
        verdict, detail = self.provider.check(domain)
        if verdict == "clean":
            self.set_domain(domain, "allow", self.provider.name, detail, ALLOW_TTL)
            return url, host, domain, f"checked clean ({detail})"
        if verdict == "bad":
            self.set_domain(domain, "block", self.provider.name, detail, BLOCK_TTL)
            raise Blocked(f"{domain} flagged ({detail})")
        raise Pending(domain, detail)


class _Text(html.parser.HTMLParser):
    SKIP = {"script", "style", "noscript", "svg", "template", "iframe", "head", "nav", "footer", "aside", "form", "button", "select", "dialog"}

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.parts, self.skip = [], 0

    def handle_starttag(self, tag, attrs):
        if tag in self.SKIP:
            self.skip += 1
        elif tag in ("p", "br", "li", "tr", "h1", "h2", "h3", "h4", "div", "section", "article"):
            self.parts.append("\n")

    def handle_endtag(self, tag):
        if tag in self.SKIP and self.skip:
            self.skip -= 1

    def handle_data(self, data):
        if not self.skip:
            self.parts.append(data)


def html_to_text(body):
    p = _Text()
    p.feed(body)
    text = "".join(p.parts)
    return re.sub(r"\n\s*\n+", "\n\n", re.sub(r"[ \t]+", " ", text)).strip()


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


def _checked_connection(address, *args, **kwargs):
    """socket.create_connection that refuses internal peers -- re-checked at connect
    time so a DNS answer that changes after validation (rebinding) can't reach the LAN."""
    sock = socket.create_connection(address, *args, **kwargs)
    peer = sock.getpeername()[0]
    if _bad_ip(peer):
        sock.close()
        raise Blocked(f"connection to internal address {peer} refused")
    return sock


class _SafeHTTPConnection(http.client.HTTPConnection):
    def __init__(self, *a, **k):
        super().__init__(*a, **k)
        self._create_connection = _checked_connection


class _SafeHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, *a, **k):
        super().__init__(*a, **k)
        self._create_connection = _checked_connection


class _SafeHTTPHandler(urllib.request.HTTPHandler):
    def http_open(self, req):
        return self.do_open(_SafeHTTPConnection, req)


class _SafeHTTPSHandler(urllib.request.HTTPSHandler):
    def https_open(self, req):
        return self.do_open(_SafeHTTPSConnection, req, context=ssl.create_default_context())


def safe_opener():
    return urllib.request.build_opener(urllib.request.ProxyHandler({}), _SafeHTTPHandler, _SafeHTTPSHandler, _NoRedirect)


def fetch(guard, url, opener=None):
    """GET a URL through the guard. Every redirect hop is re-checked. Returns dict."""
    opener = opener or safe_opener()
    hops = []
    for _ in range(MAX_REDIRECTS + 1):
        url, host, domain, how = guard.check(url)
        hops.append(f"{domain} ({how})")
        req = urllib.request.Request(url, method="GET", headers={
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) signal-bridge-webfetch/1.0",
            "Accept": "text/html,text/plain,application/json;q=0.9,*/*;q=0.1"})
        try:
            resp = opener.open(req, timeout=TIMEOUT)
        except urllib.error.HTTPError as e:
            if e.code in (301, 302, 303, 307, 308) and e.headers.get("Location"):
                url = urllib.parse.urljoin(url, e.headers["Location"])
                continue
            raise Blocked(f"HTTP {e.code} from {host}")
        except urllib.error.URLError as e:
            reason = getattr(e, "reason", e)
            raise reason if isinstance(reason, Blocked) else Blocked(f"could not reach {host}: {reason}")
        except (OSError, http.client.HTTPException) as e:
            raise Blocked(f"could not reach {host}: {e.__class__.__name__}")
        with resp:
            ctype = (resp.headers.get("Content-Type") or "").lower()
            if not ctype.startswith(TEXT_TYPES):
                raise Blocked(f"refusing non-text content ({ctype or 'unknown type'})")
            body = resp.read(MAX_BYTES + 1)
        truncated = len(body) > MAX_BYTES
        charset = (re.search(r"charset=([\w-]+)", ctype) or [None, "utf-8"])[1]
        text = body[:MAX_BYTES].decode(charset, errors="replace")
        if "html" in ctype:
            text = html_to_text(text)
        if len(text) > MAX_TEXT:
            text, truncated = text[:MAX_TEXT], True
        return {"url": url, "domain": domain, "hops": hops, "content_type": ctype.split(";")[0],
                "truncated": truncated, "text": text}
    raise Blocked("too many redirects")


def load_provider(key_path, state_dir):
    """VirusTotal if a key file exists (readable only by the owner), else None."""
    key_path = os.path.expanduser(key_path)
    if not os.path.exists(key_path):
        return None
    if os.stat(key_path).st_mode & 0o077:
        raise SystemExit(f"{key_path} must not be readable by other users (chmod 600)")
    key = open(key_path).read().strip()
    return VirusTotal(key, os.path.join(state_dir, "vt_quota.json")) if key else None


def load_config(path=None):
    """Config from ~/.config/webguard/config.toml (all keys optional)."""
    import tomllib
    cfg = dict(DEFAULTS)
    path = path or CONFIG_PATH
    try:
        with open(path, "rb") as f:
            cfg.update(tomllib.load(f))
    except FileNotFoundError:
        pass
    return cfg


def build(wcfg=None, log=lambda m: None):
    """Shared WebGuard. Pass a config dict (the Signal bridge passes its [web] section) or
    nothing to use ~/.config/webguard/config.toml."""
    cfg = dict(DEFAULTS)
    cfg.update(load_config() if wcfg is None else wcfg)
    state = os.path.expanduser(cfg["state_dir"])
    os.makedirs(state, mode=0o700, exist_ok=True)
    provider = load_provider(cfg["key_file"], state)
    feeds = ThreatFeeds(os.path.join(state, "feeds.db"), top_n=cfg["auto_allow_top"])
    dns = ProtectiveDNS() if cfg["protective_dns"] else None
    return WebGuard(os.path.join(state, "web.db"), provider, deny=cfg["deny"], feeds=feeds, dns=dns,
                    auto_allow_top=cfg["auto_allow_top"])


def main(argv=None):
    import argparse
    ap = argparse.ArgumentParser(prog="webguard", description=__doc__.split("\n\n")[0])
    ap.add_argument("--config", help="config file (default ~/.config/webguard/config.toml)")
    sub = ap.add_subparsers(dest="action", required=True)
    for name in ("check", "fetch"):
        sp = sub.add_parser(name)
        sp.add_argument("url")
    for name in ("allow", "deny"):
        sp = sub.add_parser(name)
        sp.add_argument("domain")
        sp.add_argument("--days", type=int, default=30 if name == "allow" else 0, help="0 = forever")
    sp = sub.add_parser("list")
    sp.add_argument("--pending", action="store_true")
    sub.add_parser("status")
    sub.add_parser("update-feeds")
    a = ap.parse_args(argv)

    import tomllib
    wcfg = None
    if a.config:
        with open(a.config, "rb") as f:
            wcfg = tomllib.load(f)
    g = build(wcfg, log=print)

    if a.action == "update-feeds":
        print(g.feeds.refresh(log=print))
    elif a.action == "status":
        print(g.feeds.info())
        print(f"protective DNS: {'on' if g.dns else 'off'}")
        print(f"reputation provider: {g.provider.name if g.provider else 'none (unknown domains need approval)'}")
        print(f"auto-allow: Tranco top {g.auto_allow_top}")
        print(f"decisions: {len(g.listing())} domains, {len(g.pending())} awaiting approval")
    elif a.action == "list":
        rows = g.pending() if a.pending else g.listing()
        for row in rows:
            if a.pending:
                d, who, url, reason, asked = row
                print(f"{d:40} {who:12} {time.strftime('%F %R', time.localtime(asked))}  {url[:60]}")
            else:
                d, verdict, source, exp = row
                until = time.strftime("%F", time.localtime(exp)) if exp else "forever"
                print(f"{verdict:6} {d:40} {source:10} until {until}")
    elif a.action in ("allow", "deny"):
        domain = registrable_domain(re.sub(r"^https?://", "", a.domain).split("/")[0])
        ttl = a.days * 86400 if a.days else None
        g.set_domain(domain, "allow" if a.action == "allow" else "block", "owner",
                     f"{a.action}ed from the command line", ttl)
        print(f"{a.action}ed {domain}" + (f" for {a.days} days" if a.days else ""))
    elif a.action == "check":
        try:
            print("ALLOW:", g.check(a.url)[3])
        except Blocked as e:
            print("BLOCK:", e)
        except Pending as e:
            print("ASK:", e)
    else:
        try:
            r = fetch(g, a.url)
            print(" -> ".join(r["hops"]), r["content_type"], "truncated" if r["truncated"] else "")
            print(r["text"])
        except (Blocked, Pending) as e:
            raise SystemExit(f"{type(e).__name__.upper()}: {e}")


if __name__ == "__main__":
    main()
