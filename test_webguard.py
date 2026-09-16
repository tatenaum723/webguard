"""Web guard tests -- no network: resolver, DNS, feeds, reputation and HTTP are all faked."""
import io
import json
import os
import socket
import sqlite3
import tempfile
import time
import unittest
import unittest.mock
import urllib.error
import zipfile
from email.message import Message

import webguard as wg

PUBLIC = "93.184.216.34"


def resolver(table):
    def resolve(host, port, proto=0):
        ip = table.get(host, PUBLIC)
        if ip is None:
            raise socket.gaierror("nxdomain")
        return [(socket.AF_INET, socket.SOCK_STREAM, proto, "", (ip, port))]
    return resolve


class FakeProvider:
    name = "fakevt"

    def __init__(self, verdicts):
        self.verdicts, self.calls = verdicts, []

    def check(self, domain):
        self.calls.append(domain)
        return self.verdicts.get(domain, ("unknown", "never seen"))


class FakeDNS:
    def __init__(self, blocked=()):
        self.blocked, self.calls = set(blocked), []

    def check(self, host):
        self.calls.append(host)
        return "Quad9 threat DNS (9.9.9.9) blocks it" if host in self.blocked else None


def make_feeds(path, threats=(), popular=()):
    """threats: [(host, source, wildcard)], popular: [(domain, rank)]"""
    tranco = io.BytesIO()
    with zipfile.ZipFile(tranco, "w") as z:
        z.writestr("top-1m.csv", "".join(f"{r},{d}\n" for d, r in popular))
    by_source = {}
    for h, src, _ in threats:
        by_source.setdefault(src, []).append(h)
    payloads = {wg.TRANCO_URL: tranco.getvalue()}
    for name, (url, fmt, wild) in wg.FEEDS.items():
        hosts = by_source.get(name, [])
        if fmt == "domains":
            body = "# comment\n" + "\n".join(hosts)
        elif fmt == "hosts":
            body = "# urlhaus\n" + "\n".join(f"127.0.0.1\t{h}" for h in hosts)
        else:
            body = "\n".join(f"https://{h}/login.php?x=1" for h in hosts)
        payloads[url] = body.encode()
    f = wg.ThreatFeeds(path, top_n=1000)
    f.refresh(downloader=lambda url: payloads[url])
    return f


class Resp(io.BytesIO):
    def __init__(self, body, ctype="text/html; charset=utf-8"):
        super().__init__(body.encode() if isinstance(body, str) else body)
        self.headers = {"Content-Type": ctype}


class FakeOpener:
    def __init__(self, routes):
        self.routes, self.seen = routes, []

    def open(self, req, timeout=None):
        self.seen.append((req.get_method(), req.full_url))
        r = self.routes[req.full_url]
        if isinstance(r, tuple) and r[0] == "redirect":
            hdrs = Message()
            hdrs["Location"] = r[1]
            raise urllib.error.HTTPError(req.full_url, 302, "Found", hdrs, None)
        return r


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.provider = FakeProvider({})
        self.dns = FakeDNS()
        self.feeds = make_feeds(os.path.join(self.tmp.name, "feeds.db"),
                                threats=[("evil-wild.com", "hagezi-tif", 1), ("bad-host.example.org", "urlhaus", 0),
                                         ("phish.github.io", "openphish", 0)],
                                popular=[("wikipedia.org", 12), ("python.org", 400), ("evil-wild.com", 500)])
        self.table = {}
        self.g = wg.WebGuard(os.path.join(self.tmp.name, "web.db"), None, resolver=resolver(self.table),
                             feeds=self.feeds, dns=self.dns, auto_allow_top=1000)

    def blocked(self, url):
        with self.assertRaises(wg.Blocked):
            self.g.check(url)


class SSRF(Base):
    def test_schemes(self):
        for u in ("file:///etc/passwd", "ftp://example.com/", "gopher://x.com/", "javascript:alert(1)"):
            self.blocked(u)

    def test_credentials_and_raw_ips(self):
        self.blocked("https://user:pw@wikipedia.org/")
        self.blocked("http://127.0.0.1:30000/v1/models")
        self.blocked("http://[::1]/")
        self.blocked("http://169.254.169.254/latest/meta-data/")
        self.blocked("http://2130706433/")

    def test_internal_names(self):
        self.blocked("http://localhost/")
        self.blocked("http://aipc.local/")
        self.blocked("http://router.lan/")

    def test_resolves_internal(self):
        self.table.update({"sneaky.com": "192.168.1.254", "meta.com": "169.254.169.254", "cgnat.com": "100.64.1.1",
                           "mapped.com": "::ffff:127.0.0.1", "gone.com": None})
        for h in self.table:
            self.blocked(f"https://{h}/")

    def test_connect_time_peer_check(self):
        srv = socket.socket()
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        self.addCleanup(srv.close)
        with self.assertRaises(wg.Blocked):
            wg._checked_connection(srv.getsockname(), timeout=2)


class Policy(Base):
    def test_deny_list(self):
        self.blocked("https://pastebin.com/raw/abc")
        self.blocked("https://abc.ngrok-free.app/")

    def test_threat_feeds_wildcard_exact(self):
        self.blocked("https://evil-wild.com/")
        self.blocked("https://a.b.evil-wild.com/")          # wildcard feed covers subdomains
        self.blocked("https://bad-host.example.org/")
        self.table["other.example.org"] = PUBLIC
        with self.assertRaises(wg.Pending):                  # exact feed does not block siblings
            self.g.check("https://other.example.org/")
        self.blocked("https://phish.github.io/x")
        with self.assertRaises(wg.Pending):
            self.g.check("https://someone.github.io/")

    def test_feeds_beat_popularity(self):
        self.blocked("https://evil-wild.com/")                # ranked 500 but listed

    def test_protective_dns(self):
        self.dns.blocked.add("fresh-phish.net")
        self.blocked("https://fresh-phish.net/")

    def test_established_site_auto_allowed_and_cached(self):
        url, host, domain, how = self.g.check("https://en.wikipedia.org/wiki/Kepler")
        self.assertEqual(domain, "wikipedia.org")
        self.assertIn("Tranco", how)
        self.assertEqual(self.g._get("wikipedia.org")[:2], ("allow", "tranco"))

    def test_unknown_pending_without_provider(self):
        with self.assertRaises(wg.Pending) as c:
            self.g.check("https://smallblog.dev/post")
        self.assertEqual(c.exception.domain, "smallblog.dev")

    def test_owner_allow_and_deny(self):
        self.g.set_domain("smallblog.dev", "allow", "owner", "", 30 * 86400)
        self.assertEqual(self.g.check("https://smallblog.dev/")[3], "allowed by owner")
        self.g.set_domain("wikipedia.org", "block", "owner", "", None)
        self.blocked("https://wikipedia.org/")

    def test_owner_allow_overrides_false_positive(self):
        self.g.set_domain("evil-wild.com", "allow", "owner", "", 86400)
        self.g.check("https://evil-wild.com/")

    def test_cached_allow_still_rechecked_against_threats(self):
        self.g.set_domain("wentbad.com", "allow", "fakevt", "", 30 * 86400)
        self.g.check("https://wentbad.com/")
        self.dns.blocked.add("wentbad.com")
        self.blocked("https://wentbad.com/")

    def test_allow_expires_after_ttl(self):
        self.g.set_domain("smallblog.dev", "allow", "fakevt", "", -1)
        with self.assertRaises(wg.Pending):
            self.g.check("https://smallblog.dev/")

    def test_provider_verdicts_cached(self):
        self.g.provider = FakeProvider({"clean.dev": ("clean", "0 malicious"), "bad.dev": ("bad", "9 malicious")})
        self.g.check("https://clean.dev/")
        self.g.check("https://www.clean.dev/other")
        self.assertEqual(self.g.provider.calls, ["clean.dev"])
        self.blocked("https://bad.dev/")
        self.blocked("https://bad.dev/again")
        self.assertEqual(self.g.provider.calls, ["clean.dev", "bad.dev"])
        with self.assertRaises(wg.Pending):
            self.g.check("https://unseen.dev/")

    def test_registrable_domain(self):
        self.assertEqual(wg.registrable_domain("news.bbc.co.uk"), "bbc.co.uk")
        self.assertEqual(wg.registrable_domain("a.b.example.com"), "example.com")
        self.assertEqual(wg.registrable_domain("alice.github.io"), "alice.github.io")

    def test_quota(self):
        self.assertTrue(all(self.g.take_quota("group:x", 3) for _ in range(3)))
        self.assertFalse(self.g.take_quota("group:x", 3))
        self.assertTrue(self.g.take_quota("owner", 3))


class Fetch(Base):
    def test_fetch_html_to_text(self):
        op = FakeOpener({"https://en.wikipedia.org/wiki/X": Resp("<html><head><title>t</title><script>evil()</script>"
                                                               "</head><body><p>Hello</p><p>World &amp; more</p></body></html>")})
        r = wg.fetch(self.g, "https://en.wikipedia.org/wiki/X", opener=op)
        self.assertEqual(r["text"], "Hello\nWorld & more")
        self.assertEqual(op.seen, [("GET", "https://en.wikipedia.org/wiki/X")])

    def test_redirect_hop_rechecked(self):
        self.table["internal.example"] = "10.0.0.5"
        op = FakeOpener({"https://en.wikipedia.org/r": ("redirect", "https://pastebin.com/raw/x")})
        with self.assertRaises(wg.Blocked):
            wg.fetch(self.g, "https://en.wikipedia.org/r", opener=op)
        self.assertEqual(len(op.seen), 1)                    # never requested the denied hop

    def test_redirect_to_unknown_is_pending(self):
        op = FakeOpener({"https://en.wikipedia.org/r": ("redirect", "/wiki/ok"),
                         "https://en.wikipedia.org/wiki/ok": ("redirect", "https://unknown-site.dev/")})
        with self.assertRaises(wg.Pending):
            wg.fetch(self.g, "https://en.wikipedia.org/r", opener=op)

    def test_redirect_loop(self):
        op = FakeOpener({"https://en.wikipedia.org/a": ("redirect", "https://en.wikipedia.org/b"),
                         "https://en.wikipedia.org/b": ("redirect", "https://en.wikipedia.org/a")})
        with self.assertRaises(wg.Blocked):
            wg.fetch(self.g, "https://en.wikipedia.org/a", opener=op)

    def test_binary_refused(self):
        op = FakeOpener({"https://python.org/f.exe": Resp(b"MZ\x90", "application/octet-stream")})
        with self.assertRaises(wg.Blocked):
            wg.fetch(self.g, "https://python.org/f.exe", opener=op)

    def test_truncation(self):
        op = FakeOpener({"https://python.org/big": Resp("x" * (wg.MAX_TEXT + 50), "text/plain")})
        r = wg.fetch(self.g, "https://python.org/big", opener=op)
        self.assertTrue(r["truncated"])
        self.assertEqual(len(r["text"]), wg.MAX_TEXT)


class Feeds(unittest.TestCase):
    def test_failed_feed_keeps_previous_rows(self):
        with tempfile.TemporaryDirectory() as d:
            f = make_feeds(os.path.join(d, "feeds.db"), threats=[("keepme.com", "hagezi-tif", 1)], popular=[("a.com", 1)])
            self.assertEqual(f.threat("x.keepme.com"), "hagezi-tif")

            def flaky(url):
                raise OSError("feed down")
            counts = f.refresh(downloader=flaky)
            self.assertIn("failed", counts["hagezi-tif"])
            self.assertEqual(f.threat("keepme.com"), "hagezi-tif")
            self.assertEqual(f.rank("a.com"), 1)

    def test_parsers_reject_junk(self):
        self.assertEqual(list(wg.parse_feed(b"# c\n127.0.0.1 ok.com\n127.0.0.1 1.2.3.4\nbad line here\n", "hosts")), ["ok.com"])
        self.assertEqual(list(wg.parse_feed(b"https://X.com/a\nnot a url\n", "urls")), ["x.com"])


class DNSParse(unittest.TestCase):
    def test_protective_dns_logic(self):
        answers = {("1.1.1.2", "cf.com"): ("ok", ["0.0.0.0"]), ("9.9.9.9", "q9.com"): ("nxdomain", []),
                   ("9.9.9.10", "q9.com"): ("ok", ["1.2.3.4"]), ("9.9.9.9", "dead.com"): ("nxdomain", []),
                   ("9.9.9.10", "dead.com"): ("nxdomain", [])}
        d = wg.ProtectiveDNS(query=lambda s, n: answers.get((s, n), ("ok", ["1.2.3.4"])))
        self.assertIn("Cloudflare", d.check("cf.com"))
        self.assertIn("Quad9", d.check("q9.com"))
        self.assertIsNone(d.check("dead.com"))               # doesn't exist anywhere: not a threat verdict
        self.assertIsNone(d.check("fine.com"))
        down = wg.ProtectiveDNS(query=lambda s, n: ("error", []))
        self.assertIsNone(down.check("x.com"))


if __name__ == "__main__":
    unittest.main(verbosity=1)


class Download(Base):
    def setUp(self):
        super().setUp()
        self.dest = os.path.join(self.tmp.name, "dl")

    def op(self, body, ctype, headers=None):
        r = Resp(body, ctype)
        if headers:
            r.headers.update(headers)
        return FakeOpener({"https://python.org/f": r})

    def test_saves_pdf_with_hash(self):
        r = wg.download(self.g, "https://python.org/f", self.dest, opener=self.op(b"%PDF-1.7 data", "application/pdf"))
        self.assertTrue(os.path.exists(r["path"]))
        self.assertEqual(r["bytes"], 13)
        self.assertEqual(len(r["sha256"]), 64)

    def test_refuses_executables_and_unknown_types(self):
        with self.assertRaises(wg.Blocked):
            wg.download(self.g, "https://python.org/f", self.dest,
                        opener=self.op(b"MZ", "application/x-msdownload"))
        with self.assertRaises(wg.Blocked):   # right type, executable name
            wg.download(self.g, "https://python.org/f", self.dest,
                        opener=self.op(b"x", "application/zip"), name="payload.sh")

    def test_size_cap_enforced_even_when_length_lies(self):
        with self.assertRaises(wg.Blocked):
            wg.download(self.g, "https://python.org/f", self.dest,
                        opener=self.op(b"x" * 5000, "application/pdf"), max_bytes=1000)
        self.assertEqual(os.listdir(self.dest), [])          # partial file cleaned up

    def test_declared_length_rejected_early(self):
        op = self.op(b"x", "application/pdf", {"Content-Length": "99999999"})
        with self.assertRaises(wg.Blocked):
            wg.download(self.g, "https://python.org/f", self.dest, opener=op, max_bytes=1000)

    def test_names_cannot_escape_the_directory(self):
        self.assertEqual(wg.safe_name("https://x.com/../../etc/passwd", "text/plain"), "passwd.txt")
        self.assertEqual(wg.safe_name("https://x.com/a%2F..%2Fb.pdf", "application/pdf"), "a_.._b.pdf")
        self.assertEqual(wg.safe_name("https://x.com/", "application/pdf"), "download.pdf")

    def test_second_file_does_not_overwrite(self):
        for _ in range(2):
            r = wg.download(self.g, "https://python.org/f", self.dest, opener=self.op(b"a", "application/pdf"))
        self.assertEqual(sorted(os.listdir(self.dest)), ["f-2.pdf", "f.pdf"])

    def test_blocked_domain_never_downloads(self):
        with self.assertRaises(wg.Blocked):
            wg.download(self.g, "https://evil-wild.com/f", self.dest, opener=self.op(b"a", "application/pdf"))


class Search(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.feeds = make_feeds(os.path.join(self.tmp.name, "f.db"), threats=[("bad-result.com", "hagezi-tif", 1)])
        self.g = wg.WebGuard(os.path.join(self.tmp.name, "w.db"), None, feeds=self.feeds)
        self.payload = {"results": [
            {"title": "Good", "url": "https://good.org/a", "content": "snippet"},
            {"title": "Bad", "url": "https://bad-result.com/x", "content": "malware"},
            {"title": "Denied", "url": "https://pastebin.com/raw/x", "content": "paste"},
            {"title": "Junk", "url": "", "content": "no url"},
        ]}

    def fake_urlopen(self, req, timeout=None):
        self.asked = req.full_url
        return Resp(json.dumps(self.payload), "application/json")

    def test_filters_threats_and_denylist(self):
        with unittest.mock.patch.object(wg.urllib.request, "urlopen", self.fake_urlopen):
            results = wg.search("cissp study guide", guard=self.g)
        self.assertEqual([r["url"] for r in results], ["https://good.org/a"])
        self.assertIn("q=cissp+study+guide", self.asked)

    def test_service_down_is_a_clear_error(self):
        def boom(req, timeout=None):
            raise wg.urllib.error.URLError("connection refused")
        with unittest.mock.patch.object(wg.urllib.request, "urlopen", boom):
            with self.assertRaises(wg.Blocked) as c:
                wg.search("x", guard=self.g)
        self.assertIn("searxng", str(c.exception))
