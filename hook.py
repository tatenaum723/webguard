#!/usr/bin/env python3
"""Claude Code PreToolUse hook: send outbound web access through the shared web guard.

Registered for WebFetch and Bash in ~/.claude/settings.json. Decisions:

  clean, established or already allowed   -> allow   (WebFetch only; Bash falls through
                                                      to normal permissions, since a command
                                                      does more than just fetch)
  threat feed / protective DNS / deny hit -> deny    (reason goes back to the model)
  unknown domain                          -> ask     (recorded as pending, so it can also be
                                                      approved later over Signal)

The allowlist is shared with the Signal bridge: `webguard allow example.com` or `!allow
example.com` in Signal applies to both. Internal errors ask rather than silently allowing.

Limitation: this checks the URL Claude asks for. Redirects inside WebFetch are not visible
to the hook (the bridge's own fetcher re-checks every hop).
"""
import json
import os
import re
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import webguard as wg

LOG = os.path.join(wg.STATE_DIR, "hook.log")
DNS_TIMEOUT = 1.5
# things that fetch: explicit URLs, plus bare hosts given to curl/wget
URL_RE = re.compile(r"https?://[^\s'\"|;>)`]+", re.I)
BARE_RE = re.compile(r"\b(?:curl|wget|http|https|xh)\s+(?:-[^\s]+\s+)*([a-z0-9][a-z0-9.-]*\.[a-z]{2,})(?:[/:][^\s'\"|;>)`]*)?", re.I)


def decide(event, name, reason):
    return {"hookSpecificOutput": {"hookEventName": event, "permissionDecision": name,
                                   "permissionDecisionReason": reason}}


def urls_from(tool, tool_input):
    if tool in ("WebFetch", "WebSearch"):
        url = tool_input.get("url") or ""
        return [url] if url else []
    if tool == "Bash":
        cmd = tool_input.get("command") or ""
        found = URL_RE.findall(cmd)
        found += [f"https://{h}" for h in BARE_RE.findall(cmd) if not any(h in u for u in found)]
        return found
    return []


def log(record):
    try:
        os.makedirs(wg.STATE_DIR, mode=0o700, exist_ok=True)
        with open(LOG, "a") as f:
            f.write(json.dumps({"t": time.strftime("%F %T"), **record}) + "\n")
    except OSError:
        pass


def is_local(url):
    """Localhost / LAN / *.local targets: not external internet access. Claude Code can already
    reach them directly, so the guard stays out of the way (the Signal bridge still blocks them,
    where the request comes from a model talking to strangers)."""
    import urllib.parse
    host = (urllib.parse.urlsplit(url).hostname or "").lower()
    if host in ("localhost",) or host.endswith((".local", ".internal", ".lan", ".home", ".localhost")):
        return True
    try:
        return wg._bad_ip(host)
    except ValueError:
        return False


def check_urls(guard, urls, who):
    """(decision, reason) for a set of URLs. Worst verdict wins."""
    allowed = []
    for url in urls:
        if is_local(url):
            allowed.append(f"{url.split('/')[2]}: local address, not checked")
            continue
        try:
            _, _, domain, how = guard.check(url)
            allowed.append(f"{domain}: {how}")
        except wg.Blocked as e:
            if "raw IP" in str(e):               # a public IP literal: unusual but sometimes deliberate
                return "ask", f"webguard: {url} targets a raw public IP address, not a hostname"
            return "deny", f"webguard blocked this: {e}"
        except wg.Pending as e:
            guard.note_pending(e.domain, who, url, e.reason)
            return "ask", (f"webguard doesn't know {e.domain} ({e.reason}). Approve here, or from any "
                           f"device with: webguard allow {e.domain}")
    return "allow", "webguard: " + "; ".join(allowed[:4])


def main():
    try:
        event = json.load(sys.stdin)
    except (json.JSONDecodeError, ValueError):
        return
    tool = event.get("tool_name", "")
    tool_input = event.get("tool_input") or {}
    urls = urls_from(tool, tool_input)
    if not urls:
        return
    hook_event = event.get("hook_event_name", "PreToolUse")
    who = f"claude-code ({os.path.basename(event.get('cwd', '') or '?')})"
    try:
        guard = wg.build()
        if guard.dns:
            guard.dns = wg.ProtectiveDNS(query=lambda s, n: wg.dns_query(s, n, timeout=DNS_TIMEOUT))
        decision, reason = check_urls(guard, urls, who)
    except Exception as e:                      # never let a guard bug silently open the door
        decision, reason = "ask", f"webguard could not check this URL ({type(e).__name__}: {e})"
    log({"tool": tool, "urls": urls, "decision": decision, "reason": reason})
    if decision == "allow" and tool != "WebFetch":
        return                                   # a Bash command does more than fetch: normal rules apply
    print(json.dumps(decide(hook_event, decision, reason)))


if __name__ == "__main__":
    main()
