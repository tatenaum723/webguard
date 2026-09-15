#!/usr/bin/env python3
"""Claude Code PreToolUse hook: send outbound web access through the shared web guard.

Registered for WebFetch and Bash in ~/.claude/settings.json. Decisions:

  clean, established or already allowed   -> allow   (WebFetch only; Bash falls through
                                                      to normal permissions, since a command
                                                      does more than just fetch)
  threat feed / protective DNS / deny hit -> deny    (reason goes back to the model)
  unknown domain                          -> ask, and recorded as pending so it can also be
                                                      approved over Signal. In bypassPermissions
                                                      mode nothing would prompt, so "ask" becomes
                                                      "deny": approve with `webguard allow <domain>`.

The allowlist is shared with the Signal bridge: `webguard allow example.com` or `!allow
example.com` in Signal applies to both. Internal errors ask rather than silently allowing.

Two rules keep this from becoming friction:
  * only shell commands that actually reach the network are inspected, so a URL inside an
    echo, a grep pattern or a commit message is ignored;
  * for shell commands only real threat verdicts block. A malformed or unresolvable URL
    mentioned in passing is skipped rather than denied (WebFetch, where the URL is the whole
    point of the call, still reports those).

Limitation: this checks the URL Claude asks for. Redirects inside WebFetch are not visible to
the hook (the bridge's own fetcher re-checks every hop). WebSearch carries only a query, so it
isn't filtered -- but any URL Claude fetches afterwards is.
"""
import json
import os
import re
import sys
import time
import urllib.parse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import webguard as wg

LOG = os.path.join(wg.STATE_DIR, "hook.log")
DNS_TIMEOUT = 1.5
URL_RE = re.compile(r"https?://[^\s'\"|;>)`]+", re.I)
BARE_RE = re.compile(r"\b(?:curl|wget|xh)\s+(?:-[^\s]+\s+)*([a-z0-9][a-z0-9.-]*\.[a-z]{2,})(?:[/:][^\s'\"|;>)`]*)?", re.I)
# Commands that can reach the network. A URL in any other command is just text.
FETCHERS = {"curl", "wget", "xh", "http", "httpie", "aria2c", "lynx", "w3m", "links", "nc", "ncat",
            "git", "pip", "pip3", "uv", "uvx", "pipx", "npm", "npx", "yarn", "pnpm", "bun", "deno",
            "go", "cargo", "gem", "docker", "podman", "helm", "kubectl", "terraform", "ansible-galaxy",
            "scp", "rsync", "sftp", "ftp", "youtube-dl", "yt-dlp", "gh", "glab", "brew", "apt-get"}
SEGMENT_RE = re.compile(r"[;&|]{1,2}|\n|\$\(|`")
TOKEN_RE = re.compile(r"[A-Za-z0-9_./-]+")
# guard complaints that mean "this isn't really a fetchable URL", not "this is dangerous"
SOFT = ("not a valid URL", "needs a public hostname", "does not resolve", "raw IP addresses")


def decide(event, name, reason):
    return {"hookSpecificOutput": {"hookEventName": event, "permissionDecision": name,
                                   "permissionDecisionReason": reason}}


def fetching_segments(cmd):
    """Command segments that invoke something capable of fetching."""
    for seg in SEGMENT_RE.split(cmd):
        if any(os.path.basename(t) in FETCHERS for t in TOKEN_RE.findall(seg)):
            yield seg


def urls_from(tool, tool_input):
    if tool in ("WebFetch", "WebSearch"):
        url = tool_input.get("url") or ""
        return [url] if url else []
    if tool == "Bash":
        found = []
        for seg in fetching_segments(tool_input.get("command") or ""):
            for url in URL_RE.findall(seg):
                if url not in found:
                    found.append(url)
            for host in BARE_RE.findall(seg):
                if not any(host in u for u in found):
                    found.append(f"https://{host}")
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
    host = (urllib.parse.urlsplit(url).hostname or "").lower()
    if host == "localhost" or host.endswith((".local", ".internal", ".lan", ".home", ".localhost")):
        return True
    try:
        return wg._bad_ip(host)
    except ValueError:
        return False


def check_urls(guard, urls, who, strict=True):
    """(decision, reason) for a set of URLs. Worst verdict wins. With strict=False (shell
    commands) only real threat verdicts block."""
    notes = []
    for url in urls:
        if is_local(url):
            notes.append("local address, not checked")
            continue
        try:
            _, _, domain, how = guard.check(url)
            notes.append(f"{domain}: {how}")
        except wg.Blocked as e:
            if not strict and any(m in str(e) for m in SOFT):
                notes.append(f"skipped ({e})")
                continue
            if "raw IP" in str(e):               # a public IP literal: unusual, sometimes deliberate
                return "ask", f"webguard: {url} targets a raw public IP address, not a hostname"
            return "deny", f"webguard blocked this: {e}"
        except wg.Pending as e:
            guard.note_pending(e.domain, who, url, e.reason)
            return "ask", (f"webguard doesn't know {e.domain} ({e.reason}). Approve here, or from any "
                           f"device with: webguard allow {e.domain}")
    return "allow", "webguard: " + "; ".join(notes[:4])


def main():
    try:
        event = json.load(sys.stdin)
    except (json.JSONDecodeError, ValueError):
        return
    tool = event.get("tool_name", "")
    urls = urls_from(tool, event.get("tool_input") or {})
    if not urls:
        return
    hook_event = event.get("hook_event_name", "PreToolUse")
    # "ask" means "fall back to normal permissions" -- but in these modes there are none,
    # so an unknown domain would be allowed silently. Fail closed instead.
    no_prompts = event.get("permission_mode") in ("bypassPermissions", "acceptEdits")
    who = f"claude-code ({os.path.basename(event.get('cwd', '') or '?')})"
    try:
        guard = wg.build()
        if guard.dns:
            guard.dns = wg.ProtectiveDNS(query=lambda s, n: wg.dns_query(s, n, timeout=DNS_TIMEOUT))
        decision, reason = check_urls(guard, urls, who, strict=(tool != "Bash"))
    except Exception as e:                      # never let a guard bug silently open the door
        decision, reason = "ask", f"webguard could not check this URL ({type(e).__name__}: {e})"
    if decision == "ask" and no_prompts:
        decision = "deny"
        reason += " (no permission prompt in this mode, so it is denied for now)"
    log({"tool": tool, "urls": urls, "decision": decision, "reason": reason, "mode": event.get("permission_mode")})
    if decision == "allow" and tool != "WebFetch":
        return                                   # a Bash command does more than fetch: normal rules apply
    print(json.dumps(decide(hook_event, decision, reason)))


if __name__ == "__main__":
    main()
