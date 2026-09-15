# webguard

One web filter for everything on this box that reaches the internet: the Signal bridge
(chat model and sandboxed `!task` agents) and Claude Code (a PreToolUse hook). One
allowlist, one pending queue — approving a site in Signal also approves it in Claude Code.

No API key required. Open threat intelligence and free protective DNS do the work;
VirusTotal is optional and only adds a layer.

## Order of checks

| # | layer | source |
|---|---|---|
| 1 | SSRF: http(s), public hostname, no credentials/raw IPs/internal names; re-checked at connect time (DNS rebinding) | built in |
| 2 | Deny-list: paste, request-capture and tunnel sites | built in + `deny` in config |
| 3 | Owner decisions | `webguard allow/deny`, `!allow`/`!deny` over Signal |
| 4 | Threat feeds, refreshed daily | [HaGeZi TIF](https://github.com/hagezi/dns-blocklists) (~2.4M domains, wildcard), [abuse.ch URLhaus](https://urlhaus.abuse.ch/), [OpenPhish](https://openphish.com/) |
| 5 | Protective DNS, live | Cloudflare `1.1.1.2` (returns `0.0.0.0` for malware), Quad9 `9.9.9.9` (NXDOMAIN vs unfiltered `9.9.9.10`) |
| 6 | Allowlist cache, 30-day expiry (layers 4–5 still run every time) | `web.db` |
| 7 | Established sites: [Tranco](https://tranco-list.eu/) top 20k that passed 4–5 | `feeds.db` |
| 8 | Reputation provider, optional | VirusTotal v3 domain lookups (nothing submitted), free-tier limits enforced |
| 9 | Otherwise: pending — a person approves it | `webguard list --pending` |

Measured 2026-09-15 against that day's live OpenPhish hosts: Cloudflare DNS caught most,
Quad9 and HaGeZi fewer but overlapping only partly, so the layers stack. 36 of the Tranco
top 20k are on HaGeZi's threat list, which is why popularity alone never allows a site.

## Use

```bash
webguard check https://example.org/     # what would happen, and why
webguard fetch https://example.org/     # fetch through the guard (text only, 2MB/15s caps)
webguard allow example.org [--days 30]  # or --days 0 for forever
webguard deny  example.org
webguard list [--pending]
webguard status
webguard update-feeds                   # webguard-feeds.timer runs this daily
```

`~/bin/webguard` wraps `webguard.py`; state lives in `~/.local/state/webguard`
(`feeds.db` ~90 MB, `web.db`, `hook.log`), config in `~/.config/webguard/config.toml`.

## Claude Code hook

`hook.py` is registered as a PreToolUse hook for WebFetch and Bash:

- known-good → allowed (WebFetch only; a Bash command does more than fetch, so it falls
  through to normal permissions)
- threat feed / DNS / deny-list hit → denied, with the reason returned to the model
- unknown domain → asks, and is recorded as pending so it can also be approved from Signal.
  In `bypassPermissions` / `acceptEdits` mode nothing would prompt, so it is denied instead —
  approve with `webguard allow <domain>`
- localhost / LAN targets → ignored (Claude Code can reach them anyway)
- guard failure → asks, never silently allows

Two rules keep it from becoming friction:

- only shell commands that actually reach the network are inspected (`curl`, `git`, `pip`, …),
  so a URL inside an `echo`, a `grep` pattern or a commit message is ignored;
- for shell commands, only real threat verdicts block. A malformed or unresolvable URL, or a
  raw IP, is skipped rather than denied (WebFetch, where the URL is the point of the call,
  still reports those).

It checks the URL Claude asks for; redirects inside WebFetch aren't visible to the hook.
WebSearch carries only a query, so it isn't filtered — but any URL Claude then fetches is.
The hook constrains what gets fetched, not the agent: anything with shell access can run
`webguard allow`. Claude should ask a person before approving a domain, not self-approve.

`python3 manual_check.py` prints the decisions for a set of realistic cases against the live guard.

Every decision is logged to `~/.local/state/webguard/hook.log`.

## Consumers

- Signal bridge (`~/signal-bridge`): `fetch_url` tool in chat, `python3 /cfg/webfetch` in the
  sandbox. Imports this package via a `.pth` file in its venv.
- Claude Code: `~/.claude/settings.json` hooks.

```bash
python3 -m unittest test_webguard test_hook     # offline: fake resolver, DNS, feeds, HTTP
```
