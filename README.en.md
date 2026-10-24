# dsh-traffic-guard

A **byte-budget gate for metered proxies** for [DeepSeek Harness](https://github.com/deepseek-ai/deepseek-harness) (dsh).
Agent downloads go direct by default; the local proxy is used only when a direct attempt actually stalls,
and every proxied byte is charged against a hard per-call / per-day budget and written to a local ledger.

One CLI (`netguard`, usable standalone) + one Host plugin exposing three tools:
`net_usage`, `net_probe`, `net_download`.

> 中文: [README.md](README.md)

## Why

When your egress is metered (a paid proxy plan, a mobile hotspot, a corporate gateway), **traffic is money**.
Agents make that easy to lose:

- a single `curl -O`, `git clone` or `pip install` can be hundreds of MB;
- desktop apps' **nightly auto-updaters** download full bundles in the background — we measured a single
  **347.7 MB** update, and its updater used Chromium's network stack, which **honours the system proxy**,
  so it really did spend plan traffic;
- proxy clients usually report only an account-level total, **with no per-app or per-host attribution**;
- meanwhile CLI children (curl/git/npm) often ignore the system proxy, so "some traffic goes through the
  proxy and some doesn't" and the accounting never lines up.

`dsh-traffic-guard` turns this into one auditable policy: **direct first → escalate only on stall →
hard budget → everything logged**.

## What it does

| Layer | Behaviour |
| --- | --- |
| **Routing** | Direct by default. Only hosts in `proxy_hosts` may use the proxy, and only after a direct attempt fails / returns zero bytes / reads too slowly. The proxy is discovered from the OS (`scutil --proxy` on macOS, `NETGUARD_HTTP_PROXY` elsewhere); no hardcoded port. |
| **Budget** | Proxied calls are capped per call (default 128 MiB) and per day (default 300 MiB). Exceeding either is a hard failure (exit 3); only `--force` overrides. Direct traffic is free and not charged. |
| **Redirects** | Automatic following is disabled and **every hop is re-evaluated** (borrowed from SSRF-guard plugins): a redirect from a proxy host to a direct host is re-decided, not blindly proxied. |
| **Pre-checks** | If `Content-Length` already exceeds the call budget, nothing is downloaded; while streaming, bytes are counted and the read is aborted on overflow. |
| **Timeouts** | One `max_time` budget for the whole redirect chain, so N hops cannot multiply the wait. |
| **Ledger** | One JSONL row per call: timestamp, URL, host, route, bytes, duration, outcome, matched rule. `report` aggregates by day and host. |
| **Fail cache** | A host that recently failed direct repeatedly skips the direct attempt next time, saving the 8 s stall each call. |

## Install

```bash
dsh plugin --profile <profile> add github:<you>/dsh-traffic-guard
```

or install the checkout as a local bundle with `plugin_manager` (`action: install_bundle`,
`target: <absolute path to this repository>`). The plugin has no dsh dependencies (Node builtins only),
so a linked package works.

Tools exposed to the model: `net_usage`, `net_probe`, `net_download`.

## Standalone CLI

```bash
export NETGUARD_HOME=~/.dsh/netguard      # optional, this is the default
cp cli/config.example.json "$NETGUARD_HOME/config.json"

python3 cli/netguard.py status
python3 cli/netguard.py probe https://github.com/
python3 cli/netguard.py dl https://example.com/file.zip -o /tmp/file.zip
python3 cli/netguard.py report --days 7
```

Exit codes: `0` ok, `3` budget/size refused, `4` network failure, `5` proxy needed but unavailable.

## Configuration

`$NETGUARD_HOME/config.json` (default `~/.dsh/netguard/config.json`); see
[cli/config.example.json](cli/config.example.json).

```json
{
  "route": {
    "proxy_hosts": ["github.com", "*.githubusercontent.com", "huggingface.co"],
    "direct_hosts": ["*.deepseek.com", "*.npmmirror.com", "*.aliyun.com"]
  },
  "budget": { "per_call": 134217728, "per_day": 314572800 }
}
```

`proxy_hosts` are hosts **allowed** to use the proxy when direct stalls (not "must use proxy").
`direct_hosts` are hosts that **never** use the proxy and take precedence.

## Compared with related dsh plugins

The ecosystem already has egress-security plugins; this one is about **budget and accounting**:

| Project | Focus | What we borrowed |
| --- | --- | --- |
| [JackZo400/dsh-netguard](https://github.com/JackZo400/dsh-netguard) | SSRF guard: resolve and check every IP, re-check every redirect hop, stream with a byte cap, pre-check `Content-Length` | Per-hop redirect re-evaluation, `Content-Length` pre-check, whole-chain timeout |
| [CharlotteN7/dsh-netguard](https://github.com/CharlotteN7/dsh-netguard) | Host allowlist for `web_fetch`/`web_search`, pre-execute destination checks, audit-first mode | Audit-first framing (record first, constrain only proxy spend) |
| [wtdwang/dsh-tool-netguard](https://github.com/wtdwang/dsh-tool-netguard) | Split "egress" vs "ingress", `tools/pre-execute` + `ctx.approval` | Possible future "ask before over-budget" gate |
| [MukundaKatta/resilient-agent](https://github.com/MukundaKatta/resilient-agent) | Retries, circuit breaker, USD budget, egress allowlist, audit trace | Independent validation that budget + audit compose |

If you need SSRF / exfiltration protection, use those; this repo keeps you from burning a metered plan.

## Limitations

- **Not an OS-level firewall.** It constrains downloads that go through `netguard`. Bypassing calls
  (`curl`, `git clone`, app auto-updaters) are not stopped, though they show up in system/plan totals.
- Proxy clients generally have **no per-app attribution**; this plugin fills that gap with its own ledger,
  which only covers calls routed through it.
- The budget is a hard constraint on the agent, not on the machine: `--force` overrides it, and other
  processes can still use the same proxy.
- HTTP/HTTPS proxies only (urllib has no SOCKS support); use the client's HTTP proxy port.
- Proxy discovery: macOS `scutil --proxy`; Linux/Windows via `NETGUARD_HTTP_PROXY`.
- Contains no vendor-specific configuration formats or keys.

## Development

```bash
python3 -m unittest discover -s test -v   # 10 tests, all against a local 127.0.0.1 server
node --check index.mjs
```

## License

MIT
