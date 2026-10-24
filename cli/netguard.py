#!/usr/bin/env python3
"""netguard — a byte-budget gate for agents that download through a metered proxy.

Design goals
------------
1. Direct first. Direct traffic costs nothing on a metered proxy plan.
2. Proxy only when the direct attempt actually stalls (connect timeout, zero bytes,
   or a dead-slow read) AND the host is on the proxy allowlist.
3. Every proxy byte is budgeted: per-call and per-day caps in ``config.json``.
   Exceeding a cap is an error, not a warning.
4. Every call is logged to a JSONL ledger, so "how much of my plan did the agent
   burn today" has an answer that a proxy client's total counter cannot give you.

The proxy address is discovered from the OS (``scutil --proxy`` on macOS); no port
is hardcoded. On Linux, set ``NETGUARD_HTTP_PROXY`` or put it in the config file.

Exit codes: 0 ok, 2 usage, 3 budget denied, 4 network failed, 5 proxy unavailable.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta
from pathlib import Path

VERSION = "1.1.0"

HOME = Path(os.environ.get("NETGUARD_HOME") or (Path.home() / ".dsh" / "netguard"))
CONFIG_PATH = HOME / "config.json"
LEDGER_PATH = HOME / "ledger.jsonl"

DEFAULT_CONFIG = {
    "version": 1,
    "route": {
        # Hosts that may use the proxy when direct stalls. Add the hosts that are
        # actually slow or blocked from your network.
        "proxy_hosts": [
            "github.com",
            "*.github.com",
            "*.githubusercontent.com",
            "codeload.github.com",
            "objects.githubusercontent.com",
            "release-assets.githubusercontent.com",
            "huggingface.co",
            "*.huggingface.co",
            "*.hf.co",
            "*.hf-mirror.com",
        ],
        # Hosts that must never use the proxy, even if the wildcard above matched.
        # Your model API, package mirrors, and update CDNs usually belong here:
        # proxying them wastes plan bytes and adds a hop.
        "direct_hosts": [
            "localhost",
            "127.0.0.1",
            "*.local",
            "*.npmmirror.com",
            "*.ustc.edu.cn",
            "*.aliyun.com",
            "*.tencentcos.cn",
            "*.myqcloud.com",
        ],
    },
    "stall": {
        "connect_timeout": 8,
        "read_timeout": 20,
        "speed_limit": 65536,  # bytes/s
        "speed_window": 10,    # seconds
        "max_time": 900,       # whole-chain budget
    },
    "budget": {
        "per_call": 134217728,  # 128 MiB
        "per_day": 314572800,   # 300 MiB
    },
    # Optional explicit proxy, overriding OS detection and NETGUARD_HTTP_PROXY.
    # Example: {"url": "http://127.0.0.1:7890"}
    "proxy": {"url": ""},
    "max_redirects": 5,
    "fail_cache_days": 7,
    "fail_cache_threshold": 2,
}


# --------------------------------------------------------------------------- utils

def now_iso() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def today_key() -> str:
    return datetime.now().strftime("%Y-%m-%d")


def human(n) -> str:
    n = float(n or 0)
    if n < 1024:
        return f"{int(n)}B"
    for unit in ("KiB", "MiB", "GiB"):
        n /= 1024
        if n < 1024 or unit == "GiB":
            return f"{n:.1f}{unit}"
    return f"{n:.1f}GiB"


def ensure_home() -> None:
    HOME.mkdir(parents=True, exist_ok=True)


def load_config() -> dict:
    cfg = json.loads(json.dumps(DEFAULT_CONFIG))
    if CONFIG_PATH.exists():
        try:
            merge(cfg, json.loads(CONFIG_PATH.read_text(encoding="utf-8")))
        except Exception as exc:
            print(f"[netguard] bad config, using defaults: {exc}", file=sys.stderr)
    return cfg


def merge(base: dict, override: dict) -> None:
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(base.get(key), dict):
            merge(base[key], value)
        else:
            base[key] = value


# ------------------------------------------------------------------ proxy discovery

_scutil = {"at": 0.0, "value": None}


def parse_proxy(value: str):
    """Accept "host:port", "127.0.0.1:7890", "http://host:port" -> (host, port)."""
    if not value:
        return None
    parsed = urllib.parse.urlparse(value if "://" in value else f"http://{value}")
    if not parsed.hostname:
        return None
    return (parsed.hostname, int(parsed.port or 80))


def _windows_proxy():
    """Read the WinINET system proxy from HKCU (best effort, no admin needed)."""
    try:
        import winreg
        path = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, path) as key:
            enabled, _ = winreg.QueryValueEx(key, "ProxyEnable")
            server, _ = winreg.QueryValueEx(key, "ProxyServer")
        if not enabled or not server:
            return None
        if "=" in server:  # "http=h:p;https=h:p"
            parts = dict(item.split("=", 1) for item in server.split(";") if "=" in item)
            server = parts.get("https") or parts.get("http") or ""
        return parse_proxy(server)
    except Exception:
        return None


def _linux_proxy():
    """Read the GNOME system proxy with gsettings (best effort)."""
    try:
        def gs(*args):
            return subprocess.run(["gsettings", *args], capture_output=True,
                                  text=True, timeout=3).stdout.strip().strip("'")
        if gs("get", "org.gnome.system.proxy", "mode") != "manual":
            return None
        host = gs("get", "org.gnome.system.proxy.https", "host")
        port = gs("get", "org.gnome.system.proxy.https", "port")
        if not host:
            host = gs("get", "org.gnome.system.proxy.http", "host")
            port = gs("get", "org.gnome.system.proxy.http", "port")
        if not host or not port:
            return None
        return (host, int(port))
    except Exception:
        return None


def proxy_source(cfg: dict | None = None) -> str:
    """Where the proxy address came from: config / env / macos / windows / gnome / none."""
    if cfg and (cfg.get("proxy") or {}).get("url"):
        return "config"
    if os.environ.get("NETGUARD_HTTP_PROXY"):
        return "env NETGUARD_HTTP_PROXY"
    return {"darwin": "macOS system proxy", "win32": "Windows system proxy"}.get(
        sys.platform, "Linux/GNOME system proxy (or none)")


def system_proxy(force: bool = False, cfg: dict | None = None):
    """Return (host, port) of the local HTTP proxy, or None. Never hardcodes a port.

    Precedence: config.proxy.url -> NETGUARD_HTTP_PROXY -> OS detection.
    """
    if cfg:
        explicit = (cfg.get("proxy") or {}).get("url")
        if explicit:
            return parse_proxy(explicit)
    env = os.environ.get("NETGUARD_HTTP_PROXY")
    if env:
        return parse_proxy(env)
    if not force and time.time() - _scutil["at"] < 5:
        return _scutil["value"]
    value = None
    if sys.platform == "darwin":
        try:
            out = subprocess.run(["scutil", "--proxy"], capture_output=True,
                                 text=True, timeout=5).stdout
            data = {k: v.strip() for k, v in re.findall(r"(\w+)\s*:\s*([^\n]+)", out)}
            if data.get("HTTPEnable") == "1" and data.get("HTTPProxy"):
                value = (data["HTTPProxy"], int(data.get("HTTPPort", "0")))
            elif data.get("HTTPSEnable") == "1" and data.get("HTTPSProxy"):
                value = (data["HTTPSProxy"], int(data.get("HTTPSPort", "0")))
            elif data.get("SOCKSEnable") == "1" and data.get("SOCKSProxy"):
                value = ("socks", int(data.get("SOCKSPort", "0")))
        except Exception:
            value = None
    elif sys.platform == "win32":
        value = _windows_proxy()
    else:
        value = _linux_proxy()
    _scutil["at"] = time.time()
    _scutil["value"] = value
    return value


def proxy_url(proxy) -> str | None:
    if not proxy or proxy[0] == "socks":
        return None  # urllib cannot speak SOCKS; ask for the HTTP proxy port
    return f"http://{proxy[0]}:{proxy[1]}"


# -------------------------------------------------------------------- route policy

def host_matches(host: str, pattern: str) -> bool:
    host = host.lower().rstrip(".")
    pattern = pattern.lower().strip()
    if not pattern:
        return False
    if pattern.startswith("*."):
        return host == pattern[2:] or host.endswith(pattern[1:])
    return host == pattern


def classify(host: str, cfg: dict) -> str:
    for pat in cfg["route"]["direct_hosts"]:
        if host_matches(host, pat):
            return "direct_first"
    for pat in cfg["route"]["proxy_hosts"]:
        if host_matches(host, pat):
            return "proxy_candidate"
    return "direct_first"


# ------------------------------------------------------------------------- ledger

def read_ledger() -> list:
    if not LEDGER_PATH.exists():
        return []
    rows = []
    for line in LEDGER_PATH.read_text(encoding="utf-8", errors="replace").splitlines():
        try:
            rows.append(json.loads(line))
        except Exception:
            continue
    return rows


def append_ledger(entry: dict) -> None:
    ensure_home()
    with LEDGER_PATH.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(entry, ensure_ascii=False) + "\n")


def proxy_bytes_on(day: str) -> int:
    return sum(int(r.get("bytes") or 0) for r in read_ledger()
               if r.get("route") == "proxy" and str(r.get("ts", ""))[:10] == day)


def recent_direct_failures(host: str, cfg: dict) -> int:
    cutoff = datetime.now().astimezone() - timedelta(days=cfg["fail_cache_days"])
    count = 0
    for row in read_ledger():
        if row.get("host") != host or row.get("route") != "direct" or row.get("ok"):
            continue
        try:
            if datetime.fromisoformat(str(row.get("ts"))) >= cutoff:
                count += 1
        except Exception:
            pass
    return count


# -------------------------------------------------------------------------- HTTP

class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Let the caller re-check every redirect hop against the routing policy."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _opener(proxy: str | None):
    handlers = [urllib.request.ProxyHandler({"http": proxy, "https": proxy} if proxy else {}),
                urllib.request.HTTPSHandler(context=ssl.create_default_context()),
                _NoRedirect()]
    return urllib.request.build_opener(*handlers)


def fetch_hop(url: str, proxy: str | None, cfg: dict, sink=None,
              max_bytes: int | None = None, method: str = "GET") -> dict:
    """One HTTP request without following redirects. Streams with a hard byte cap."""
    stall = cfg["stall"]
    started = time.time()
    req = urllib.request.Request(url, method=method, headers={
        "User-Agent": f"netguard/{VERSION}",
        "Accept": "*/*",
        "Connection": "close",
    })
    total = 0
    status = 0
    headers = {}
    try:
        with _opener(proxy).open(req, timeout=stall["connect_timeout"]) as resp:
            status = resp.status
            headers = {k.lower(): v for k, v in resp.headers.items()}
            length = headers.get("content-length")
            if max_bytes is not None and length and length.isdigit() and int(length) > max_bytes:
                return {"status": status, "bytes": 0, "seconds": time.time() - started,
                        "error": "too_large", "too_large": True, "location": None,
                        "headers": headers}
            while True:
                if time.time() - started > stall["max_time"]:
                    return {"status": status, "bytes": total,
                            "seconds": time.time() - started, "error": "max_time",
                            "location": None, "headers": headers}
                chunk = resp.read(65536)
                if not chunk:
                    break
                total += len(chunk)
                if max_bytes is not None and total > max_bytes:
                    return {"status": status, "bytes": total,
                            "seconds": time.time() - started, "error": "budget_exceeded",
                            "exceeded": True, "location": None, "headers": headers}
                if sink is not None:
                    sink(chunk)
            return {"status": status, "bytes": total, "seconds": time.time() - started,
                    "error": None, "location": None, "headers": headers}
    except urllib.error.HTTPError as exc:
        headers = {k.lower(): v for k, v in (exc.headers or {}).items()}
        location = headers.get("location")
        code = exc.code
        if 300 <= code < 400 and location:
            return {"status": code, "bytes": total, "seconds": time.time() - started,
                    "error": None, "location": location, "headers": headers}
        return {"status": code, "bytes": total, "seconds": time.time() - started,
                "error": f"http_{code}", "location": None, "headers": headers}
    except Exception as exc:
        return {"status": status, "bytes": total, "seconds": time.time() - started,
                "error": f"{type(exc).__name__}: {str(exc)[:160]}", "location": None,
                "headers": headers}


def stalled(result: dict) -> bool:
    """A stall is an error, or a non-2xx/3xx response. A successful HEAD has 0 bytes."""
    if result.get("error"):
        return True
    status = int(result.get("status") or 0)
    if 200 <= status < 400:
        return False
    return result.get("bytes", 0) == 0


def fetch_url(url: str, cfg: dict, sink=None, max_bytes: int | None = None,
              force: bool = False, no_escalate: bool = False, method: str = "GET") -> dict:
    """Fetch a URL, applying the routing policy at every redirect hop."""
    purl = proxy_url(system_proxy(force=True, cfg=cfg))
    day = today_key()
    used = proxy_bytes_on(day)
    budget = cfg["budget"]
    hops = []
    url = str(url)
    started = time.time()

    for _ in range(cfg["max_redirects"] + 1):
        parsed = urllib.parse.urlparse(url)
        host = (parsed.hostname or "").lower()
        cls = classify(host, cfg)
        route, reason = "direct", "direct_first"
        if cls == "proxy_candidate":
            if recent_direct_failures(host, cfg) >= cfg["fail_cache_threshold"] and purl:
                route, reason = "proxy", "fail_cache"
            elif purl is None:
                route, reason = "direct", "proxy_unavailable"
            else:
                route, reason = "direct", "try_direct_first"

        def do(route_name: str):
            cap = None
            if route_name == "proxy":
                remaining = budget["per_day"] - proxy_bytes_on(day)
                if force:
                    cap = max_bytes if max_bytes is not None else budget["per_call"]
                else:
                    if remaining <= 0:
                        return None
                    cap = budget["per_call"] if max_bytes is None else min(max_bytes, budget["per_call"])
                    cap = min(cap, remaining)
            else:
                cap = max_bytes
            return fetch_hop(url, purl if route_name == "proxy" else None, cfg,
                             sink=sink, max_bytes=cap, method=method)

        result = do(route)
        if route == "direct":
            hops.append({"url": url, "host": host, "route": "direct", "error": result["error"],
                         "bytes": result["bytes"]})
            if stalled(result) and cls == "proxy_candidate" and purl and not no_escalate \
                    and not result.get("too_large"):
                route, reason = "proxy", "direct_stalled"
                result = do("proxy")
                if result is None:
                    return {"ok": False, "error": "budget_denied", "route": "proxy",
                            "host": host, "hops": hops, "seconds": time.time() - started,
                            "bytes": sum(h["bytes"] for h in hops)}
                hops.append({"url": url, "host": host, "route": "proxy",
                             "error": result["error"], "bytes": result["bytes"]})
        elif route == "proxy":
            if result is None:
                return {"ok": False, "error": "budget_denied", "route": "proxy",
                        "host": host, "hops": hops, "seconds": time.time() - started,
                        "bytes": sum(h["bytes"] for h in hops)}
            hops.append({"url": url, "host": host, "route": "proxy", "error": result["error"],
                         "bytes": result["bytes"]})

        location = result.get("location")
        if 300 <= result.get("status", 0) < 400 and location:
            url = urllib.parse.urljoin(url, location)
            continue
        total = sum(h["bytes"] for h in hops)
        ok = result.get("error") is None and not result.get("exceeded")
        return {"ok": ok, "status": result.get("status"), "error": result.get("error"),
                "exceeded": result.get("exceeded", False), "too_large": result.get("too_large", False),
                "route": hops[-1]["route"] if hops else "direct", "host": host,
                "bytes": total, "seconds": time.time() - started, "hops": hops}
    return {"ok": False, "error": "too_many_redirects", "route": "direct",
            "host": (urllib.parse.urlparse(url).hostname or ""), "hops": hops,
            "bytes": sum(h["bytes"] for h in hops), "seconds": time.time() - started}


# ---------------------------------------------------------------------- commands

def viewturbo_status():
    """Optional: read a local proxy client's own /status counters (no extra traffic)."""
    try:
        req = urllib.request.Request("http://127.0.0.1:15731/status",
                                     headers={"Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=1.5) as resp:
            data = (json.loads(resp.read().decode("utf-8")).get("data") or {})
        if not data.get("running"):
            return {"running": False}
        return {"running": True, "sent_bytes": data.get("sent_bytes"),
                "received_bytes": data.get("received_bytes")}
    except Exception:
        return None


def cmd_status(args, cfg) -> int:
    proxy = system_proxy(force=True, cfg=cfg)
    purl = proxy_url(proxy)
    used = proxy_bytes_on(today_key())
    if purl:
        proxy_line = f"{purl}  [{proxy_source(cfg)}]"
    else:
        proxy_line = f"none  [{proxy_source(cfg)}]"
    info = {
        "version": VERSION, "time": now_iso(), "proxy": purl,
        "today_proxy_bytes": used, "per_day": cfg["budget"]["per_day"],
        "per_call": cfg["budget"]["per_call"], "ledger": str(LEDGER_PATH),
        "proxy_source": proxy_source(cfg),
    }
    print(f"netguard {VERSION}")
    print(f"time         : {info['time']}")
    print(f"proxy        : {proxy_line}")
    print(f"today proxy  : {human(used)} / {human(cfg['budget']['per_day'])}"
          f"  (remaining {human(max(0, cfg['budget']['per_day'] - used))})")
    print(f"per-call cap : {human(cfg['budget']['per_call'])}")
    print(f"ledger       : {LEDGER_PATH}")
    if args.json:
        print(json.dumps(info, ensure_ascii=False))
    return 0


def cmd_probe(args, cfg) -> int:
    host = (urllib.parse.urlparse(args.url).hostname or "").lower()
    cls = classify(host, cfg)
    purl = proxy_url(system_proxy(force=True, cfg=cfg))
    direct = fetch_hop(args.url, None, cfg, method="HEAD")
    recommend = "direct"
    reason = "direct_ok"
    if stalled(direct):
        if cls == "proxy_candidate" and purl:
            recommend, reason = "proxy", "direct_stalled"
        elif cls == "direct_first":
            reason = "direct_failed_but_not_allowlisted"
        elif purl is None:
            recommend, reason = "none", "proxy_unavailable"
    payload = {"url": args.url, "host": host, "class": cls, "recommended": recommend,
               "reason": reason, "direct": direct}
    if args.json:
        print(json.dumps(payload, ensure_ascii=False))
    else:
        state = "ok" if not stalled(direct) else f"failed ({direct['error']})"
        print(f"host        : {host}  [{cls}]")
        print(f"direct      : {state}  {direct['seconds']:.2f}s")
        print(f"recommended : {recommend}  ({reason})")
    return 5 if recommend == "none" else 0


def cmd_dl(args, cfg) -> int:
    out = Path(args.output or Path(urllib.parse.urlparse(args.url).path).name or "download.bin")
    out.parent.mkdir(parents=True, exist_ok=True)
    part = out.with_suffix(out.suffix + ".part")
    fh = part.open("wb")
    try:
        payload = fetch_url(args.url, cfg, sink=fh.write,
                            max_bytes=args.max_bytes, force=args.force,
                            no_escalate=args.no_escalate)
    finally:
        fh.close()

    if payload["ok"]:
        part.replace(out)
        payload["output"] = str(out)
    else:
        part.unlink(missing_ok=True)
    append_ledger({"ts": now_iso(), "url": args.url, "host": payload.get("host"),
                   "route": payload.get("route"), "bytes": payload.get("bytes", 0),
                   "seconds": round(payload.get("seconds", 0.0), 2),
                   "ok": payload["ok"], "error": payload.get("error"),
                   "output": payload.get("output"), "hops": payload.get("hops")})
    if args.json:
        print(json.dumps(payload, ensure_ascii=False))
    elif payload["ok"]:
        print(f"ok  {payload['route']:<6} {human(payload['bytes']):>9} "
              f"{payload['seconds']:>6.2f}s -> {payload['output']}")
    else:
        print(f"failed [{payload['error']}] {payload.get('host', '')}", file=sys.stderr)
    if payload["ok"]:
        return 0
    if payload.get("error") == "budget_denied":
        return 3
    if payload.get("too_large"):
        return 3
    return 4


def cmd_report(args, cfg) -> int:
    cutoff = (datetime.now() - timedelta(days=args.days - 1)).strftime("%Y-%m-%d")
    rows = [r for r in read_ledger() if str(r.get("ts", ""))[:10] >= cutoff]
    by_day, by_host = {}, {}
    for row in rows:
        day_key = str(row.get("ts", ""))[:10]
        day = by_day.setdefault(day_key, {"direct": 0, "proxy": 0, "calls": 0, "failed": 0})
        route = row.get("route") or "direct"
        day[route] = day.get(route, 0) + int(row.get("bytes") or 0)
        day["calls"] += 1
        day["failed"] += 0 if row.get("ok") else 1
        host = by_host.setdefault(row.get("host") or "?", {"direct": 0, "proxy": 0, "calls": 0})
        host[route] += int(row.get("bytes") or 0)
        host["calls"] += 1
    payload = {"days": args.days, "by_day": by_day, "by_host": by_host,
               "today_proxy_bytes": proxy_bytes_on(today_key()),
               "per_day": cfg["budget"]["per_day"]}
    if args.json:
        print(json.dumps(payload, ensure_ascii=False))
        return 0
    print(f"last {args.days} days  ({LEDGER_PATH})")
    print(f"{'date':<12}{'direct':>10}{'proxy':>10}{'calls':>7}{'failed':>7}")
    for day_key in sorted(by_day):
        row = by_day[day_key]
        print(f"{day_key:<12}{human(row['direct']):>10}{human(row['proxy']):>10}"
              f"{row['calls']:>7}{row['failed']:>7}")
    print(f"\ntoday proxy: {human(proxy_bytes_on(today_key()))} / {human(cfg['budget']['per_day'])}")
    if by_host:
        print("\nby host:")
        for host, row in sorted(by_host.items(), key=lambda kv: -kv[1]["proxy"])[:15]:
            print(f"  {host:<44}{human(row['proxy']):>10} proxy / {human(row['direct']):>10} direct")
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="netguard",
                                     description="byte-budget gate for metered proxies")
    parser.add_argument("--version", action="version", version=f"netguard {VERSION}")
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_status = sub.add_parser("status", help="proxy state and today's budget")
    p_status.add_argument("--json", action="store_true")

    p_probe = sub.add_parser("probe", help="is direct usable for this URL?")
    p_probe.add_argument("url")
    p_probe.add_argument("--json", action="store_true")

    p_dl = sub.add_parser("dl", help="download with routing policy and budget")
    p_dl.add_argument("url")
    p_dl.add_argument("-o", "--output")
    p_dl.add_argument("--max-bytes", type=int, default=None)
    p_dl.add_argument("--force", action="store_true", help="ignore today's budget")
    p_dl.add_argument("--no-escalate", action="store_true", help="never fall back to the proxy")
    p_dl.add_argument("--json", action="store_true")

    p_report = sub.add_parser("report", help="ledger summary")
    p_report.add_argument("--days", type=int, default=7)
    p_report.add_argument("--json", action="store_true")

    args = parser.parse_args(argv)
    cfg = load_config()
    ensure_home()
    return {"status": cmd_status, "probe": cmd_probe, "dl": cmd_dl,
            "report": cmd_report}[args.cmd](args, cfg)


if __name__ == "__main__":
    sys.exit(main())
