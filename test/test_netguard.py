"""Unit tests for cli/netguard.py (stdlib only, no external network).

The tests exercise the pure policy (routing, budgets, ledger) against a local
127.0.0.1 HTTP server, so they run in CI without a proxy or internet access.
"""

import importlib.util
import os
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TMP = tempfile.mkdtemp(prefix="netguard-test-")
os.environ["NETGUARD_HOME"] = TMP

spec = importlib.util.spec_from_file_location("netguard", ROOT / "cli" / "netguard.py")
ng = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ng)


class Handler(BaseHTTPRequestHandler):
    body = b"0123456789" * 8  # 80 bytes

    def do_HEAD(self):
        if self.path == "/r1":
            self.send_response(302)
            self.send_header("Location", "/r2")
            self.end_headers()
            return
        if self.path == "/r2":
            self.send_response(302)
            self.send_header("Location", "/file")
            self.end_headers()
            return
        if self.path == "/big":
            self.send_response(200)
            self.send_header("Content-Length", "1000000")
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("Content-Length", str(len(self.body)))
        self.end_headers()

    def do_GET(self):
        if self.path == "/r1":
            self.send_response(302)
            self.send_header("Location", "/r2")
            self.end_headers()
            return
        if self.path == "/r2":
            self.send_response(302)
            self.send_header("Location", "/file")
            self.end_headers()
            return
        if self.path == "/big":
            self.send_response(200)
            self.send_header("Content-Length", "1000000")
            self.end_headers()
            try:
                for _ in range(1000):
                    self.wfile.write(b"x" * 1000)
            except (BrokenPipeError, ConnectionResetError):
                pass  # client aborted on the size cap, as intended
            return
        self.send_response(200)
        self.send_header("Content-Length", str(len(self.body)))
        self.end_headers()
        try:
            self.wfile.write(self.body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def log_message(self, *args):
        pass


class LocalServer:
    @classmethod
    def start(cls):
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        cls.port = cls.httpd.server_address[1]
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def stop(cls):
        cls.httpd.shutdown()


def setUpModule():
    LocalServer.start()


def tearDownModule():
    LocalServer.stop()


class TestRouting(unittest.TestCase):
    def test_wildcard(self):
        self.assertTrue(ng.host_matches("raw.githubusercontent.com", "*.githubusercontent.com"))
        self.assertTrue(ng.host_matches("githubusercontent.com", "*.githubusercontent.com"))
        self.assertFalse(ng.host_matches("notgithubusercontent.com.evil.com", "*.githubusercontent.com"))
        self.assertTrue(ng.host_matches("GitHub.com", "github.com"))

    def test_classify_direct_wins(self):
        cfg = {
            "route": {
                "proxy_hosts": ["*.example.com"],
                "direct_hosts": ["api.example.com"],
            }
        }
        self.assertEqual(ng.classify("api.example.com", cfg), "direct_first")
        self.assertEqual(ng.classify("cdn.example.com", cfg), "proxy_candidate")
        self.assertEqual(ng.classify("other.org", cfg), "direct_first")

    def test_proxy_url(self):
        self.assertEqual(ng.proxy_url(("127.0.0.1", 7890)), "http://127.0.0.1:7890")
        self.assertIsNone(ng.proxy_url(("socks", 1080)))
        self.assertIsNone(ng.proxy_url(None))

    def test_human(self):
        self.assertEqual(ng.human(0), "0B")
        self.assertEqual(ng.human(1023), "1023B")
        self.assertEqual(ng.human(1024), "1.0KiB")
        self.assertEqual(ng.human(1536), "1.5KiB")


class TestLedger(unittest.TestCase):
    def setUp(self):
        ng.LEDGER_PATH.unlink(missing_ok=True)
        ng.ensure_home()

    def test_proxy_bytes_only_counts_proxy(self):
        day = ng.today_key()
        ng.append_ledger({"ts": ng.now_iso(), "host": "a", "route": "proxy", "bytes": 100, "ok": True})
        ng.append_ledger({"ts": ng.now_iso(), "host": "b", "route": "direct", "bytes": 999, "ok": True})
        self.assertEqual(ng.proxy_bytes_on(day), 100)

    def test_fail_cache(self):
        ng.append_ledger({"ts": ng.now_iso(), "host": "slow.example", "route": "direct",
                          "bytes": 0, "ok": False})
        ng.append_ledger({"ts": ng.now_iso(), "host": "slow.example", "route": "direct",
                          "bytes": 0, "ok": False})
        cfg = {"fail_cache_days": 7}
        self.assertEqual(ng.recent_direct_failures("slow.example", cfg), 2)
        self.assertEqual(ng.recent_direct_failures("fast.example", cfg), 0)


class TestFetchPolicy(unittest.TestCase):
    def setUp(self):
        ng.LEDGER_PATH.unlink(missing_ok=True)
        ng.ensure_home()
        self.cfg = ng.load_config()
        self.cfg["route"]["proxy_hosts"] = []
        self.cfg["route"]["direct_hosts"] = ["127.0.0.1"]
        self.cfg["stall"]["connect_timeout"] = 3
        self.cfg["stall"]["max_time"] = 10

    def base(self, path):
        return f"http://127.0.0.1:{LocalServer.port}{path}"

    def test_direct_download(self):
        got = bytearray()
        result = ng.fetch_url(self.base("/file"), self.cfg, sink=got.extend)
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["route"], "direct")
        self.assertEqual(bytes(got), Handler.body)
        self.assertEqual(result["bytes"], len(Handler.body))

    def test_redirect_hops_followed(self):
        got = bytearray()
        result = ng.fetch_url(self.base("/r1"), self.cfg, sink=got.extend)
        self.assertTrue(result["ok"], result)
        self.assertEqual(bytes(got), Handler.body)
        self.assertEqual(len(result["hops"]), 3)

    def test_content_length_precheck(self):
        result = ng.fetch_url(self.base("/big"), self.cfg, max_bytes=1000)
        self.assertFalse(result["ok"])
        self.assertEqual(result["error"], "too_large")
        # pre-check must not download the body at all
        self.assertEqual(result["bytes"], 0)

    def test_budget_denied_without_proxy(self):
        cfg = dict(self.cfg)
        cfg["route"] = {"proxy_hosts": ["*"], "direct_hosts": []}
        result = ng.fetch_url(self.base("/file"), cfg)
        # no proxy available in CI: direct is tried, and since the host is a
        # proxy candidate without a reachable proxy, the call still succeeds
        # directly (fail-open on "no proxy configured").
        self.assertTrue(result["ok"], result)


class TestProxyResolution(unittest.TestCase):
    def setUp(self):
        self._saved = os.environ.pop("NETGUARD_HTTP_PROXY", None)
        ng._scutil["at"] = 0.0

    def tearDown(self):
        os.environ.pop("NETGUARD_HTTP_PROXY", None)
        if self._saved is not None:
            os.environ["NETGUARD_HTTP_PROXY"] = self._saved

    def test_config_explicit_wins_over_env(self):
        cfg = {"proxy": {"url": "http://10.1.2.3:7890"}}
        os.environ["NETGUARD_HTTP_PROXY"] = "http://127.0.0.1:9999"
        self.assertEqual(ng.system_proxy(force=True, cfg=cfg), ("10.1.2.3", 7890))
        self.assertEqual(ng.proxy_source(cfg), "config")

    def test_config_accepts_host_port(self):
        cfg = {"proxy": {"url": "127.0.0.1:8888"}}
        self.assertEqual(ng.system_proxy(force=True, cfg=cfg), ("127.0.0.1", 8888))

    def test_env_used_without_config(self):
        os.environ["NETGUARD_HTTP_PROXY"] = "http://127.0.0.1:9999"
        self.assertEqual(ng.system_proxy(force=True), ("127.0.0.1", 9999))
        self.assertIn("env", ng.proxy_source())

    def test_parse_proxy_empty(self):
        self.assertIsNone(ng.parse_proxy(""))


if __name__ == "__main__":
    unittest.main()
