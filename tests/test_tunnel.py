#!/usr/bin/env python3
"""Offline tests for the SOCKS5 tunnel and the `via=tunnel` marker. Run: python3 tests/test_tunnel.py"""
import io
import os
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import pkg_audit as pa  # noqa: E402
import socks_fake  # noqa: E402


class Hello(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Length", "5")
        self.end_headers()
        self.wfile.write(b"hello")

    def log_message(self, *a):
        pass


class Tunnel(unittest.TestCase):
    def setUp(self):
        self.old_env, self.old_set = os.environ.get("AUDIT_SOCKS"), set(pa.VIA_TUNNEL)
        pa.VIA_TUNNEL.clear()
        self.web = HTTPServer(("127.0.0.1", 0), Hello)
        threading.Thread(target=self.web.serve_forever, daemon=True).start()
        self.seen = []
        self.port, self.close = socks_fake.serve(self.seen, {"mirror.test": ("127.0.0.1", self.web.server_port)})

    def tearDown(self):
        self.close()
        self.web.shutdown()
        pa.VIA_TUNNEL.clear()
        pa.VIA_TUNNEL.update(self.old_set)
        if self.old_env is None:
            os.environ.pop("AUDIT_SOCKS", None)
        else:
            os.environ["AUDIT_SOCKS"] = self.old_env

    def test_every_mirror_uses_the_tunnel_unless_marked_direct(self):
        with tempfile.TemporaryDirectory() as d:
            f = Path(d) / "m.txt"
            f.write_text("a https://one.example/x/ via=tunnel\nb https://two.example\nc https://3.example 1.2.3.4 # c\n"
                         "d https://four.example via=direct\ne https://five.example mcr.microsoft.com via=direct 1.2.3.5\n")
            rows = pa.read_list(f)
        self.assertEqual(rows, [["a", "https://one.example/x/"], ["b", "https://two.example"], ["c", "https://3.example", "1.2.3.4"],
                                ["d", "https://four.example"], ["e", "https://five.example", "mcr.microsoft.com", "1.2.3.5"]])
        self.assertEqual(pa.VIA_TUNNEL, {"https://one.example/x", "https://two.example", "https://3.example"})

    def test_an_official_source_never_uses_the_tunnel(self):
        os.environ["AUDIT_SOCKS"] = f"127.0.0.1:{self.port}"
        pa.VIA_TUNNEL.update({"https://registry.npmjs.org", "https://mirror.example"})
        self.assertFalse(pa.via_tunnel("https://registry.npmjs.org/lodash"))
        self.assertTrue(pa.via_tunnel("https://mirror.example/lodash"))

    def test_only_marked_mirrors_use_the_tunnel(self):
        os.environ["AUDIT_SOCKS"] = f"127.0.0.1:{self.port}"
        pa.VIA_TUNNEL.add("https://one.example/x")
        self.assertTrue(pa.via_tunnel("https://one.example/x/pkg"))
        self.assertFalse(pa.via_tunnel("https://two.example/x/pkg"))
        self.assertFalse(pa.via_tunnel("https://one.example/y"))

    def test_without_a_tunnel_nothing_is_marked(self):
        os.environ.pop("AUDIT_SOCKS", None)
        pa.VIA_TUNNEL.add("https://one.example")
        self.assertFalse(pa.via_tunnel("https://one.example/a"))
        os.environ["AUDIT_SOCKS"] = "nonsense"
        self.assertFalse(pa.via_tunnel("https://one.example/a"))

    def test_a_tunnelled_registry_asks_for_its_token_through_the_tunnel(self):
        os.environ["AUDIT_SOCKS"] = f"127.0.0.1:{self.port}"
        pa.VIA_TUNNEL.add("https://hub.mirror.test")
        opened = []

        class Answer(io.BytesIO):
            def __enter__(self):
                return self

        class Opener:
            def __init__(self, handlers):
                self.handlers = handlers

            def open(self, url, timeout):
                opened.append((self.handlers, url))
                return Answer(b'{"token": "t"}')

        challenge = 'Bearer realm="https://hub.mirror.test/token",service="registry"'
        real, pa.urllib.request.build_opener = pa.urllib.request.build_opener, lambda *handlers: Opener(handlers)
        try:
            self.assertEqual(pa.Registry("https://hub.mirror.test").token(challenge, "library/alpine"), "t")
            self.assertEqual(pa.Registry("https://other.mirror.test").token(challenge, "library/alpine"), "t")
        finally:
            pa.urllib.request.build_opener = real
        self.assertEqual([handlers for handlers, _ in opened], [(pa.TunnelHandler,), ()])
        self.assertIn("scope=repository%3Alibrary%2Falpine%3Apull", opened[0][1])

    def test_connect_by_name_through_the_proxy(self):
        sock = pa.socks_connect(("127.0.0.1", self.port), "mirror.test", 80, 5)
        sock.sendall(b"GET / HTTP/1.0\r\n\r\n")
        data = b""
        while chunk := sock.recv(4096):
            data += chunk
        sock.close()
        self.assertTrue(data.startswith(b"HTTP/1.0 200"))
        self.assertTrue(data.endswith(b"hello"))
        self.assertEqual(self.seen, [("mirror.test", 80)])  # the proxy got the name, not an address

    def test_refused_by_the_far_end(self):
        with self.assertRaises(RuntimeError) as ctx:
            pa.socks_connect(("127.0.0.1", self.port), "127.0.0.1", 1, 5)  # nothing listens on port 1
        self.assertIn("could not reach", str(ctx.exception))

    def test_tunnel_down_is_an_error_not_a_hang(self):
        with self.assertRaises(OSError):
            pa.socks_connect(("127.0.0.1", 1), "mirror.test", 443, 2)


if __name__ == "__main__":
    unittest.main()
