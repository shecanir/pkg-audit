#!/usr/bin/env python3
"""Offline tests for serve.py and the queue helpers. Run: python3 tests/test_serve.py"""
import json
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from http.server import ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import pkg_audit as pa  # noqa: E402
import serve  # noqa: E402

NOW = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)


def iso(minutes_ago):
    return (NOW - timedelta(minutes=minutes_ago)).strftime("%Y-%m-%dT%H:%M:%SZ")


def report(checked_at):
    return {"groups": [{"id": "npm", "mirrors": {"m.example": {"checked_at": checked_at}}}]}


class TestSchedule(unittest.TestCase):
    def test_next_boundary(self):
        self.assertEqual(serve.seconds_to_next(5, 600.0), 301)      # exactly on a boundary: wait a full step
        self.assertEqual(serve.seconds_to_next(5, 601.0), 300)
        self.assertEqual(serve.seconds_to_next(5, 899.5), 1.5 + 0)  # 0.5 s before the boundary plus 1 s

    def test_failing_run_does_not_stop_the_loop(self):
        calls = []
        orig_run, orig_sleep = serve.subprocess.run, serve.time.sleep

        def fake_run(cmd, **kw):
            calls.append(cmd)
            if len(calls) == 1:
                raise OSError("boom")
            if len(calls) == 3:
                raise KeyboardInterrupt
            return type("R", (), {"returncode": 0})()
        serve.subprocess.run, serve.time.sleep = fake_run, lambda s: None
        try:
            with self.assertRaises(KeyboardInterrupt):
                serve.run_forever(5, ["x"], 10)
        finally:
            serve.subprocess.run, serve.time.sleep = orig_run, orig_sleep
        self.assertEqual(len(calls), 3)


class Decide(unittest.TestCase):
    def test_unknown_group_or_mirror_is_refused(self):
        self.assertEqual(serve.decide(report(iso(99)), {}, "npm", "other", NOW, 30)[0], 404)
        self.assertEqual(serve.decide(report(iso(99)), {}, "pypi", "m.example", NOW, 30)[0], 404)

    def test_recently_checked_mirror_waits_out_the_cooldown(self):
        status, body = serve.decide(report(iso(10)), {}, "npm", "m.example", NOW, 30)
        self.assertEqual((status, body["status"]), (429, "cooldown"))
        self.assertAlmostEqual(body["retry_after"], 20 * 60, delta=2)

    def test_old_enough_mirror_is_queued(self):
        status, body = serve.decide(report(iso(31)), {}, "npm", "m.example", NOW, 30)
        self.assertEqual((status, body.get("add")), (202, True))

    def test_never_checked_mirror_can_be_queued(self):
        self.assertEqual(serve.decide(report(None), {}, "npm", "m.example", NOW, 30)[0], 202)

    def test_already_queued_is_not_added_again(self):
        status, body = serve.decide(report(iso(99)), {"npm/m.example": "x"}, "npm", "m.example", NOW, 30)
        self.assertEqual((status, body), (202, {"status": "queued"}))


class Limit(unittest.TestCase):
    def test_per_client_rate_limit(self):
        lim = serve.Limiter(3)
        self.assertEqual([lim.allow("a", now=t) for t in (0, 1, 2, 3)], [True, True, True, False])
        self.assertTrue(lim.allow("b", now=3))     # another client is unaffected
        self.assertTrue(lim.allow("a", now=61))    # the window moves on


class Queue(unittest.TestCase):
    def test_add_remove_and_unreadable_file(self):
        with tempfile.TemporaryDirectory() as d:
            q = Path(d) / "queue.json"
            self.assertEqual(pa.queue_read(q), {})
            pa.queue_add(q, "npm/a")
            pa.queue_add(q, "npm/a")  # twice: still one entry, first time kept
            pa.queue_add(q, "pypi/b")
            self.assertEqual(sorted(pa.queue_read(q)), ["npm/a", "pypi/b"])
            pa.queue_remove(q, ["npm/a", "never-there"])
            self.assertEqual(sorted(pa.queue_read(q)), ["pypi/b"])
            q.write_text("not json")
            self.assertEqual(pa.queue_read(q), {})


class Page(unittest.TestCase):
    def group(self, queued=False, checked="2026-01-01T10:00:00Z"):
        return {"id": "npm", "title": "npm", "note": "n", "items": ["x@1"], "mirrors": {
            "m.example": {"url": "https://m.example", "ip": None, "checked_at": checked, "queued": queued,
                          "rows": {"x@1": {"verdict": "ok", "value": "v", "detail": ""}}}}}

    def test_best_score_first_then_by_name(self):
        g = self.group()
        row = lambda v: {"verdict": v, "value": "v", "detail": ""}
        g["items"] = ["x@1", "y@1"]
        for host, verdicts in [("c.example", ["ok", "ok"]), ("a.example", ["ok", "error"]),
                               ("b.example", ["ok", "ok"]), ("d.example", ["mismatch", "ok"])]:
            g["mirrors"][host] = {"url": "https://" + host, "ip": None, "checked_at": None, "queued": False,
                                  "rows": dict(zip(g["items"], map(row, verdicts)))}
        del g["mirrors"]["m.example"]
        out = pa.render_group(g, str)
        hosts = [h for h in ("a.example", "b.example", "c.example", "d.example")]
        self.assertEqual(sorted(hosts, key=out.index), ["b.example", "c.example", "a.example", "d.example"])
        pa.BRAND["ours"] = "d.example"
        try:
            out = pa.render_group(g, str)
        finally:
            pa.BRAND["ours"] = ""
        # our own mirror gets no place of its own: it is sorted by its score like the others
        self.assertEqual(sorted(hosts, key=out.index), ["b.example", "c.example", "a.example", "d.example"])

    def test_equal_scores_go_to_the_stronger_provider(self):
        g = self.group()
        row = {"verdict": "ok", "value": "v", "detail": ""}
        g["items"] = ["x@1"]
        g["mirrors"] = {h: {"url": "https://" + h, "ip": None, "checked_at": None, "queued": False, "rows": {"x@1": row}}
                        for h in ("a.small.example", "b.big.example")}
        out = pa.render_group(g, str, pscore={"small.example": 1.0, "big.example": 5.0})
        self.assertLess(out.index("b.big.example"), out.index("a.small.example"))  # not by name
        self.assertIn('data-p="5.000"', out)

    def test_404_is_shown_apart_from_no_answer(self):
        g = self.group()
        g["items"] = ["x@1", "y@1"]
        g["mirrors"]["m.example"]["rows"] = {"x@1": {"verdict": "missing", "value": None, "detail": "HTTP 404"},
                                             "y@1": {"verdict": "unreachable", "value": None, "detail": "timed out"}}
        out = pa.page({"generated": "2026-01-01T10:05:00Z", "groups": [g]})
        self.assertIn("پیدا نشد (۴۰۴)", out)
        self.assertIn("در دسترس نیست", out)
        self.assertNotIn("بدون پاسخ", out)

    def test_ecosystems_with_most_mirrors_first(self):
        one, two = self.group(), self.group()
        one["id"], one["title"] = "pypi", "PyPI"
        two["mirrors"]["n.example"] = dict(two["mirrors"]["m.example"], url="https://n.example")
        out = pa.page({"generated": "2026-01-01T10:05:00Z", "groups": [one, two]})
        self.assertLess(out.index('id="npm"'), out.index('id="pypi"'))
        self.assertLess(out.index('href="#npm"'), out.index('href="#pypi"'))

    def test_button_only_when_rechecks_are_enabled(self):
        r = {"generated": "2026-01-01T10:05:00Z", "groups": [self.group()]}
        pa.BRAND["recheck_minutes"] = 0
        self.assertNotIn('class="re"', pa.page(r))
        pa.BRAND["recheck_minutes"] = 30
        try:
            out = pa.page(r)
        finally:
            pa.BRAND["recheck_minutes"] = 0
        self.assertIn('class="re" data-g="npm" data-m="m.example"', out)
        self.assertIn("/api/recheck", out)
        self.assertIn("var CD=30*60000", out)

    def test_queued_and_never_checked_say_in_the_queue(self):
        pa.BRAND["recheck_minutes"] = 30
        try:
            queued = pa.page({"generated": "2026-01-01T10:05:00Z", "groups": [self.group(queued=True)]})
            never = pa.page({"generated": "2026-01-01T10:05:00Z", "groups": [self.group(checked=None)]})
        finally:
            pa.BRAND["recheck_minutes"] = 0
        self.assertIn("data-queued=1", queued)
        self.assertIn("در صف بررسی", queued)
        self.assertIn("در صف بررسی", never)
        self.assertNotIn("هنوز بررسی نشده", never)

    def test_asked_pairs_ignores_mirrors_not_in_the_lists(self):
        specs = [("npm", ["x@1"], [("m.example", "https://m.example")])]
        self.assertEqual(pa.asked_pairs({"npm/m.example": "t", "npm/gone": "t", "junk": "t"}, specs),
                         {("npm", "m.example")})


class Server(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.site = Path(self.tmp.name) / "site"
        self.site.mkdir()
        (self.site / "index.html").write_text("<h1>hi</h1>")
        (self.site / "report.json").write_text(json.dumps(report(iso(99))))
        (Path(self.tmp.name) / "secret.txt").write_text("secret")
        self.queue = Path(self.tmp.name) / "queue.json"
        handler = serve.make_handler(self.site, self.queue, 30, serve.Limiter(100))
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        self.base = f"http://127.0.0.1:{self.httpd.server_address[1]}"

    def tearDown(self):
        self.httpd.shutdown()
        self.tmp.cleanup()

    def call(self, path, data=None, raw=None):
        body = raw if raw is not None else (json.dumps(data).encode() if data is not None else None)
        req = urllib.request.Request(self.base + path, data=body, method="POST" if body is not None else "GET",
                                     headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=5) as r:
                return r.status, r.read(), dict(r.headers)
        except urllib.error.HTTPError as e:
            with e:
                return e.code, e.read(), dict(e.headers)

    def test_static_files_and_headers(self):
        status, body, headers = self.call("/")
        self.assertEqual((status, body), (200, b"<h1>hi</h1>"))
        self.assertIn("max-age", headers["Cache-Control"])
        self.assertEqual(self.call("/../secret.txt")[0], 404)
        self.assertEqual(self.call("/%2e%2e/secret.txt")[0], 404)

    def test_recheck_queues_once_then_cooldown_follows_the_check(self):
        status, body, headers = self.call("/api/recheck", {"group": "npm", "mirror": "m.example"})
        self.assertEqual((status, json.loads(body)), (202, {"status": "queued"}))
        self.assertEqual(headers["Cache-Control"], "no-store")
        self.assertEqual(list(pa.queue_read(self.queue)), ["npm/m.example"])
        self.call("/api/recheck", {"group": "npm", "mirror": "m.example"})   # again: no second entry
        self.assertEqual(len(pa.queue_read(self.queue)), 1)
        # the job ran: entry removed and the mirror was just checked
        pa.queue_remove(self.queue, ["npm/m.example"])
        (self.site / "report.json").write_text(json.dumps(report(datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))))
        status, body, _ = self.call("/api/recheck", {"group": "npm", "mirror": "m.example"})
        self.assertEqual((status, json.loads(body)["status"]), (429, "cooldown"))
        self.assertEqual(pa.queue_read(self.queue), {})

    def test_bad_requests(self):
        self.assertEqual(self.call("/api/recheck", raw=b"not json")[0], 400)
        self.assertEqual(self.call("/api/recheck", {"group": "npm"})[0], 400)
        self.assertEqual(self.call("/api/recheck", raw=b"x" * 5000)[0], 400)
        self.assertEqual(self.call("/api/recheck", {"group": "npm", "mirror": "evil.example"})[0], 404)
        self.assertEqual(self.call("/api/other", {"a": 1})[0], 404)
        self.assertEqual(self.call("/api/recheck")[0], 404)  # GET is not the API
        self.assertEqual(pa.queue_read(self.queue), {})

    def test_data_files_are_open_to_other_programs(self):
        (self.site / "summary.json").write_text('{"schema": "pkg-audit/summary@1"}')
        status, _, headers = self.call("/summary.json")
        headers = {k.lower(): v for k, v in headers.items()}
        self.assertEqual((status, headers.get("access-control-allow-origin")), (200, "*"))
        self.assertEqual(headers["content-type"], "application/json; charset=utf-8")
        self.assertNotIn("Access-Control-Allow-Origin", self.call("/")[2])


class ForwardedFor(unittest.TestCase):
    def test_only_entries_of_trusted_proxies_count(self):
        self.assertEqual(serve.client_of("forged, 203.0.113.9", "10.0.0.2", 1), "203.0.113.9")
        self.assertEqual(serve.client_of("forged, 203.0.113.9, 198.51.100.1", "10.0.0.2", 2), "203.0.113.9")
        self.assertEqual(serve.client_of("forged", "10.0.0.2", 0), "10.0.0.2")
        self.assertEqual(serve.client_of(None, "10.0.0.2", 1), "10.0.0.2")
        self.assertEqual(serve.client_of("203.0.113.9", "10.0.0.2", 2), "203.0.113.9")


if __name__ == "__main__":
    unittest.main()
