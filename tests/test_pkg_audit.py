#!/usr/bin/env python3
"""Offline tests: no network. Run: python3 tests/test_pkg_audit.py"""
import contextlib
import importlib.util
import io
import json
import sys
import tempfile
import threading
import time
import unittest
import zipfile
from pathlib import Path

spec = importlib.util.spec_from_file_location("pkg_audit", Path(__file__).resolve().parent.parent / "pkg_audit.py")
pa = importlib.util.module_from_spec(spec)
sys.modules["pkg_audit"] = pa
spec.loader.exec_module(pa)


class Paths(unittest.TestCase):
    def test_cargo_path(self):
        self.assertEqual(pa.cargo_path("a"), "1/a")
        self.assertEqual(pa.cargo_path("ab"), "2/ab")
        self.assertEqual(pa.cargo_path("abc"), "3/a/abc")
        self.assertEqual(pa.cargo_path("serde"), "se/rd/serde")

    def test_split(self):
        hub = "registry-1.docker.io"
        self.assertEqual(pa.split("alpine:3.20"), (hub, "library/alpine", "3.20"))
        self.assertEqual(pa.split("curlimages/curl:8"), (hub, "curlimages/curl", "8"))
        self.assertEqual(pa.split("docker.io/alpine:3.20"), (hub, "library/alpine", "3.20"))
        self.assertEqual(pa.split("mcr.microsoft.com/dotnet/aspnet:9.0"), ("mcr.microsoft.com", "dotnet/aspnet", "9.0"))
        self.assertEqual(pa.split("localhost:5000/app:v1"), ("localhost:5000", "app", "v1"))

    def test_registry_digest_falls_back_to_get_like_docker_pull(self):
        manifest = b'{"schemaVersion": 2}'

        class Answer:
            def __init__(self, headers):
                self.headers = headers

            def getheader(self, name, default=None):
                return self.headers.get(name, default)

        def registry(answers):
            asked = []

            class Fake(pa.Registry):
                def request(self, method, path, repo, hops=0):
                    asked.append(method)
                    status, headers = answers[method]
                    return status, Answer(headers), manifest if method == "GET" else b""
            return Fake("https://m.example"), asked

        both = {"Docker-Content-Digest": "sha256:" + "d" * 64}
        reg, asked = registry({"HEAD": (200, both)})
        self.assertEqual((reg.digest("library/alpine", "3.20"), asked), (both["Docker-Content-Digest"], ["HEAD"]))
        reg, asked = registry({"HEAD": (404, {}), "GET": (200, both)})
        self.assertEqual((reg.digest("library/alpine", "3.20"), asked), (both["Docker-Content-Digest"], ["HEAD", "GET"]))
        reg, asked = registry({"HEAD": (200, {}), "GET": (200, {})})  # no header at all: the manifest's own hash
        self.assertEqual(reg.digest("library/alpine", "3.20"), "sha256:" + pa.hashlib.sha256(manifest).hexdigest())
        reg, asked = registry({"HEAD": (404, {}), "GET": (404, {})})
        with self.assertRaisesRegex(RuntimeError, r"HTTP 404 \(HEAD and GET\)"):
            reg.digest("library/alpine", "3.20")
        reg, asked = registry({"HEAD": (405, {}), "GET": (401, {})})
        with self.assertRaisesRegex(RuntimeError, r"HTTP 401 \(HEAD 405\)"):
            reg.digest("library/alpine", "3.20")

    def test_parse_docker_mirrors(self):
        self.assertEqual(
            pa.parse_docker_mirrors([["a", "https://a"], ["b", "https://b", "mcr.microsoft.com"],
                                     ["c", "https://c", "192.0.2.1"], ["d", "https://d", "quay.io", "192.0.2.2"]]),
            [("a", "https://a", "registry-1.docker.io", None), ("b", "https://b", "mcr.microsoft.com", None),
             ("c", "https://c", "registry-1.docker.io", "192.0.2.1"), ("d", "https://d", "quay.io", "192.0.2.2")])

    def test_a_mirror_whose_registry_has_no_image_is_left_out_with_a_warning(self):
        mirrors = [("hub", "https://hub", "registry-1.docker.io", None), ("typo", "https://t", "mcr.microsoft.co", None)]
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            kept = pa.mirrors_with_images(mirrors, {"registry-1.docker.io": ["alpine:3.20"]})
        self.assertEqual(kept, mirrors[:1])
        self.assertIn("typo", err.getvalue())
        self.assertIn("mcr.microsoft.co", err.getvalue())


class Values(unittest.TestCase):
    def setUp(self):
        self.real_get = pa.get

    def tearDown(self):
        pa.get = self.real_get

    def test_npm_integrity(self):
        doc = {"versions": {"1.0.0": {"dist": {"integrity": "sha512-abc"}}}}
        pa.get = lambda url, accept="*/*": ("application/json", json.dumps(doc).encode())
        self.assertEqual(pa.fetch_value("npm", "https://m", "left-pad@1.0.0"), "sha512-abc")

    def test_pypi_html_and_json_agree(self):
        html = b'<a href="x/requests-2.0.0.tar.gz#sha256=aa">requests-2.0.0.tar.gz</a><a href="x/requests-2.1.0.tar.gz#sha256=bb">requests-2.1.0.tar.gz</a>'
        js = json.dumps({"files": [{"filename": "requests-2.0.0.tar.gz", "hashes": {"sha256": "aa"}},
                                     {"filename": "requests-2.1.0.tar.gz", "hashes": {"sha256": "bb"}}]}).encode()
        pa.get = lambda url, accept="*/*": ("text/html", html)
        from_html = pa.fetch_value("pypi", "https://m", "requests==2.0.0")
        pa.get = lambda url, accept="*/*": ("application/vnd.pypi.simple.v1+json", js)
        self.assertEqual(from_html, pa.fetch_value("pypi", "https://m", "requests==2.0.0"))
        self.assertEqual(from_html, "requests-2.0.0.tar.gz aa")

    def test_cargo_and_rubygems(self):
        pa.get = lambda url, accept="*/*": ("", b'{"vers":"1.0.0","cksum":"c1"}\n{"vers":"1.0.1","cksum":"c2"}\n')
        self.assertEqual(pa.fetch_value("cargo", "https://m", "serde@1.0.1"), "c2")
        pa.get = lambda url, accept="*/*": ("", b"---\n13.2.1 |checksum:" + b"a" * 64 + b",ruby:>= 2\n")
        self.assertEqual(pa.fetch_value("rubygems", "https://m", "rake@13.2.1"), "a" * 64)

    def test_maven_rejects_html(self):
        pa.get = lambda url, accept="*/*": ("text/html", b"<!doctype html><html>")
        with self.assertRaises(RuntimeError):
            pa.fetch_value("maven", "https://m", "junit:junit:4.13.2")
        pa.get = lambda url, accept="*/*": ("text/plain", b"8ac9e16d933b6fb43bc7f576336b8f4d7eb5ba12\n")
        self.assertEqual(pa.fetch_value("maven", "https://m", "junit:junit:4.13.2"), "8ac9e16d933b6fb43bc7f576336b8f4d7eb5ba12")

    def test_go_module_hash(self):
        def archive(files, level):
            buffer = io.BytesIO()
            with zipfile.ZipFile(buffer, "w", level) as zipped:
                for name, content in files:
                    zipped.writestr(name, content)
            return buffer.getvalue()
        files = [("example.com/m@v1.0.0/go.mod", "module example.com/m\n"), ("example.com/m@v1.0.0/a.go", "package m\n")]
        calls = []

        def fake_get(url, accept="*/*", limit=None):
            calls.append(url)
            return "application/zip", archive(files[::-1], zipfile.ZIP_DEFLATED)  # other order and packing, same files
        pa.get = fake_get
        self.assertEqual(pa.fetch_value("gomod", "https://m", "github.com/Foo/bar@v1.0.0-RC1"), pa.go_module_hash(archive(files, zipfile.ZIP_STORED)))
        self.assertEqual(calls, ["https://m/github.com/!foo/bar/@v/v1.0.0-!r!c1.zip"])
        self.assertEqual(pa.go_module_hash(archive(files, zipfile.ZIP_STORED)), "h1:SXy42eQ/QbleX7vtuAPFnaM3tNuQnfeo7rulG/p7iOw=")

    def test_get_does_not_read_past_a_limit(self):
        class Answer(io.BytesIO):
            headers = {"Content-Type": "application/zip"}

            def __enter__(self):
                return self

        class Opener:
            def open(self, req, timeout):
                return Answer(b"z" * 100)

        real, pa.urllib.request.build_opener = pa.urllib.request.build_opener, lambda *handlers: Opener()
        try:
            self.assertEqual(pa.get("https://m/a.zip", limit=100)[1], b"z" * 100)
            with self.assertRaises(RuntimeError):
                pa.get("https://m/a.zip", limit=99)
        finally:
            pa.urllib.request.build_opener = real

    def test_go_module_zip_over_the_limit_is_an_error(self):
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as zipped:  # small packed, large unpacked
            zipped.writestr("m@v1/a", b"\0" * 600)
            zipped.writestr("m@v1/b", b"\0" * 600)
        body = buffer.getvalue()
        self.assertLess(len(body), 1000)
        pa.go_module_hash(body, limit=1200)
        with self.assertRaises(RuntimeError):
            pa.go_module_hash(body, limit=1000)  # the two files together are over
        with self.assertRaises(RuntimeError):
            pa.go_module_hash(body, limit=500)  # the first file alone is over

    def test_npm_asks_like_the_npm_client(self):
        asked = []

        def fake_get(url, accept="*/*", limit=None):
            asked.append((url, accept))
            return "application/json", b'{"versions": {"22.7.5": {"dist": {"integrity": "sha512-x"}}}}'
        pa.get = fake_get
        self.assertEqual(pa.fetch_value("npm", "https://m", "@types/node@22.7.5"), "sha512-x")
        self.assertEqual(asked, [("https://m/@types%2Fnode",
                                  "application/vnd.npm.install-v1+json; q=1.0, application/json; q=0.8, */*")])

    def test_missing_version_is_an_error(self):
        pa.get = lambda url, accept="*/*": ("", b'{"vers":"1.0.0","cksum":"c1"}\n')
        with self.assertRaises(RuntimeError):
            pa.fetch_value("cargo", "https://m", "serde@9.9.9")


def run_group(kind, items, targets, workers=1, active=None, prior=None):
    """Drive package_group the way main() does."""
    active = {n for n, _ in targets} if active is None else active
    group, official, after = pa.package_group(kind, items, targets, active, prior)
    pa.run_jobs(official, workers)
    pa.run_jobs(after(), workers)
    return group


class Verdicts(unittest.TestCase):
    def setUp(self):
        self.real = pa.fetch_value
        pa.OFFICIAL["npm"] = "https://official"

    def tearDown(self):
        pa.fetch_value, pa.DEADLINE = self.real, None

    def test_package_verdicts(self):
        values = {"https://official": "good", "https://ok": "good", "https://bad": "evil"}

        failures = {"https://down": RuntimeError("HTTP 500"), "https://gone": RuntimeError("HTTP 404"),
                    "https://slow": RuntimeError("The read operation timed out")}

        def fake(kind, base, item):
            if base in failures:
                raise failures[base]
            return values[base]
        pa.fetch_value = fake
        g = run_group("npm", ["x@1.0.0"], [("ok", "https://ok"), ("bad", "https://bad"), ("down", "https://down"),
                                           ("gone", "https://gone"), ("slow", "https://slow")])
        got = {n: m["rows"]["x@1.0.0"]["verdict"] for n, m in g["mirrors"].items()}
        self.assertEqual(got, {"ok": "ok", "bad": "mismatch", "down": "error", "gone": "missing",
                               "slow": "unreachable"})

    def test_failure_verdicts(self):
        for detail, exc, want in [("HTTP 404 (HEAD and GET)", None, "missing"), ("HTTP 410", None, "missing"),
                                  ("HTTP 403", None, "error"), ("HTTP 500", None, "error"),
                                  ("answer longer than 10 bytes", None, "error"),
                                  ("boom", TimeoutError("boom"), "unreachable"),
                                  ("[Errno 61] Connection refused", None, "unreachable"),
                                  ("skipped: 3 requests in a row got no answer", None, "unreachable")]:
            self.assertEqual(pa.failure_verdict(detail, exc), want, detail)

    def test_a_mirror_that_never_answers_is_given_up_on(self):
        calls = []

        def fake(kind, base, item):
            if base == "https://official":
                return "good"
            calls.append(item)
            raise TimeoutError("no answer")
        pa.fetch_value = fake
        g = run_group("npm", [f"p{i}@1.0.0" for i in range(8)], [("dead", "https://dead")])
        self.assertEqual(len(calls), pa.GIVE_UP_AFTER)
        rows = g["mirrors"]["dead"]["rows"]
        self.assertEqual({r["verdict"] for r in rows.values()}, {"unreachable"})
        self.assertIn("skipped", rows["p7@1.0.0"]["detail"])

    def test_checks_never_made_leave_no_row_instead_of_an_error(self):
        pa.DEADLINE = time.monotonic() - 1  # budget already used up
        pa.fetch_value = lambda kind, base, item: "good"
        g = run_group("npm", ["a@1.0.0"], [("m", "https://m")])
        self.assertEqual(g["mirrors"]["m"]["rows"], {})  # not an error that would stand for an hour
        # ...so the mirror is unfinished and the next run checks it at once, whatever its turn
        prior = {"npm": {"mirrors": {"m": {"url": "https://m", "rows": g["mirrors"]["m"]["rows"]}}}}
        spec = [("npm", ["a@1.0.0"], [("m", "https://m")])]
        self.assertEqual(pa.pick_active(spec, prior, 12, 3), {("npm", "m")})
        # and the page calls it "in the queue", not "no answer"
        report = {"generated": "2026-01-01T00:00:00Z", "groups": [g]}
        self.assertIn("در صف بررسی", pa.page(report))


    def test_docker_mirrors_are_compared_with_their_own_registry(self):
        digests = {"https://registry-1.docker.io": "sha256:" + "a" * 64, "https://mcr.microsoft.com": "sha256:" + "b" * 64,
                   "https://hub.mirror": "sha256:" + "a" * 64, "https://mcr.mirror": "sha256:" + "c" * 64}

        class Fake:
            def __init__(self, base, ip=None):
                self.base = base

            def digest(self, repo, tag):
                return digests[self.base]

            def manifest_hashes_to(self, repo, digest):
                return self.base != "https://mcr.microsoft.com" or digest == digests[self.base]

        real, pa.Registry = pa.Registry, Fake
        try:
            refs = ["alpine:3.20", "mcr.microsoft.com/dotnet/aspnet:9.0"]
            mirrors = [("hub", "https://hub.mirror", "registry-1.docker.io", None),
                       ("mcr", "https://mcr.mirror", "mcr.microsoft.com", None)]
            group, official, after = pa.docker_group(refs, mirrors, {"hub", "mcr"})
            self.assertEqual([host for host, _ in official], ["mcr.microsoft.com", "registry-1.docker.io"])
            pa.run_jobs(official, 1)
            pa.run_jobs(after(), 1)
        finally:
            pa.Registry = real
        self.assertEqual(group["mirrors"]["hub"]["items"], ["alpine:3.20"])
        self.assertEqual(group["mirrors"]["mcr"]["items"], ["mcr.microsoft.com/dotnet/aspnet:9.0"])
        self.assertEqual({r: v["verdict"] for r, v in group["mirrors"]["hub"]["rows"].items()}, {"alpine:3.20": "ok"})
        self.assertEqual({r: v["verdict"] for r, v in group["mirrors"]["mcr"]["rows"].items()},
                         {"mcr.microsoft.com/dotnet/aspnet:9.0": "mismatch"})

    def test_each_official_registry_gets_its_own_group(self):
        class Same:
            def __init__(self, base, ip=None):
                pass

            def digest(self, repo, tag):
                return "sha256:" + "a" * 64

            def manifest_hashes_to(self, repo, digest):
                return True

        def leave(code):  # main() ends with os._exit, which would end the test run too
            raise SystemExit(code)

        real, pa.Registry = pa.Registry, Same
        real_exit, pa.os._exit = pa.os._exit, leave
        try:
            with tempfile.TemporaryDirectory() as d:
                d = Path(d)
                (d / "images.txt").write_text("alpine:3.20\nmcr.microsoft.com/dotnet/aspnet:9.0\nquay.io/a/b:1\n")
                (d / "mirrors.txt").write_text("hub https://hub.mirror\nmcr https://mcr.mirror mcr.microsoft.com\n")
                argv, sys.argv = sys.argv, ["pkg_audit.py", str(d / "images.txt"), str(d / "mirrors.txt"),
                                            "--json", str(d / "r.json"), "--html", str(d / "i.html")]
                try:
                    pa.main()
                except SystemExit as exc:
                    self.assertIn(exc.code, (0, None))
                finally:
                    sys.argv = argv
                report = json.loads((d / "r.json").read_text())
                page = (d / "i.html").read_text()
        finally:
            pa.Registry, pa.os._exit = real, real_exit
        groups = {g["id"]: g for g in report["groups"]}
        self.assertEqual(list(groups), ["docker", "docker-mcr-microsoft-com"])  # Docker Hub first; quay has no mirror
        self.assertEqual((groups["docker"]["title"], list(groups["docker"]["mirrors"]), groups["docker"]["items"]),
                         ("Docker Hub", ["hub"], ["alpine:3.20"]))
        self.assertEqual((groups["docker-mcr-microsoft-com"]["title"], list(groups["docker-mcr-microsoft-com"]["mirrors"])),
                         ("Microsoft (MCR)", ["mcr"]))
        self.assertIn('href="#docker-mcr-microsoft-com"', page)

    def test_an_official_registry_that_is_down_keeps_its_mirrors_last_result(self):
        class Down:
            def __init__(self, base, ip=None):
                pass

            def digest(self, repo, tag):
                raise RuntimeError("HTTP 503")

        old = {"url": "https://mcr.mirror", "ip": None, "checked_at": "2024-01-01T00:00:00Z",
               "rows": {"mcr.microsoft.com/x/y:1": {"verdict": "ok", "value": "sha256:1", "detail": ""}}}
        real, pa.Registry = pa.Registry, Down
        try:
            group, official, after = pa.docker_group(
                ["mcr.microsoft.com/x/y:1"], [("mcr", "https://mcr.mirror", "mcr.microsoft.com", None)],
                {"mcr"}, {"mirrors": {"mcr": old}})
            pa.run_jobs(official, 1)
            self.assertEqual(after(), [])
        finally:
            pa.Registry = real
        self.assertEqual(group["mirrors"]["mcr"]["rows"], old["rows"])
        self.assertEqual(group["mirrors"]["mcr"]["checked_at"], old["checked_at"])


class Turns(unittest.TestCase):
    def specs(self):
        return [("npm", ["a@1"], [("m%d" % i, f"https://h{i}.example") for i in range(6)])]

    def prior(self, specs):
        return {gid: {"mirrors": {n: {"url": u, "rows": {i: {"verdict": "ok"} for i in items}}
                                  for n, u in ms}} for gid, items, ms in specs}

    def test_each_host_is_checked_once_over_the_slots(self):
        specs, seen = self.specs(), []
        prior = self.prior(specs)
        for slot in range(3):
            seen += sorted(n for _, n in pa.pick_active(specs, prior, 3, slot))
        self.assertEqual(sorted(seen), ["m0", "m1", "m2", "m3", "m4", "m5"])  # all, none twice
        self.assertEqual(len(pa.pick_active(specs, prior, 3, 0)), 2)          # a third per run

    def test_everything_runs_when_there_is_one_slot_or_no_state(self):
        specs = self.specs()
        self.assertEqual(len(pa.pick_active(specs, self.prior(specs), 1, 0)), 6)
        self.assertEqual(len(pa.pick_active(specs, {}, 12, 5)), 6)  # no state: all, whatever the turn

    def test_a_mirror_with_a_new_item_or_url_is_checked_at_once(self):
        specs = self.specs()
        prior = self.prior(specs)
        specs[0] = ("npm", ["a@1", "b@1"], specs[0][2])  # an item the state has no row for
        self.assertEqual(len(pa.pick_active(specs, prior, 12, 11)), 6)

    def test_mirrors_not_checked_now_keep_their_last_result_and_time(self):
        pa.OFFICIAL["npm"] = "https://official"
        real = pa.fetch_value
        pa.fetch_value = lambda kind, base, item: "good"
        try:
            old = {"mirrors": {"idle": {"url": "https://idle", "ip": None, "checked_at": "2026-01-01T10:00:00Z",
                                       "rows": {"x@1": {"verdict": "mismatch", "value": "evil", "detail": "kept"}}}}}
            g = run_group("npm", ["x@1"], [("idle", "https://idle"), ("now", "https://now")], active={"now"}, prior=old)
        finally:
            pa.fetch_value = real
        self.assertEqual(g["mirrors"]["idle"]["rows"]["x@1"]["detail"], "kept")
        self.assertEqual(g["mirrors"]["idle"]["checked_at"], "2026-01-01T10:00:00Z")
        self.assertEqual(g["mirrors"]["now"]["rows"]["x@1"]["verdict"], "ok")
        self.assertNotEqual(g["mirrors"]["now"]["checked_at"], "2026-01-01T10:00:00Z")

    def test_no_official_request_when_no_mirror_of_a_group_is_due(self):
        group, official, after = pa.package_group("npm", ["a@1"], [("m", "https://m")], set(), None)
        self.assertEqual(official, [])
        self.assertEqual(after(), [])


class Pool(unittest.TestCase):
    def test_one_request_at_a_time_per_host_but_hosts_overlap(self):
        lock, state = threading.Lock(), {"now": {}, "max_same": 0, "max_all": 0}

        def job(host):
            def run():
                with lock:
                    state["now"][host] = state["now"].get(host, 0) + 1
                    state["max_same"] = max(state["max_same"], state["now"][host])
                    state["max_all"] = max(state["max_all"], sum(state["now"].values()))
                time.sleep(0.05)
                with lock:
                    state["now"][host] -= 1
            return run
        jobs = [("a", job("a")) for _ in range(4)] + [("b", job("b")) for _ in range(4)]
        pa.run_jobs(jobs, 4)
        self.assertEqual(state["max_same"], 1)   # never two requests at once to one host
        self.assertEqual(state["max_all"], 2)    # but the two hosts did run together

    def test_workers_bound_the_overlap(self):
        lock, state = threading.Lock(), {"now": 0, "max": 0}

        def run():
            with lock:
                state["now"] += 1
                state["max"] = max(state["max"], state["now"])
            time.sleep(0.05)
            with lock:
                state["now"] -= 1
        pa.run_jobs([(f"h{i}", run) for i in range(8)], 3)
        self.assertEqual(state["max"], 3)

    def test_a_stuck_job_is_abandoned_without_waiting_for_the_whole_budget(self):
        real = pa.STUCK_AFTER
        pa.STUCK_AFTER = 0.3
        pa.DEADLINE = time.monotonic() + 600  # a long budget must not keep the run waiting
        try:
            started = time.monotonic()
            pa.run_jobs([("slow", lambda: time.sleep(30)), ("fast", lambda: None)], 2)
            self.assertLess(time.monotonic() - started, 5)
        finally:
            pa.DEADLINE, pa.STUCK_AFTER = None, real

    def test_settle_drops_rows_cut_off_mid_request(self):
        report = {"groups": [{"id": "g", "items": ["x", "y"], "mirrors": {"m": {"rows": {
            "x": {"verdict": "error", "value": None, "detail": ""},                  # cut off
            "y": {"verdict": "error", "value": None, "detail": "HTTP 404"}}}}}]}      # a real answer
        pa.settle(report, {("g", "m")})
        self.assertEqual(list(report["groups"][0]["mirrors"]["m"]["rows"]), ["y"])

    def test_old_state_with_unchecked_rows_is_healed_on_load(self):
        with tempfile.TemporaryDirectory() as d:
            f = Path(d) / "report.json"
            f.write_text(json.dumps({"groups": [{"id": "npm", "mirrors": {"m": {"url": "https://m", "rows": {
                "a": {"verdict": "error", "value": None, "detail": "skipped: the run's time budget (--max-seconds) was used up"},
                "b": {"verdict": "error", "value": None, "detail": "no answer before the run's time budget ran out"},
                "c": {"verdict": "error", "value": None, "detail": "skipped: 3 requests in a row got no answer"},
                "d": {"verdict": "ok", "value": "v", "detail": ""},
                "e": {"verdict": "error", "value": None, "detail": "HTTP 404"}}}}}]}))
            rows = pa.load_state(f)["npm"]["mirrors"]["m"]["rows"]
        self.assertEqual(sorted(rows), ["c", "d", "e"])  # only the never-made checks are dropped
        self.assertEqual((rows["c"]["verdict"], rows["e"]["verdict"]), ("unreachable", "missing"))


class PageState(unittest.TestCase):
    def test_page_shows_last_check_time_and_tolerates_missing_rows(self):
        group = {"id": "npm", "title": "npm", "note": "n", "items": ["x@1", "y@1"], "mirrors": {
            "m": {"url": "https://m.example", "ip": None, "checked_at": "2026-01-01T10:00:00Z",
                  "rows": {"x@1": {"verdict": "ok", "value": "v", "detail": ""}}}}}  # y@1 never checked
        out = pa.page({"generated": "2026-01-01T10:05:00Z", "groups": [group]})
        self.assertIn("آخرین بررسی", out)
        self.assertIn("قدیمی", out)  # 2026-01-01 is long ago


class Page(unittest.TestCase):
    def test_page_renders_and_escapes(self):
        pa.BRAND.update(ours="m", ours_label="<b>us</b>", title="T", name="N", tagline="t", footer_html="<i>f</i>")
        group = {"id": "npm", "title": "npm", "note": "n", "items": ["x@1"], "mirrors": {
            "m": {"url": "https://m.example", "ip": None,
                  "rows": {"x@1": {"verdict": "mismatch", "value": "<script>", "detail": ""}}}}}
        out = pa.page({"generated": "2026-01-01T00:00:00Z", "groups": [group]})
        self.assertEqual(out.count("<script>"), 2)  # only the page's own search and tooltip scripts; the value is escaped
        self.assertIn("&lt;script&gt;", out)
        self.assertIn("&lt;b&gt;us&lt;/b&gt;", out)
        self.assertIn("ناهمخوان", out)
        # the headline names the mirror, the ecosystem and the item
        head = out[out.index('class="verdict'):out.index('class="nums"')]
        self.assertIn("m.example", head)
        self.assertIn('href="#npm"', head)
        self.assertIn("x@1", head)
        self.assertIn("&lt;b&gt;us&lt;/b&gt;", head)  # marked as ours
        self.assertNotIn("og:image", out)  # no site_url, no preview tags
        pa.BRAND["site_url"] = "https://audit.example.com/"
        out = pa.page({"generated": "2026-01-01T00:00:00Z", "groups": [group]})
        self.assertIn('property="og:image" content="https://audit.example.com/og.jpg"', out)
        self.assertIn('name="twitter:card" content="summary_large_image"', out)
        pa.BRAND["site_url"] = ""
        self.assertNotIn('class="src"', out)
        pa.BRAND["source_url"] = "https://github.com/example/pkg-audit"
        out = pa.page({"generated": "2026-01-01T00:00:00Z", "groups": [group]})
        self.assertIn('class="src" href="https://github.com/example/pkg-audit"', out)
        self.assertGreaterEqual(out.count("github.com/example/pkg-audit"), 3)
        pa.BRAND["source_url"] = ""


if __name__ == "__main__":
    unittest.main()
