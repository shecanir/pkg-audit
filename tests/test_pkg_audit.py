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
        self.assertNotIn("<!--head-->", out)
        pa.BRAND["head_html"] = "<!--head-->"
        out = pa.page({"generated": "2026-01-01T00:00:00Z", "groups": [group]})
        self.assertIn("<style>", out[:out.index("<!--head-->")])
        self.assertLess(out.index("<!--head-->"), out.index("</head>"))
        pa.BRAND["head_html"] = ""
        self.assertNotIn('class="src"', out)
        pa.BRAND["source_url"] = "https://github.com/example/pkg-audit"
        out = pa.page({"generated": "2026-01-01T00:00:00Z", "groups": [group]})
        self.assertIn('class="src" href="https://github.com/example/pkg-audit"', out)
        self.assertGreaterEqual(out.count("github.com/example/pkg-audit"), 3)
        pa.BRAND["source_url"] = ""


class History(unittest.TestCase):
    def report(self, at, rows, url="https://m.example"):
        return {"generated": at, "groups": [{"id": "npm", "mirrors": {"m": {"url": url, "rows": {
            i: {"verdict": v, "value": "h" if v != "missing" else None, "detail": ""} for i, v in rows.items()}}}}]}

    def test_counts_days_and_changes(self):
        h = pa.add_history({}, self.report("2026-11-03T10:00:00Z", {"a@1": "ok", "b@1": "mismatch", "c@1": "pending"}),
                           {("npm", "m")})
        self.assertEqual(h["days"], {"2026-11-03": {"npm/m": {"ok": 1, "mismatch": 1}}})
        self.assertEqual([(e["item"], e["from"], e["to"]) for e in h["events"]], [("b@1", None, "mismatch")])
        # 21:00 UTC is already the next day in Tehran
        h = pa.add_history(h, self.report("2026-11-03T21:00:00Z", {"a@1": "missing", "b@1": "mismatch"}), {("npm", "m")})
        self.assertEqual(h["days"]["2026-11-04"], {"npm/m": {"missing": 1, "mismatch": 1}})
        self.assertEqual([(e["item"], e["from"], e["to"]) for e in h["events"]][1:], [("a@1", "ok", "missing")])
        self.assertEqual(h["mirrors"], {"npm/m": "https://m.example"})

    def test_results_kept_from_an_earlier_run_are_not_counted(self):
        h = pa.add_history({}, self.report("2026-11-03T10:00:00Z", {"a@1": "ok"}), set())
        self.assertEqual(h["days"], {"2026-11-03": {}})
        self.assertEqual(h["events"], [])

    def test_old_days_and_changes_go_but_mismatches_stay(self):
        h = pa.add_history({}, self.report("2026-01-01T10:00:00Z", {"a@1": "ok", "b@1": "mismatch"}), {("npm", "m")})
        h = pa.add_history(h, self.report("2026-01-02T10:00:00Z", {"a@1": "missing", "b@1": "ok"}), {("npm", "m")})
        h = pa.add_history(h, self.report("2026-06-01T10:00:00Z", {"a@1": "ok", "b@1": "ok"}), {("npm", "m")})
        self.assertEqual(sorted(h["days"]), ["2026-06-01"])
        self.assertEqual([(e["item"], e["from"], e["to"]) for e in h["events"]],
                         [("b@1", None, "mismatch"), ("b@1", "mismatch", "ok"), ("a@1", "missing", "ok")])

    def test_the_page_shows_the_history_after_two_weeks(self):
        h, active = {}, {("npm", "m")}
        for day in range(1, 15):
            rows = {"a@1": "mismatch" if day == 3 else "ok", "b@1": "unreachable"}
            h = pa.add_history(h, self.report(f"2026-11-{day:02}T08:00:00Z", rows), active)
            report = self.report(f"2026-11-{day:02}T08:00:00Z", rows)
            report["groups"][0].update(title="npm", note="n", items=["a@1", "b@1"])
            out = pa.page(report, h)
            self.assertEqual('class="trend"' in out, day == 14)
        self.assertIn("۱۴ روز: ۹۳٪", out)  # 13 of 14 answers ok; no answer is not counted
        self.assertIn("سابقه‌ی ناهمخوانی‌ها", out)
        self.assertIn("رفع شد ۱۴۰۵/۰۸/۱۳", out)  # 2026-11-04, in the Persian calendar

    def test_providers_group_hosts_by_domain(self):
        self.assertEqual(pa.provider("mirror.arvancloud.ir"), "arvancloud.ir")
        self.assertEqual(pa.provider("mirror.ut.ac.ir"), "ut.ac.ir")
        self.assertEqual(pa.provider("10.0.0.1"), "10.0.0.1")
        report = self.report("2026-11-03T08:00:00Z", {"a@1": "ok", "b@1": "unreachable"}, url="https://npm.m.example")
        report["groups"][0].update(title="npm", note="n", items=["a@1", "b@1"])
        out = pa.page(report)
        self.assertIn('data-q="m.example"', out)
        self.assertIn("۵۰٪ سالم", out)
        self.assertIn('<b>۰</b>', out)  # 1 ok of 2 is not a healthy repository

    def test_more_healthy_repositories_rank_higher(self):
        def provider(name, repos, items=6, ok=6):
            return {f"{name}{i}": {"url": f"https://r{i}.{name}.example", "rows": {
                f"x{j}@1": {"verdict": "ok" if j < ok else "unreachable", "value": "h", "detail": ""} for j in range(items)}}
                for i in range(repos)}
        mirrors = {**provider("nine", 9, 4), **provider("six", 6, 7, 7), **provider("one", 1, 12, 11),
                   **provider("silent", 5, 12, 1)}
        g = {"id": "npm", "title": "npm", "note": "n", "items": [f"x{j}@1" for j in range(12)], "mirrors": mirrors}
        for m in mirrors.values():
            m["items"] = list(m["rows"])
        out = pa.providers([g], None, [], lambda n: str(n).translate(pa.FA_DIGITS))
        order = sorted(["nine", "six", "one", "silent"], key=lambda p: out.index(f'data-q="{p}.example"'))
        # 9 healthy repositories over 6; one at 11 of 12 (healthy, >= 90%) over 5 mostly silent ones (none healthy)
        self.assertEqual(order, ["nine", "six", "one", "silent"])

    def test_providers_rank_by_score(self):
        def mirror(url, verdicts):
            return {"url": url, "rows": {i: {"verdict": v, "value": "h", "detail": ""} for i, v in zip(["a@1", "b@1"], verdicts)}}
        g = {"id": "npm", "title": "npm", "note": "n", "items": ["a@1", "b@1"], "mirrors": {
            "small": mirror("https://npm.small.example", ["ok", "ok"]),
            "big1": mirror("https://npm.big.example", ["ok", "missing"]),
            "big2": mirror("https://npm2.big.example", ["ok", "ok"]),
            "bad1": mirror("https://npm.bad.example", ["ok", "mismatch"]),
            "bad2": mirror("https://npm2.bad.example", ["ok", "ok"])}}
        out = pa.providers([g], None, [], lambda n: str(n).translate(pa.FA_DIGITS))
        # one healthy repository each; ties go to fewer mismatches, then the higher share ok
        order = sorted(["small", "big", "bad"], key=lambda p: out.index(f'data-q="{p}.example"'))
        self.assertEqual(order, ["small", "big", "bad"])
        self.assertIn('data-score="1.000" data-pct="0.7500" data-repos="2"', out)
        self.assertIn("امتیاز چطور حساب می‌شود؟", out)
        self.assertIn('data-vsort="score" aria-pressed="true"', out)
        self.assertNotIn('class="verdict', out)  # no banner without a mismatch

    def test_history_weighs_each_healthy_repository(self):
        g = {"id": "npm", "title": "npm", "note": "n", "items": ["a@1"], "mirrors": {
            n: {"url": f"https://npm.{n}.example", "rows": {"a@1": {"verdict": "ok", "value": "h", "detail": ""}}}
            for n in ("steady", "shaky")}}
        fa = lambda n: str(n).translate(pa.FA_DIGITS)
        days = [f"2026-10-{d:02}" for d in range(1, 15)]
        history = {"days": {d: {"npm/steady": {"ok": 4}, "npm/shaky": {"ok": 2, "missing": 2, "unreachable": 9}}
                            for d in days}}
        out = pa.providers([g], history, days, fa)
        self.assertLess(out.index('data-q="steady.example"'), out.index('data-q="shaky.example"'))
        self.assertIn('data-score="0.500"', out)  # half its answered checks ok; no answer is not counted
        out = pa.providers([g], None, [], fa)  # no history yet: everyone's is full
        self.assertEqual(out.count('data-score="1.000"'), 2)

    def test_dates_are_shown_in_the_persian_calendar(self):
        self.assertEqual(pa.jalali(2024, 3, 20), (1403, 1, 1))
        self.assertEqual(pa.jalali(2025, 3, 21), (1404, 1, 1))
        self.assertEqual(pa.jalali(2026, 3, 20), (1404, 12, 29))  # 1404 is a common year
        self.assertEqual(pa.jalali(2025, 3, 20), (1403, 12, 30))  # 1403 is a leap year
        self.assertEqual(pa.jalali(2026, 11, 3), (1405, 8, 12))
        self.assertEqual(pa.fa_day("2026-11-03"), "۱۴۰۵/۰۸/۱۲")

    def test_a_broken_file_is_kept_aside(self):
        with tempfile.TemporaryDirectory() as d:
            path = f"{d}/history.json"
            Path(path).write_text("{not json")
            with contextlib.redirect_stderr(io.StringIO()):
                pa.record_history(path, self.report("2026-11-03T10:00:00Z", {"a@1": "ok"}), {("npm", "m")})
            self.assertEqual(Path(path + ".broken").read_text(), "{not json")
            self.assertEqual(json.loads(Path(path).read_text())["days"], {"2026-11-03": {"npm/m": {"ok": 1}}})


def validate(value, schema, path="$"):
    """The part of JSON Schema that schema/summary-v1.schema.json uses: type, const, enum, required,
    properties, items, additionalProperties. Returns a list of errors."""
    errors = []
    types = schema.get("type")
    if types is not None:
        names = types if isinstance(types, list) else [types]
        ok = any((t == "null" and value is None) or (t == "boolean" and isinstance(value, bool))
                 or (t == "integer" and isinstance(value, int) and not isinstance(value, bool))
                 or (t == "number" and isinstance(value, (int, float)) and not isinstance(value, bool))
                 or (t == "string" and isinstance(value, str)) or (t == "array" and isinstance(value, list))
                 or (t == "object" and isinstance(value, dict)) for t in names)
        if not ok:
            return [f"{path}: {value!r} is not {types}"]
    if "const" in schema and value != schema["const"]:
        errors.append(f"{path}: {value!r} != {schema['const']!r}")
    if "enum" in schema and value not in schema["enum"]:
        errors.append(f"{path}: {value!r} not in {schema['enum']}")
    if isinstance(value, dict):
        for key in schema.get("required", []):
            if key not in value:
                errors.append(f"{path}: missing {key}")
        for key, sub in schema.get("properties", {}).items():
            if key in value:
                errors += validate(value[key], sub, f"{path}.{key}")
        extra = schema.get("additionalProperties")
        if isinstance(extra, dict):
            for key, v in value.items():
                if key not in schema.get("properties", {}):
                    errors += validate(v, extra, f"{path}.{key}")
    if isinstance(value, list) and "items" in schema:
        for i, v in enumerate(value):
            errors += validate(v, schema["items"], f"{path}[{i}]")
    return errors


SCHEMA = json.loads((Path(__file__).resolve().parent.parent / "schema" / "summary-v1.schema.json").read_text())


def ok_rows(items, ms=None):
    return {item: {"verdict": "ok", "value": "v", "detail": "", **({"ms": ms[i]} if ms else {})}
            for i, item in enumerate(items)}


class Safety(unittest.TestCase):
    def test_public_addresses(self):
        for public in ("8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"):
            self.assertTrue(pa.is_public_address(public), public)
        for private in ("127.0.0.1", "10.1.2.3", "172.16.0.1", "192.168.1.1", "169.254.169.254", "::1",
                        "fd00::1", "fe80::1%eth0", "0.0.0.0", "100.64.0.1", "not-an-ip"):
            self.assertFalse(pa.is_public_address(private), private)

    def test_a_public_mirror_cannot_send_the_auditor_to_a_private_address(self):
        for target in ("http://169.254.169.254/latest/meta-data/", "https://127.0.0.1:8080/api", "http://[::1]/",
                       "https://localhost/x", "http://metadata.google.internal/", "file:///etc/passwd", "ftp://8.8.8.8/x"):
            with self.assertRaises(RuntimeError, msg=target):
                pa.check_follow("https://8.8.8.8/v2/", target)
        pa.check_follow("https://8.8.8.8/v2/", "https://1.1.1.1/blob")  # public to public is followed

    def test_names_are_resolved_unless_through_the_tunnel(self):
        real = pa.socket.getaddrinfo
        pa.socket.getaddrinfo = lambda host, *a, **k: [(2, 1, 6, "", ("10.0.0.5", 0))] if host == "inside.example" \
            else [(2, 1, 6, "", ("8.8.8.8", 0))]
        try:
            with self.assertRaisesRegex(RuntimeError, "non-public"):
                pa.check_follow("https://mirror.example/", "https://inside.example/x")
            pa.check_follow("https://mirror.example/", "https://cdn.example/x")

            def never(*a, **k):
                raise AssertionError("resolved a name that the tunnel resolves")
            pa.socket.getaddrinfo = never
            pa.check_follow("https://mirror.example/", "https://inside.example/x", tunnel=True)
            with self.assertRaises(RuntimeError):
                pa.check_follow("https://mirror.example/", "https://10.0.0.5/x", tunnel=True)
        finally:
            pa.socket.getaddrinfo = real

    def test_a_private_mirror_may_redirect_anywhere(self):
        pa.check_follow("http://127.0.0.1:5000/", "http://127.0.0.1:5001/x")  # tests, mirrors inside a network

    def test_redirect_handler_and_token_realm_are_guarded(self):
        handler = pa.GuardedRedirect()
        req = pa.urllib.request.Request("https://8.8.8.8/x")
        with self.assertRaisesRegex(RuntimeError, "non-public"):
            handler.redirect_request(req, None, 302, "Found", {}, "http://169.254.169.254/")
        self.assertLessEqual(pa.GuardedRedirect.max_redirections, 5)
        with self.assertRaisesRegex(RuntimeError, "non-public"):
            pa.Registry("https://8.8.8.8").token('Bearer realm="http://127.0.0.1:9000/token",service="r"', "library/a")

    def test_answers_are_bounded(self):
        self.assertEqual(pa.read_limited(io.BytesIO(b"x" * 10), 10), b"x" * 10)
        with self.assertRaisesRegex(RuntimeError, "longer than 10 bytes"):
            pa.read_limited(io.BytesIO(b"x" * 11), 10)
        self.assertGreater(pa.MAX_BODY, 50 << 20)  # an npm packument served in full still fits


class Timing(unittest.TestCase):
    def test_nearest_rank(self):
        values = list(range(100, 1100, 100))  # 100..1000
        self.assertEqual((pa.nearest_rank(values, 50), pa.nearest_rank(values, 90)), (500, 900))
        self.assertEqual((pa.nearest_rank([7], 50), pa.nearest_rank([7], 90)), (7, 7))
        self.assertEqual(pa.nearest_rank([1, 2], 50), 1)

    def test_only_checks_that_gave_a_value_are_timed(self):
        rows = {}

        def check(item, row):
            if item == "bad":
                raise RuntimeError("HTTP 500")
            row["verdict"] = "ok"
        pa.check_rows(["a", "bad", "b"], rows, check)
        self.assertIsInstance(rows["a"]["ms"], int)
        self.assertNotIn("ms", rows["bad"])
        self.assertEqual(pa.check_time(rows)["n"], 2)
        self.assertIsNone(pa.check_time({"x": {"verdict": "unreachable", "value": None, "detail": "t"}}))


class Summary(unittest.TestCase):
    def setUp(self):
        self.brand = dict(pa.BRAND)
        pa.BRAND.update(site_url="https://audit.example.com", source_url="https://github.com/example/pkg-audit",
                        name="Example", disclosure="Example runs this page and the mirror named ours.",
                        vantage={"tunnel": "Iran"})
        items = [f"p{i}@1" for i in range(10)]
        self.report = {"generated": "2026-11-04T10:00:00Z", "groups": [{
            "id": "npm", "title": "npm", "note": "n", "items": items, "official": ["https://registry.npmjs.org"], "mirrors": {
                "ours": {"url": "https://npm.ours.example", "checked_at": "2026-11-04T09:58:00Z", "via": "tunnel",
                         "rows": ok_rows(items, ms=list(range(100, 1100, 100)))},
                "bad.example": {"url": "https://npm.bad.example", "checked_at": "2026-11-04T09:59:00Z",
                                "rows": {**ok_rows(items[1:]), items[0]: {"verdict": "mismatch", "value": "x", "detail": "d"}}},
                "new.example": {"url": "https://mirror.new.example", "checked_at": None, "rows": {}},
                "half.example": {"url": "https://half.example", "checked_at": "2026-11-04T09:00:00Z", "rows": ok_rows(items[:5])},
            }}]}

    def tearDown(self):
        pa.BRAND.clear()
        pa.BRAND.update(self.brand)

    def mirror(self, out, name):
        return next(m for m in out["groups"][0]["mirrors"] if m["name"] == name)

    def test_matches_the_schema(self):
        out = pa.summary(self.report)
        self.assertEqual(validate(out, SCHEMA), [])
        json.dumps(out)  # serialisable

    def test_verdicts_health_and_missing_data(self):
        out = pa.summary(self.report)
        ours, bad, new, half = (self.mirror(out, n) for n in ("ours", "bad.example", "new.example", "half.example"))
        self.assertEqual((ours["healthy"], ours["status"], ours["counts"], ours["score_points"]), (True, "complete", {"ok": 10}, 1.0))
        self.assertEqual((bad["healthy"], bad["counts"]), (False, {"ok": 9, "mismatch": 1}))
        self.assertEqual(bad["score_points"], 0)
        # nothing measured yet: no verdict on health, no time, no points
        self.assertEqual((new["healthy"], new["status"], new["measured"], new["check_ms"], new["checked_at"]),
                         (None, "pending", 0, None, None))
        self.assertEqual((half["healthy"], half["status"], half["measured"]), (False, "partial", 5))
        self.assertEqual(ours["check_ms"], {"median": 500, "p90": 900, "n": 10})
        self.assertEqual((ours["via"], bad["via"]), ("tunnel", "direct"))
        self.assertIsNone(ours["history"]["ok_share"])  # no history yet: not 100%, unknown
        self.assertEqual(ours["report_url"], "https://audit.example.com/#npm")
        self.assertEqual(out["methodology"], {"version": pa.METHODOLOGY_VERSION,
                                              "url": "https://github.com/example/pkg-audit/blob/main/METHODOLOGY.md"})
        self.assertEqual(out["vantage"], {"tunnel": "Iran"})
        self.assertIn("ours", out["operator"]["disclosure"])

    def test_provider_ranking_is_the_pages_and_reproducible(self):
        out = pa.summary(self.report)
        self.assertEqual([p["provider"] for p in out["providers"]][0], "ours.example")
        self.assertEqual([p["rank"] for p in out["providers"]], list(range(1, len(out["providers"]) + 1)))
        points = {}
        for m in out["groups"][0]["mirrors"]:
            points[m["provider"]] = points.get(m["provider"], 0) + m["score_points"]
        for p in out["providers"]:
            self.assertAlmostEqual(p["score"], points[p["provider"]], places=3)
        # the operator's own mirror is ranked by the same formula: change nothing but its name
        renamed = json.loads(json.dumps(self.report))
        g = renamed["groups"][0]["mirrors"]
        g["someone-else"] = g.pop("ours")
        self.assertEqual([p["score"] for p in pa.summary(renamed)["providers"]], [p["score"] for p in out["providers"]])

    def test_a_group_with_one_provider_still_scores_and_says_so(self):
        self.assertEqual(pa.summary(self.report)["groups"][0]["providers"], 4)
        alone = json.loads(json.dumps(self.report))
        alone["groups"][0]["mirrors"] = {"ours": alone["groups"][0]["mirrors"]["ours"]}
        out = pa.summary(alone)
        self.assertEqual(out["groups"][0]["providers"], 1)
        self.assertEqual(self.mirror(out, "ours")["score_points"], 1.0)
        self.assertEqual((out["providers"][0]["score"], out["providers"][0]["healthy_alone"]), (1.0, 1))
        self.assertIn("فقط یک ارائه‌دهنده این‌جا بررسی می‌شود", pa.page(alone))
        self.assertNotIn("فقط یک ارائه‌دهنده این‌جا بررسی می‌شود", pa.page(self.report))

    def test_history_weighs_the_points(self):
        days = {f"2026-10-{d:02}": {"npm/ours": {"ok": 9, "error": 1, "unreachable": 5}} for d in range(1, 21)}
        out = pa.summary(self.report, {"days": days, "events": []})
        ours = self.mirror(out, "ours")
        self.assertEqual(ours["history"], {"days": 20, "ok": 180, "answered": 200, "unanswered": 100, "ok_share": 0.9})
        self.assertAlmostEqual(ours["score_points"], 0.9)
        self.assertTrue(out["rules"]["history_complete"])

    def test_the_page_states_the_method_and_links_the_data(self):
        out = pa.page(self.report)
        self.assertIn(pa.METHODOLOGY_VERSION, out)
        self.assertIn('href="/summary.json"', out)
        self.assertIn("METHODOLOGY.md", out)
        self.assertIn("Example runs this page", out)
        self.assertIn("میانه ۵۰۰ میلی‌ثانیه".translate(pa.FA_DIGITS), out)
        ld = out.split('<script type="application/ld+json">', 1)[1].split("</script>", 1)[0]
        data = json.loads(ld)
        self.assertEqual((data["@type"], data["dateModified"]), ("Dataset", "2026-11-04T10:00:00Z"))
        self.assertIn("https://audit.example.com/summary.json", [d["contentUrl"] for d in data["distribution"]])

    def test_one_main_landmark_and_links_in_text_are_underlined(self):
        out = pa.page(self.report)
        self.assertEqual((out.count("<main"), out.count("</main>")), (1, 1))
        self.assertLess(out.index("</header>"), out.index("<main"))
        self.assertLess(out.index("</main>"), out.index("<footer>"))
        self.assertIn("section.note p a,section.note li a,footer a{text-decoration:underline", out)

    def test_json_ld_cannot_close_its_script(self):
        pa.BRAND["title"] = "</script><script>alert(1)</script>"
        out = pa.page(self.report)
        ld = out.split('<script type="application/ld+json">', 1)[1].split("</script>", 1)[0]
        self.assertIn("alert(1)", json.loads(ld)["name"])


if __name__ == "__main__":
    unittest.main()
