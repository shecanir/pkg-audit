#!/usr/bin/env python3
"""Check that Docker registry mirrors serve what the official registry serves, for the images people pull.

A mirror that is compromised, or an insider, can answer `alpine:3.20` with a manifest that is not
Docker Hub's. Docker would accept it (a pull by tag checks no publisher signature), so the only
way to notice is to ask Docker Hub and the mirror the same question and compare. This does that
for any number of mirrors, ours and other operators', and writes a JSON report and a static page.
An image is on Docker Hub unless its name starts with another registry (`mcr.microsoft.com/...`);
a mirror of such a registry is compared with that registry, for the images that are on it.

For every image in the list and every mirror:
  official  digest of the tag on registry-1.docker.io (asked directly, never through a mirror)
  mirror    digest the mirror answers for the same tag, and whether the manifest it serves by that
            digest really hashes to it (what Docker checks on a pull)
  verdict   ok        same digest as Docker Hub
            stale     another digest, but one Docker Hub itself still serves for this repository
                      (the tag moved and the mirror kept the old manifest): not an attack, the
                      mirror lags
            mismatch  a digest Docker Hub does not have at all, or a manifest whose bytes do not
                      hash to its digest: investigate at once
            missing   the mirror answered 404 (or 410): it does not have the image or tag
            unreachable  no answer at all (timeout, connection refused or reset)
            error     an answer that cannot be used (another HTTP status, a broken body)
Layers are not downloaded: a manifest names its config and layers by hash, so equal manifest
digests mean equal content, and a client verifies every blob against the manifest it pulled.

Mirror list, one per line: `name https://host [registry] [ip]`. The registry is the official one the
mirror stands for (default Docker Hub). With an ip the TLS connection goes to that address (SNI and
certificate still for the host), to probe one PoP or one proxy of a mirror instead of whatever DNS
answers.

Limits, stated so nobody reads more into a green page than it says: this detects a mirror that
answers these questions wrongly. It cannot see one that answers the auditor correctly and other
clients (an address range, a time window such as an outage) wrongly; run it from several
networks, inside and outside Iran, and probe each PoP, and still pin digests in your own builds.

Python 3.8+, standard library only.
"""
import argparse
import base64
import contextlib
import hashlib
import html
import http.client
import io
import ipaddress
import json
import os
import re
import socket
import queue
import ssl
import sys
import threading
import time
import urllib.parse
import urllib.request
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

try:
    import fcntl
except ImportError:  # Windows: no locking (the re-check queue then needs one writer)
    fcntl = None

HUB_HOST = "registry-1.docker.io"
ACCEPT = ", ".join([
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.docker.distribution.manifest.v2+json",
])


DEADLINE = None      # time.monotonic() value after which remaining checks are skipped (set by --max-seconds)
STUCK_AFTER = 120    # seconds a thread may go without finishing a request before it is abandoned
GRACE = 45           # seconds after the budget before stuck threads are abandoned
GIVE_UP_AFTER = 3    # consecutive items that timed out or could not connect: skip the rest of that mirror


PROGRESS = {}


def progress():
    """Called by a worker whenever it starts or finishes something: proof of life for run_jobs."""
    PROGRESS[threading.get_ident()] = time.monotonic()


def out_of_time():
    return DEADLINE is not None and time.monotonic() > DEADLINE


def skip_reason(down):
    if down >= GIVE_UP_AFTER:
        return f"skipped: {GIVE_UP_AFTER} requests in a row got no answer"
    return "skipped: the run's time budget (--max-seconds) was used up"


FAILED = ("missing", "unreachable", "error")  # verdicts of a check that gave no value to compare
NO_ANSWER = re.compile(r"timed out|timeout|refused|reset by peer|unreachable|no route|not known|getaddrinfo|"
                       r"Errno|SOCKS|tunnel|Remote end closed|EOF occurred|no answer", re.I)


def failure_verdict(detail, exc=None):
    """missing for a 404/410, unreachable when the host gave no answer, error for any other failure.
    Read from the message too, since get() turns network errors into RuntimeError(reason) and older
    reports saved only the message."""
    if re.match(r"HTTP (404|410)\b", detail):
        return "missing"
    if (exc is not None and unreachable(exc)) or NO_ANSWER.search(detail):
        return "unreachable"
    return "error"


def unreachable(exc):
    """True for failures that say the host is not answering at all (not an HTTP status)."""
    return isinstance(exc, (TimeoutError, OSError, http.client.HTTPException)) and not isinstance(
        exc, urllib.error.HTTPError)


class Pinned(http.client.HTTPSConnection):
    """HTTPS to a fixed address; SNI and certificate check stay on the host name."""

    def __init__(self, host, ip, **kw):
        super().__init__(host, **kw)
        self.ip = ip

    def connect(self):
        sock = socket.create_connection((self.ip, self.port), self.timeout)
        self.sock = ssl.create_default_context().wrap_socket(sock, server_hostname=self.host)


# Mirrors can be asked through a tunnel to a server inside Iran, so they are seen as a user there
# sees them (and those that do not answer from abroad answer at all): AUDIT_SOCKS=host:port of a
# local SOCKS5 proxy (an `ssh -N -D` to the Iranian server). With it set, every mirror of the
# mirrors/targets files uses it, except one whose line says `via=direct` (no secret in those files);
# how the tunnel connects is not this program's business and is never read or printed by it. The
# official sources are always asked directly. Without AUDIT_SOCKS every mirror is asked directly.
VIA_TUNNEL = set()  # mirror addresses that use the tunnel when there is one


def is_official(url):
    return any(url.startswith(base) for base in OFFICIAL.values())


def tunnel_address():
    value = os.environ.get("AUDIT_SOCKS", "").strip()
    host, _, port = value.rpartition(":")
    return (host, int(port)) if host and port.isdigit() else None


def via_tunnel(url):
    return (tunnel_address() is not None and not is_official(url)
            and any(url.rstrip("/").startswith(base) for base in VIA_TUNNEL))


def _recv_exact(sock, n):
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise RuntimeError("tunnel closed the connection")
        data += chunk
    return data


def socks_connect(proxy, host, port, timeout):
    """TCP connection to host:port through a SOCKS5 proxy (no authentication; the name is resolved by
    the proxy, so a mirror is looked up from where the tunnel ends)."""
    sock = socket.create_connection(proxy, timeout)
    try:
        sock.sendall(b"\x05\x01\x00")
        if _recv_exact(sock, 2) != b"\x05\x00":
            raise RuntimeError("tunnel proxy wants authentication")
        name = host.encode("idna")
        sock.sendall(b"\x05\x01\x00\x03" + bytes([len(name)]) + name + port.to_bytes(2, "big"))
        head = _recv_exact(sock, 4)
        if head[1] != 0:
            raise RuntimeError(f"tunnel could not reach {host} (SOCKS code {head[1]})")
        _recv_exact(sock, {1: 4, 4: 16}.get(head[3]) or _recv_exact(sock, 1)[0])
        _recv_exact(sock, 2)
        return sock
    except BaseException:
        sock.close()
        raise


class TunnelHTTPS(http.client.HTTPSConnection):
    """HTTPS through the tunnel; SNI and certificate check stay on the host name."""

    def connect(self):
        sock = socks_connect(tunnel_address(), self.host, self.port, self.timeout)
        self.sock = ssl.create_default_context().wrap_socket(sock, server_hostname=self.host)


class TunnelHandler(urllib.request.HTTPSHandler):
    def https_open(self, req):
        return self.do_open(TunnelHTTPS, req)


class Registry:
    """Anonymous pull access to one registry, following its Bearer challenge."""

    def __init__(self, base, ip=None):
        parts = urllib.parse.urlsplit(base)
        self.host, self.port, self.ip = parts.hostname, parts.port or 443, ip
        self.tunnel = via_tunnel(base)
        self.tokens = {}

    def request(self, method, path, repo, hops=0):
        for attempt in range(2):
            conn = (TunnelHTTPS(self.host, self.port, timeout=30) if self.tunnel
                    else Pinned(self.host, self.ip, port=self.port, timeout=30) if self.ip
                    else http.client.HTTPSConnection(self.host, self.port, timeout=30))
            headers = {"Accept": ACCEPT, "User-Agent": "pkg-audit/1"}
            if repo in self.tokens:
                headers["Authorization"] = "Bearer " + self.tokens[repo]
            try:
                conn.request(method, path, headers=headers)
                resp = conn.getresponse()
                body = resp.read()
                if resp.status == 401 and attempt == 0:
                    self.tokens[repo] = self.token(resp.getheader("WWW-Authenticate", ""), repo)
                    continue
                if resp.status in (301, 302, 303, 307, 308) and hops < 3:
                    # Docker follows these; Pulp answers manifests with a redirect to its content app
                    target = urllib.parse.urlsplit(urllib.parse.urljoin(
                        f"https://{self.host}{path}", resp.getheader("Location", "")))
                    if target.hostname == self.host:
                        return self.request(method, target.path + ("?" + target.query if target.query else ""),
                                            repo, hops + 1)
                    follow = urllib.request.Request(target.geturl(), method=method, headers={"Accept": ACCEPT})
                    opener = urllib.request.build_opener(TunnelHandler) if self.tunnel else urllib.request.build_opener()
                    with opener.open(follow, timeout=30) as final:
                        return final.status, final, final.read()
                return resp.status, resp, body
            finally:
                conn.close()

    def token(self, challenge, repo):
        """A pull token from the realm the registry names. For a mirror asked through the tunnel the
        token is asked through it too: a mirror that answers only from inside Iran usually issues its
        tokens from its own host as well."""
        if not challenge.lower().startswith("bearer "):
            raise RuntimeError("401 without a Bearer challenge")
        fields = dict(re.findall(r'(\w+)="([^"]*)"', challenge))
        query = urllib.parse.urlencode({"service": fields.get("service", ""),
                                        "scope": f"repository:{repo}:pull"})
        opener = urllib.request.build_opener(TunnelHandler) if self.tunnel else urllib.request.build_opener()
        with opener.open(f"{fields['realm']}?{query}", timeout=30) as resp:
            data = json.load(resp)
        return data.get("token") or data["access_token"]

    def digest(self, repo, tag):
        """The digest the registry gives the tag. Asked with HEAD first (no manifest body); a registry
        that answers HEAD with an error or without Docker-Content-Digest is asked with GET, as `docker
        pull` does, and without that header the digest is the sha256 of the manifest it served, which
        is the digest a client pulling by tag takes."""
        path = f"/v2/{repo}/manifests/{tag}"
        status, resp, _ = self.request("HEAD", path, repo)
        value = resp.getheader("Docker-Content-Digest") if status == 200 else None
        if value:
            return value
        got, resp, body = self.request("GET", path, repo)
        if got != 200:
            raise RuntimeError(f"HTTP {got} (HEAD and GET)" if got == status else f"HTTP {got} (HEAD {status})")
        return resp.getheader("Docker-Content-Digest") or "sha256:" + hashlib.sha256(body).hexdigest()

    def manifest_hashes_to(self, repo, digest):
        status, _, body = self.request("GET", f"/v2/{repo}/manifests/{digest}", repo)
        if status != 200:
            raise RuntimeError(f"HTTP {status} fetching manifest by digest")
        return "sha256:" + hashlib.sha256(body).hexdigest() == digest


def registry_host(name):
    return HUB_HOST if name.lower() in ("docker.io", "index.docker.io") else name.lower()


def split(ref):
    """(registry, repository, tag). A first path part with a dot, a port or `localhost` names the
    registry; any other image is on Docker Hub."""
    name, _, tag = ref.rpartition(":")
    first, _, rest = name.partition("/")
    host, repo = HUB_HOST, name
    if rest and ("." in first or ":" in first or first == "localhost"):
        host, repo = registry_host(first), rest
    if host == HUB_HOST and "/" not in repo:
        repo = "library/" + repo
    return host, repo, tag


def read_list(path):
    """Fields of every non-empty line. The mirror address on a line (the field starting with http)
    is remembered as one to ask through the tunnel, unless the line has a `via=direct` field. That
    field, and `via=tunnel` (the default now, still accepted), are taken out of the fields."""
    rows = [line.split("#", 1)[0].split() for line in Path(path).read_text().splitlines()
            if line.split("#", 1)[0].strip()]
    for fields in rows:
        direct = "via=direct" in fields
        fields[:] = [f for f in fields if f not in ("via=direct", "via=tunnel")]
        if not direct:
            VIA_TUNNEL.update(f.rstrip("/") for f in fields if f.startswith("http"))
    return rows


def parse_docker_mirrors(rows):
    """`name URL [registry] [ip]` lines -> (name, URL, registry the mirror stands for, ip or None)."""
    parsed = []
    for name, url, *rest in rows:
        upstream, ip = HUB_HOST, None
        for field in rest:
            try:
                ipaddress.ip_address(field)
                ip = field
            except ValueError:
                upstream = registry_host(field)
        parsed.append((name, url, upstream, ip))
    return parsed


def mirrors_with_images(mirrors, on_registry):
    """The (name, URL, registry, ip) mirrors whose registry has an image in the list. The others are
    left out with a warning, so a misspelt registry does not make a mirror vanish without a word."""
    for name, url, upstream, _ in mirrors:
        if upstream not in on_registry:
            print(f"docker mirror {name} ({url}) stands for {upstream}, which has no image in the image list; "
                  "not checked", file=sys.stderr)
    return [m for m in mirrors if m[2] in on_registry]


def check_rows(items, rows, check):
    """Run `check(item, row)` for each item, one after another, so a host sees one request at a
    time. `rows` is filled as it goes: if the run is cut short, what was done is still there.
    An item that was not checked (out of time) gets no row: it shows as "in the queue" and the
    mirror counts as unfinished, so the next run checks it, instead of an error that would stand
    until the mirror's next turn."""
    down = 0
    for item in items:
        progress()
        if out_of_time():
            continue
        row = rows[item] = {"verdict": "error", "value": None, "detail": ""}
        if down >= GIVE_UP_AFTER:  # a host that answers nothing is a finding, and is reported
            row.update(verdict="unreachable", detail=skip_reason(down))
            continue
        try:
            check(item, row)
            down = 0
        except Exception as exc:
            row.update(verdict=failure_verdict(str(exc), exc), detail=str(exc))
            down = down + 1 if unreachable(exc) else 0
        progress()


def now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def keep_or_new(prior, name, url, ip, active):
    """A mirror's entry: fresh when it is checked in this run, else the previous run's result
    (shown until its next turn comes), else empty."""
    if not active and prior and prior.get("url") == url:
        return {"url": url, "ip": ip, "rows": prior["rows"], "checked_at": prior.get("checked_at")}
    return {"url": url, "ip": ip, "rows": {}, "checked_at": now_iso() if active else None}


REGISTRY_TITLES = {
    HUB_HOST: "Docker Hub",
    "mcr.microsoft.com": "Microsoft (MCR)",
    "gcr.io": "Google (GCR)",
    "ghcr.io": "GitHub (GHCR)",
    "quay.io": "Quay",
    "docker.elastic.co": "Elastic",
    "registry.k8s.io": "Kubernetes (registry.k8s.io)",
}


def docker_group_id(upstream):
    """The report and page id of the group of one official registry. Docker Hub keeps `docker`, the
    id of the single Docker group of earlier versions, so its state, queue entries and links stay."""
    return "docker" if upstream == HUB_HOST else "docker-" + re.sub(r"[^a-z0-9]+", "-", upstream.lower()).strip("-")


def docker_group(refs, mirrors, active, prior_group=None):
    """The group, the jobs that ask the official registries (one per registry with a mirror checked
    now, so they are asked at the same time) and a function returning the mirror jobs once their
    answers are in. `mirrors` are (name, URL, registry, ip); each is compared on the images that
    are on its registry. main() makes one group per registry, so a mirror of MCR is not listed with
    the Docker Hub mirrors; a group of mirrors of several registries is still possible."""
    official, failed = {}, {}
    registries = {upstream: Registry(f"https://{upstream}") for _, _, upstream, _ in mirrors}
    items = {upstream: [ref for ref in refs if split(ref)[0] == upstream] for upstream in registries}
    if len(registries) == 1:
        (upstream,) = registries
        label = "Docker Hub" if upstream == HUB_HOST else upstream
        gid, title, note = (docker_group_id(upstream), REGISTRY_TITLES.get(upstream, upstream),
                            f"digest هر تگ در برابر {label}")
    else:
        gid, title, note = "docker", "Docker", "digest هر تگ در برابر رجیستری رسمی همان ایمیج"
    group = {"id": gid, "title": title, "items": [ref for ref in refs if split(ref)[0] in registries],
             "mirrors": {}, "note": note}
    prior = (prior_group or {}).get("mirrors", {})
    wanted = sorted({upstream for name, _, upstream, _ in mirrors if name in active})

    def ask_official(upstream):
        def ask():
            for ref in items[upstream]:
                _, repo, tag = split(ref)
                try:
                    official[ref] = registries[upstream].digest(repo, tag)
                except Exception as exc:
                    failed[upstream] = f"{ref}: {upstream} did not answer ({exc})"
                    return
        return ask

    def one_mirror(reg, upstream, rows):
        label = "Docker Hub" if upstream == HUB_HOST else upstream

        def check(ref, row):
            _, repo, tag = split(ref)
            row["value"] = reg.digest(repo, tag)
            if not reg.manifest_hashes_to(repo, row["value"]):
                row.update(verdict="mismatch", detail="manifest bytes do not hash to its digest")
            elif row["value"] == official[ref]:
                row["verdict"] = "ok"
            else:
                try:
                    known = registries[upstream].manifest_hashes_to(repo, row["value"])
                except RuntimeError:
                    known = False
                if known:
                    row.update(verdict="stale", detail=f"another digest {label} serves for this repository")
                else:
                    row.update(verdict="mismatch", detail=f"{label} has no manifest with this digest")
        return lambda: check_rows(items[upstream], rows, check)

    def after_official():
        for message in failed.values():  # nothing to compare against: those mirrors keep their last result
            print(message + "; its mirrors are not checked in this run", file=sys.stderr)
        jobs = []
        for name, url, upstream, ip in mirrors:
            if name not in active:
                continue
            if upstream in failed:
                group["mirrors"][name] = dict(keep_or_new(prior.get(name), name, url, ip, False),
                                              items=items[upstream])
                continue
            jobs.append((urllib.parse.urlsplit(url).hostname,
                         one_mirror(Registry(url, ip), upstream, group["mirrors"][name]["rows"])))
        return jobs

    for name, url, upstream, ip in mirrors:
        group["mirrors"][name] = dict(keep_or_new(prior.get(name), name, url, ip, name in active),
                                      items=items[upstream])
    return group, [(upstream, ask_official(upstream)) for upstream in wanted], after_official

# Package ecosystems: the same question as for Docker, asked of metadata that is immutable for a
# pinned version, so any difference from the official source is a mismatch (no `stale`).
OFFICIAL = {
    "npm": "https://registry.npmjs.org",
    "pypi": "https://pypi.org",
    "cargo": "https://index.crates.io",
    "maven": "https://repo1.maven.org/maven2",
    "nodejs": "https://nodejs.org/dist",
    "golang": "https://dl.google.com/go",
    "gomod": "https://proxy.golang.org",
    "gradle": "https://services.gradle.org/distributions",
    "rubygems": "https://index.rubygems.org",
    "helm": "https://get.helm.sh",
    "k8s": "https://dl.k8s.io/release",
    "hashicorp": "https://releases.hashicorp.com",
    "debian": "https://deb.debian.org/debian",
    "ubuntu": "https://archive.ubuntu.com/ubuntu",
    "almalinux": "https://repo.almalinux.org/almalinux",
    "rocky": "https://dl.rockylinux.org/pub/rocky",
    "epel": "https://dl.fedoraproject.org/pub/epel",
    "fedora": "https://dl.fedoraproject.org/pub/fedora/linux",
    "centos": "https://mirror.stream.centos.org",
    "alpine": "https://dl-cdn.alpinelinux.org/alpine",
    "archlinux": "https://geo.mirror.pkgbuild.com",
    "kali": "https://kali.download/kali",
    "opensuse": "https://download.opensuse.org",
    "chromedriver": "https://chromedriver.storage.googleapis.com",
    "chrome": "https://storage.googleapis.com/chrome-for-testing-public",
    "python": "https://www.python.org/ftp/python",
    "playwright": "https://cdn.playwright.dev/builds",
}
TITLES = {
    "npm": ("npm", "هش integrity نسخه‌های ثابت بسته‌ها در برابر registry.npmjs.org"),
    "pypi": ("PyPI", "sha256 فایل‌های هر نسخه در برابر pypi.org"),
    "cargo": ("Cargo", "cksum هر crate در index رسمی crates.io"),
    "maven": ("Maven", "sha1 فایل jar در برابر Maven Central"),
    "nodejs": ("Node.js", "فایل SHASUMS256.txt هر نسخه در برابر nodejs.org"),
    "golang": ("Go", "فایل sha256 هر نسخه در برابر dl.google.com"),
    "gomod": ("Go modules", "هش h1 نسخه‌های ثابت ماژول‌ها در برابر proxy.golang.org"),
    "gradle": ("Gradle", "فایل sha256 هر distribution در برابر services.gradle.org"),
    "rubygems": ("RubyGems", "checksum هر gem در compact index رسمی rubygems.org"),
    "helm": ("Helm", "فایل sha256 باینری Helm در برابر get.helm.sh"),
    "k8s": ("kubectl", "فایل sha256 باینری kubectl در برابر dl.k8s.io"),
    "hashicorp": ("HashiCorp", "فایل SHA256SUMS هر نسخه در برابر releases.hashicorp.com"),
    "debian": ("Debian", "sha256 چند بستهٔ .deb ثابت در برابر deb.debian.org"),
    "ubuntu": ("Ubuntu", "sha256 چند بستهٔ .deb ثابت در برابر archive.ubuntu.com"),
    "almalinux": ("AlmaLinux", "sha256 کلیدهای GPG ثابت در برابر repo.almalinux.org"),
    "rocky": ("Rocky Linux", "sha256 کلیدهای GPG ثابت در برابر dl.rockylinux.org"),
    "epel": ("EPEL", "sha256 کلیدهای GPG ثابت در برابر dl.fedoraproject.org/pub/epel"),
    "fedora": ("Fedora", "sha256 فایل‌های ثابت یک نسخهٔ منتشرشده در برابر dl.fedoraproject.org"),
    "centos": ("CentOS Stream", "sha256 فایل‌های ثابت درخت نصب در برابر mirror.stream.centos.org"),
    "alpine": ("Alpine", "sha256 فایل‌های ثابت منتشرشدهٔ minirootfs در برابر dl-cdn.alpinelinux.org"),
    "archlinux": ("Arch Linux", "sha256 چند بستهٔ ثابت در برابر geo.mirror.pkgbuild.com"),
    "kali": ("Kali Linux", "sha256 بسته‌های .deb ثابت در برابر kali.download"),
    "opensuse": ("openSUSE", "sha256 کلید GPG ثابت یک نسخهٔ Leap در برابر download.opensuse.org"),
    "chromedriver": ("ChromeDriver (قدیمی)", "sha256 فایل نسخهٔ ثابت chromedriver پیش از ۱۱۵ در برابر chromedriver.storage.googleapis.com"),
    "chrome": ("Chrome for Testing", "sha256 فایل chromedriver یک نسخهٔ ثابت در برابر storage.googleapis.com/chrome-for-testing-public"),
    "python": ("Python", "sha256 فایل امضای هر نسخه در برابر python.org/ftp/python"),
    "playwright": ("Playwright", "sha256 یک فایل ثابت مرورگرهای Playwright در برابر cdn.playwright.dev"),
}


def get(url, accept="*/*", tries=3, limit=None):
    """GET with a few retries: a mirror or the official source resetting one connection is not a verdict.
    With a limit, a body longer than that many bytes is an error (and is not read past the limit)."""
    req = urllib.request.Request(url, headers={"Accept": accept, "User-Agent": "pkg-audit/1"})
    last = None
    opener = urllib.request.build_opener(TunnelHandler) if via_tunnel(url) else urllib.request.build_opener()
    for attempt in range(tries):
        try:
            with opener.open(req, timeout=45) as resp:
                body = resp.read() if limit is None else resp.read(limit + 1)
                if limit is not None and len(body) > limit:
                    raise RuntimeError(f"answer longer than {limit} bytes")
                return resp.headers.get("Content-Type", ""), body
        except urllib.error.HTTPError as exc:
            if exc.code < 500 and exc.code != 429:
                raise RuntimeError(f"HTTP {exc.code}")
            last = f"HTTP {exc.code}"
        except (urllib.error.URLError, OSError) as exc:
            last = str(getattr(exc, "reason", exc))[:60]
        time.sleep(2 * (attempt + 1))
    raise RuntimeError(last or "no answer")


def pypi_files(base, name, version):
    norm = re.sub(r"[-_.]+", "-", name).lower()
    ctype, body = get(f"{base}/simple/{norm}/", "application/vnd.pypi.simple.v1+json, text/html;q=0.1")
    pairs = []
    if "json" in ctype:
        pairs = [(f["filename"], f["hashes"].get("sha256", "")) for f in json.loads(body)["files"]]
    else:  # PEP 503 HTML: <a href="...file#sha256=...">file</a>
        for href, text in re.findall(r'<a [^>]*href="([^"]+)"[^>]*>([^<]+)</a>', body.decode("utf-8", "replace")):
            pairs.append((text.strip(), href.partition("#sha256=")[2]))
    ours = sorted(f"{fn} {h}" for fn, h in pairs
                  if f"-{version}-" in fn or fn.endswith((f"-{version}.tar.gz", f"-{version}.zip")))
    if not ours:
        raise RuntimeError(f"no files for {version}")
    return "\n".join(ours)


def cargo_path(name):
    """Sparse-index path of a crate (https://doc.rust-lang.org/cargo/reference/registry-index.html)."""
    n = len(name)
    return f"{n}/{name}" if n < 3 else f"3/{name[0]}/{name}" if n == 3 else f"{name[:2]}/{name[2:4]}/{name}"


def go_escape(value):
    """The module proxy protocol writes an upper-case letter as `!` and its lower-case form."""
    return re.sub(r"[A-Z]", lambda match: "!" + match.group(0).lower(), value)


# A module zip comes from the mirror under test, so it is not trusted to be small: the zip as served
# and its files unpacked (a zip bomb is tens of kilobytes) are each held to this many bytes. `go`
# itself refuses a module zip over 500 MiB; the small modules worth listing are far below this.
GO_ZIP_LIMIT = 200 << 20


def go_module_hash(body, limit=GO_ZIP_LIMIT):
    """The `h1:` hash go.sum records for a module zip: sha256 of the sorted `sha256  name` lines of
    its files, so it is the value `go` itself verifies (and does not depend on how the zip is packed).
    Files are hashed a chunk at a time; more than `limit` bytes unpacked in all is an error."""
    files, total = [], 0
    with zipfile.ZipFile(io.BytesIO(body)) as archive:
        for info in archive.infolist():
            if info.is_dir():
                continue
            # The size the zip states, checked before anything is unpacked. zipfile never unpacks a
            # file past its stated size (and fails its CRC check if there was more), so it holds.
            total += info.file_size
            if total > limit:
                raise RuntimeError(f"module zip unpacks to more than {limit} bytes")
            digest = hashlib.sha256()
            with archive.open(info) as member:
                for chunk in iter(lambda: member.read(1 << 20), b""):
                    digest.update(chunk)
            files.append((info.filename, digest.hexdigest()))
    summary = "".join(f"{digest}  {name}\n" for name, digest in sorted(files))
    return "h1:" + base64.b64encode(hashlib.sha256(summary.encode()).digest()).decode()


# What the npm client itself asks for: the abbreviated document if the registry has it, else the full one.
# Some mirrors (Nexus) answer 406 to a scoped package asked for the abbreviated document only, though npm
# installs it from them; both documents carry `dist.integrity`.
NPM_ACCEPT = "application/vnd.npm.install-v1+json; q=1.0, application/json; q=0.8, */*"


def fetch_value(kind, base, item):
    if kind == "npm":
        name, _, version = item.rpartition("@")
        _, body = get(f"{base}/{urllib.parse.quote(name, safe='@')}", NPM_ACCEPT)
        return json.loads(body)["versions"][version]["dist"]["integrity"]
    if kind == "pypi":
        name, _, version = item.partition("==")
        return pypi_files(base, name, version)
    if kind == "cargo":
        name, _, version = item.rpartition("@")
        _, body = get(f"{base}/{cargo_path(name)}")
        for line in body.decode().splitlines():
            entry = json.loads(line)
            if entry["vers"] == version:
                return entry["cksum"]
        raise RuntimeError(f"{version} not in the index")
    if kind == "maven":
        group, artifact, version = item.split(":")
        _, body = get(f"{base}/{group.replace('.', '/')}/{artifact}/{version}/{artifact}-{version}.jar.sha1")
        value = body.decode("utf-8", "replace").split()[0].lower() if body.strip() else ""
        if not re.fullmatch(r"[0-9a-f]{40}", value):  # an HTML page or error text is no answer
            raise RuntimeError("not a sha1 checksum")
        return value
    if kind == "gomod":
        module, _, version = item.rpartition("@")
        _, body = get(f"{base}/{go_escape(module)}/@v/{go_escape(version)}.zip",  # the whole zip: its files are hashed
                      limit=GO_ZIP_LIMIT)
        return go_module_hash(body)
    if kind == "rubygems":
        name, _, version = item.rpartition("@")
        _, body = get(f"{base}/info/{name}")
        for line in body.decode().splitlines():
            if line.startswith(version + " "):
                return re.search(r"checksum:([0-9a-f]{64})", line).group(1)
        raise RuntimeError(f"{version} not in the index")
    _, body = get(f"{base}/{item}")  # nodejs, golang, gradle, helm, k8s, hashicorp: a small checksum file
    return "sha256:" + hashlib.sha256(body).hexdigest()


def package_group(kind, items, targets, active, prior_group=None):
    """Like docker_group, for one package ecosystem (one official job, none if no mirror is due)."""
    official = {}
    title, note = TITLES[kind]
    group = {"id": kind, "title": title, "items": list(items), "mirrors": {}, "note": note}
    prior = (prior_group or {}).get("mirrors", {})

    def ask_official():
        for item in items:
            try:
                official[item] = fetch_value(kind, OFFICIAL[kind], item)
            except Exception as exc:
                print(f"{kind} {item}: official source did not answer ({exc}); skipped", file=sys.stderr)

    def one_mirror(base, rows):
        def check(item, row):
            row["value"] = fetch_value(kind, base.rstrip("/"), item)
            if row["value"] == official[item]:
                row["verdict"] = "ok"
            else:
                row.update(verdict="mismatch", detail="differs from the official source")
        return lambda: check_rows(group["items"], rows, check)

    def after_official():
        if active:  # items the official source could not answer are not compared
            group["items"] = [i for i in items if i in official]
        return [(urllib.parse.urlsplit(base).hostname, one_mirror(base, group["mirrors"][name]["rows"]))
                for name, base in targets if name in active and group["items"]]

    for name, base in targets:
        group["mirrors"][name] = keep_or_new(prior.get(name), name, base, None, name in active)
    return group, ([(urllib.parse.urlsplit(OFFICIAL[kind]).hostname, ask_official)] if active else []), after_official


def run_jobs(jobs, workers):
    """Run (host, fn) jobs on up to `workers` threads. Jobs of one host run one after another
    (one request at a time per host, however many ecosystems it serves); different hosts overlap.
    Returns when all are done or the run's time budget plus a grace period has passed: a thread
    stuck in a network call cannot be killed, so it is abandoned (daemon threads)."""
    by_host = {}
    for host, fn in jobs:
        by_host.setdefault(host, []).append(fn)
    todo = queue.Queue()
    for fns in by_host.values():
        todo.put(fns)

    def worker():
        while True:
            progress()
            try:
                fns = todo.get_nowait()
            except queue.Empty:
                return
            for fn in fns:
                try:
                    fn()
                except Exception as exc:  # a bug in one check must not stop the others
                    print(f"job failed: {exc!r}", file=sys.stderr)

    threads = [threading.Thread(target=worker, daemon=True) for _ in range(max(1, min(workers, len(by_host))))]
    for t in threads:
        t.start()
    while True:
        alive = [t for t in threads if t.is_alive()]
        if not alive:
            return
        now = time.monotonic()
        if DEADLINE is not None and now > DEADLINE + GRACE:
            return
        # every thread left has made no progress for a long time: they are stuck in a network
        # call that cannot be interrupted, so stop waiting for them (daemon threads)
        if all(now - PROGRESS.get(t.ident, now) > STUCK_AFTER for t in alive):
            print(f"giving up on {len(alive)} stuck thread(s)", file=sys.stderr)
            return
        time.sleep(0.2)


def settle(report, active):
    """A row still empty after the run is one whose check was cut off mid-request: drop it, so it
    reads "in the queue" and is checked again, rather than storing an error nobody measured."""
    for g in report["groups"]:
        for name, m in g["mirrors"].items():
            if (g["id"], name) not in active:
                continue
            for item in list(m["rows"]):
                row = m["rows"][item]
                if row["verdict"] == "error" and not row["detail"] and row["value"] is None:
                    del m["rows"][item]


@contextlib.contextmanager
def queue_lock(path):
    """Exclusive lock for the queue file, shared by the job and the server."""
    if fcntl is None:
        yield
        return
    with open(str(path) + ".lock", "a") as handle:
        fcntl.flock(handle, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(handle, fcntl.LOCK_UN)


def queue_read(path):
    """{ "<group id>/<mirror name>": requested-at ISO time } (empty if the file is missing or broken)."""
    try:
        data = json.loads(Path(path).read_text())
        return {str(k): str(v) for k, v in data.items()} if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def queue_write(path, queue):
    write_atomic(str(path), json.dumps(queue, indent=2, sort_keys=True) + "\n")


def queue_add(path, qid):
    with queue_lock(path):
        queue = queue_read(path)
        queue.setdefault(qid, now_iso())
        queue_write(path, queue)


def queue_remove(path, qids):
    with queue_lock(path):
        queue = queue_read(path)
        for qid in qids:
            queue.pop(qid, None)
        queue_write(path, queue)


def row_of(rows, item):
    return rows.get(item) or {"verdict": "pending", "value": None, "detail": "waiting for its first check"}


LEGACY_UNCHECKED = ("skipped: the run's time budget", "no answer before the run's time budget")


HISTORY_DAYS = 90  # daily counts, and changes other than a mismatch, are kept this long


def tehran_day(iso):
    t = datetime.strptime(iso, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    return t.astimezone(timezone(timedelta(hours=3, minutes=30))).strftime("%Y-%m-%d")


def add_history(history, report, active):
    """Add this run's fresh results (the mirrors in `active` only, never a result kept from an earlier
    run) to `history` and return it:
      days[day][group/mirror][verdict]  how many item checks got that verdict that day (Tehran date);
      last[group/mirror/item]           the item's latest verdict, to see changes;
      events                            every change of an item's verdict, and the first time one is a
                                        mismatch; mismatches are kept for ever, other changes HISTORY_DAYS.
    The first result of an item is only remembered (no event) unless it is a mismatch."""
    at = report["generated"]
    days = history.setdefault("days", {})
    last = history.setdefault("last", {})
    events = history.setdefault("events", [])
    urls = history.setdefault("mirrors", {})
    today = days.setdefault(tehran_day(at), {})
    for g in report["groups"]:
        for name, m in g["mirrors"].items():
            if (g["id"], name) not in active:
                continue
            key = f"{g['id']}/{name}"
            urls[key] = m["url"]
            counts = today.setdefault(key, {})
            for item, row in m["rows"].items():
                verdict = row["verdict"]
                if verdict == "pending":
                    continue
                counts[verdict] = counts.get(verdict, 0) + 1
                before = last.get(f"{key}/{item}")
                if before != verdict and (before is not None or verdict == "mismatch"):
                    events.append({"at": at, "group": g["id"], "mirror": name, "item": item, "from": before,
                                   "to": verdict, "value": row.get("value"), "detail": row.get("detail", "")})
                last[f"{key}/{item}"] = verdict
    cutoff = (datetime.strptime(at, "%Y-%m-%dT%H:%M:%SZ") - timedelta(days=HISTORY_DAYS)).strftime("%Y-%m-%dT%H:%M:%SZ")
    for day in [d for d in days if d < cutoff[:10]]:
        del days[day]
    history["events"] = [e for e in events if e["at"] >= cutoff or "mismatch" in (e["from"], e["to"])]
    history["updated"] = at
    return history


def record_history(path, report, active):
    """Read the history file, add this run and write it back. An unreadable file is kept beside as
    .broken and a new history starts; a failure here never stops the run."""
    p = Path(path)
    try:
        history = json.loads(p.read_text()) if p.exists() else {}
        if not isinstance(history, dict):
            raise ValueError("not an object")
    except (OSError, ValueError) as exc:
        print(f"history {path} unreadable ({exc}), kept as {path}.broken; starting a new one", file=sys.stderr)
        with contextlib.suppress(OSError):
            p.replace(path + ".broken")
        history = {}
    try:
        history = add_history(history, report, active)
        write_atomic(path, json.dumps(history, indent=1, sort_keys=True) + "\n")
        return history
    except Exception as exc:  # the report and the page matter more than the history
        print(f"history {path} not written: {exc!r}", file=sys.stderr)
        return None


HISTORY_SHOWN_AFTER = 14  # days with results before the page shows the history; fewer would mislead
HISTORY_BAR_DAYS = 30


def history_days(history):
    """The days that have results, oldest first; empty while there are fewer than HISTORY_SHOWN_AFTER."""
    days = sorted(d for d, mirrors in (history or {}).get("days", {}).items() if any(mirrors.values()))
    return days if len(days) >= HISTORY_SHOWN_AFTER else []


def day_tone(c):
    """Colour class of one day of one mirror: any mismatch is red; else by the share of answered checks
    that were ok (no answer is not counted against the mirror, it is often the network)."""
    answered = sum(v for k, v in c.items() if k not in ("unreachable", "pending"))
    if not c:
        return "none", answered
    if c.get("mismatch"):
        return "bad", answered
    if not answered:
        return "err", answered
    share = c.get("ok", 0) / answered
    return ("ok" if share >= .99 else "stale" if share >= .9 else "miss"), answered


def trend(history, days, key, fa):
    """The last HISTORY_BAR_DAYS days of one mirror (or of several: a list of keys, added up): a bar per
    day and the share of ok answers."""
    if not days:
        return ""
    shown = days[-HISTORY_BAR_DAYS:]
    cells, ok, answered, silent = "", 0, 0, 0
    for d in shown:
        c = {}
        for k in [key] if isinstance(key, str) else key:
            for verdict, n in history["days"][d].get(k, {}).items():
                c[verdict] = c.get(verdict, 0) + n
        tone, a = day_tone(c)
        ok, answered, silent = ok + c.get("ok", 0), answered + a, silent + c.get("unreachable", 0)
        date = d.replace("-", "/").translate(FA_DIGITS)
        text = (f"{fa(c.get('ok', 0))} سالم از {fa(a)} پاسخ"
                + (f"، {fa(c['mismatch'])} ناهمخوان" if c.get("mismatch") else "")
                + (f"، {fa(c['unreachable'])} بی‌پاسخ" if c.get("unreachable") else "")) if c else "بررسی نشد"
        cells += f'<i class="d {tone}" data-tt="{date}" data-td="{text}"></i>'
    pct = f"{fa(round(100 * ok / answered))}٪" if answered else "—"
    tip = (f"در {fa(len(shown))} روز گذشته {fa(ok)} پاسخ از {fa(answered)} پاسخ همان مقدار منبع رسمی بود"
           + (f"؛ {fa(silent)} بار جوابی نیامد که حساب نشده" if silent else "") + ".")
    return (f'<span class="trend"><span class="bars">{cells}</span>'
            f'<span class="pct" tabindex="0" data-td="{tip}">{fa(len(shown))} روز: {pct}</span></span>')


def mismatch_log(history, days, fa):
    """The note on past mismatches: every one in the history, newest first, or that there was none."""
    if not days:
        return ""
    seen = [e for e in history.get("events", []) if e["to"] == "mismatch"]
    since = days[0].replace("-", "/").translate(FA_DIGITS)
    if not seen:
        return (f'<h2>سابقه‌ی ناهمخوانی‌ها</h2><p>از {since} ({fa(len(days))} روز) تا امروز در هیچ میروری '
                f'ناهمخوانی دیده نشده است.</p>')
    urls = history.get("mirrors", {})
    rows = ""
    for e in sorted(seen, key=lambda e: e["at"], reverse=True)[:50]:
        host = urls.get(f"{e['group']}/{e['mirror']}", e["mirror"]).split("://", 1)[-1]
        fixed = next((x["at"] for x in history["events"] if x["at"] > e["at"] and x["group"] == e["group"]
                      and x["mirror"] == e["mirror"] and x["item"] == e["item"] and x["from"] == "mismatch"), None)
        rows += (f'<li><bdi dir="ltr">{html.escape(host)}</bdi> · <bdi dir="ltr">{html.escape(e["item"])}</bdi> · '
                 f'{tehran_day(e["at"]).replace("-", "/").translate(FA_DIGITS)}'
                 f'{"، رفع شد " + tehran_day(fixed).replace("-", "/").translate(FA_DIGITS) if fixed else "، هنوز ناهمخوان"}</li>')
    return (f'<h2>سابقه‌ی ناهمخوانی‌ها</h2><p>هر باری که از {since} تا امروز میروری مقداری داد که منبع رسمی '
            f'نداشت، این‌جا می‌ماند؛ حتی اگر بعداً درست شده باشد:</p><ul>{rows}</ul>')


def load_state(path):
    """Previous report by group id; anything unreadable is simply no state. Rows that older versions
    saved for checks they never made (out of time) are dropped, so those mirrors are checked again."""
    try:
        data = json.loads(Path(path).read_text())
        groups = {g["id"]: g for g in data["groups"]}
        for g in groups.values():
            for m in g.get("mirrors", {}).values():
                rows = m.get("rows", {})
                for item in [i for i, r in rows.items() if str(r.get("detail", "")).startswith(LEGACY_UNCHECKED)]:
                    del rows[item]
                for r in rows.values():  # older reports had one "error" for every failure
                    if r.get("verdict") == "error" and r.get("detail"):
                        r["verdict"] = failure_verdict(str(r["detail"]))
        return groups
    except (OSError, ValueError, KeyError, TypeError, AttributeError):
        return {}


def asked_pairs(queue, specs):
    """The (group id, mirror name) pairs of the queue that exist in the lists (a request for a
    mirror that was removed from them is dropped on the next run)."""
    known = {(gid, name) for gid, _, ms in specs for name, _ in ms}
    return {tuple(qid.split("/", 1)) for qid in queue if "/" in qid} & known


def pick_active(specs, prior, slots, slot):
    """specs: [(group id, items, [(mirror name, url)])]. Which (group id, name) pairs to check now.
    Hosts are spread evenly over `slots` turns; a mirror with no usable earlier result (new, URL
    changed, items added) is checked at once whatever its turn."""
    hosts = sorted({urllib.parse.urlsplit(url).hostname for _, _, ms in specs for _, url in ms})
    turn = {h: i % slots for i, h in enumerate(hosts)}
    active = set()
    for gid, items, ms in specs:
        for name, url in ms:
            old = prior.get(gid, {}).get("mirrors", {}).get(name)
            fresh = bool(old) and old.get("url") == url and all(i in old.get("rows", {}) for i in items)
            if slots <= 1 or not fresh or turn[urllib.parse.urlsplit(url).hostname] == slot:
                active.add((gid, name))
    return active


FA_DIGITS = str.maketrans("0123456789", "۰۱۲۳۴۵۶۷۸۹")
BADGE = {  # verdict -> (css class, icon, Persian label)
    "ok": ("ok", "✓", "سالم"),
    "stale": ("stale", "◷", "قدیمی"),
    "mismatch": ("bad", "✕", "ناهمخوان"),
    "missing": ("miss", "∅", "پیدا نشد (۴۰۴)"),
    "unreachable": ("err", "○", "در دسترس نیست"),
    "error": ("fail", "!", "خطا"),
    "pending": ("err", "…", "در صف بررسی"),
}
DEFAULT_BRAND = {
    "ours": "",                      # name (as in the targets files) of the operator's own mirror
    "ours_label": "",                # label shown on that mirror's column, e.g. "ما"
    "title": "پایش میرورها",
    "name": "",                      # name in the page header
    "tagline": "",                   # line under it
    "description": "مقایسه‌ی مستقل بسته‌ها و ایمیج‌های میرورها با منبع رسمی",
    "footer_html": "",               # trusted HTML for the page footer
    "credits_html": "",              # trusted HTML: extra <li> items (your own deployment tools) in the credits section
    "site_url": "",                  # public URL of the page, e.g. https://audit.example.com; enables link previews
    "source_url": "",                # public repository of this tool; shown in the header and the notes
    "og_image": "/og.jpg",
    "recheck_minutes": 0,            # >0: show "request a re-check" buttons; a mirror can be re-checked
                                     # this many minutes after its last check (needs serve.py)           # 1200x630 JPEG, path under site_url, for link previews (Telegram, Bale, ...)
}
BRAND = dict(DEFAULT_BRAND)

CSS = """
@font-face{font-family:Vazirmatn;src:url(/vazirmatn.woff2) format('woff2');font-weight:100 900;font-display:swap}
:root{--bg:#f4f1ea;--card:#fff;--fg:#0e2218;--muted:#5d6d63;--line:#e2ddd0;--primary:#157a4a;
--ok:#1f9d5c;--stale:#c99a00;--bad:#d6334a;--err:#97a29b;--miss:#e2581c;--fail:#5f6b64;--missbg:#e2581c1f;--failbg:#5f6b641f;
--okbg:#1f9d5c1c;--stalebg:#e0a8002a;--badbg:#d6334a1f;--errbg:#97a29b22;
--font:Vazirmatn,Tahoma,'Segoe UI',system-ui,sans-serif}
@media(prefers-color-scheme:dark){:root{--bg:#0b1411;--card:#111c18;--fg:#e4ede7;--muted:#8ea196;--line:#1d2d26;
--primary:#6fd69a;--ok:#4ccf86;--stale:#e8c048;--bad:#ff6f83;--err:#6f8178;--miss:#ff9550;--fail:#a3b0a8;--missbg:#ff955024;--failbg:#a3b0a81f;
--okbg:#4ccf8622;--stalebg:#e8c04824;--badbg:#ff6f8326;--errbg:#6f81781f}}
*{box-sizing:border-box}html{-webkit-text-size-adjust:100%;scroll-behavior:smooth}
body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.8 var(--font)}
a{color:var(--primary);text-decoration:none}a:hover{text-decoration:underline}
.wrap{max-width:980px;margin:0 auto;padding:0 18px}
header{padding:26px 0 0;display:flex;align-items:center;gap:12px}
header img{width:40px;height:40px;border-radius:11px;flex:none}
header .brand{font-weight:700;line-height:1.4}header .brand small{display:block;color:var(--muted);font-weight:400;font-size:12.5px}
header .src{margin-inline-start:auto;direction:ltr;font:600 12.5px ui-monospace,Menlo,Consolas,monospace;border:1px solid var(--line);background:var(--card);color:var(--fg);border-radius:999px;padding:4px 12px;white-space:nowrap}
header .src:hover{border-color:var(--primary);color:var(--primary);text-decoration:none}
h1{font-size:clamp(26px,5vw,40px);line-height:1.35;margin:22px 0 8px;font-weight:800;letter-spacing:-.01em}
h1 span{color:var(--primary)}
.lead{color:var(--muted);margin:0 0 20px;max-width:64ch}
.verdict{display:flex;align-items:center;gap:14px;border-radius:16px;padding:14px 18px;margin-bottom:18px;font-weight:600}
.verdict.good{background:var(--okbg);color:var(--ok)}.verdict.warn{background:var(--stalebg);color:var(--stale)}
.verdict.alert{background:var(--badbg);color:var(--bad)}
.verdict b{font-size:22px}.vsub{font-weight:400;color:var(--muted);font-size:13.5px}
.vsub p{margin:6px 0 0}.vsub ul{margin:8px 0 0;padding:0;list-style:none}
.vsub li{margin:6px 0;display:flex;flex-wrap:wrap;align-items:baseline;gap:4px 12px}
.vsub .eco{display:inline-flex;align-items:baseline;gap:8px;background:var(--card);border-radius:10px;padding:1px 10px}
.vsub .eco a{font-weight:700;color:var(--fg);text-decoration:none}.vsub .eco bdi{font:12.5px ui-monospace,Menlo,Consolas,monospace}.vsub .more{color:var(--muted)}
.vsub a{color:inherit;text-decoration:underline dotted}.vsub b{font-size:inherit;color:var(--fg)}.vsub em{color:var(--primary);font-style:normal}
.nums{display:flex;flex-wrap:wrap;gap:8px 20px;margin-bottom:6px;color:var(--muted);font-size:13.5px}
.nums b{color:var(--fg);font-weight:700}
nav.tabs{position:sticky;top:0;z-index:5;background:color-mix(in srgb,var(--bg) 88%,transparent);backdrop-filter:blur(8px);
display:flex;gap:6px;overflow-x:auto;padding:10px 0;margin:6px 0 4px;scrollbar-width:none}
nav.tabs::-webkit-scrollbar{display:none}
nav.tabs a{flex:none;border-radius:999px;padding:3px 14px;font-size:13.5px;color:var(--muted);border:1px solid var(--line);background:var(--card)}
nav.tabs a:hover{color:var(--fg);border-color:var(--primary);text-decoration:none}
h2.gt{font-size:21px;margin:30px 0 2px;scroll-margin-top:56px}
p.gn{color:var(--muted);font-size:13.5px;margin:0 0 12px}
.list{background:var(--card);border:1px solid var(--line);border-radius:18px;overflow:hidden}
details.m{border-bottom:1px solid var(--line)}details.m:last-child{border-bottom:0}
details.m summary{list-style:none;cursor:pointer;display:grid;grid-template-columns:minmax(0,1.25fr) auto minmax(0,1.6fr) 18px;
align-items:center;gap:6px 18px;padding:13px 18px}
details.m summary::-webkit-details-marker{display:none}
details.m summary:hover{background:var(--errbg)}
details.m summary:after{content:"";justify-self:center;width:7px;height:7px;border:solid var(--muted);border-width:0 0 1.5px 1.5px;
transform:translateY(-2px) rotate(-45deg);transition:transform .15s}
details.m[open] summary:after{transform:translateY(2px) rotate(135deg)}
.who{min-width:0}.who .host{direction:ltr;text-align:right;display:block;font:13px ui-monospace,Menlo,Consolas,monospace;overflow-wrap:anywhere}
.when{display:block;color:var(--muted);font-size:12px;margin-top:2px}.when.old{color:var(--stale)}
.items li.req{justify-content:flex-start;gap:12px;border-bottom:1px dashed var(--line);padding:9px 0}
.re{font:600 13px var(--font);color:var(--primary);background:transparent;border:1px solid var(--primary);border-radius:999px;padding:3px 14px;cursor:pointer}
.re:disabled{color:var(--muted);border-color:var(--line);cursor:default}.rs{color:var(--muted);font-size:12.5px}
.tag{display:inline-block;font-size:11.5px;font-weight:600;color:var(--muted);border:1px solid var(--line);border-radius:999px;padding:0 8px;margin-inline-start:8px;vertical-align:1px}
.score{font-weight:800;font-size:17px;min-width:3.2em;text-align:center}.score small{font-weight:400;color:var(--muted);font-size:11.5px;display:block;line-height:1.2}
.score.good{color:var(--ok)}.score.warn{color:var(--stale)}.score.alert{color:var(--bad)}.score.none{color:var(--err)}
.strip{display:flex;flex-wrap:wrap;gap:3px}
.sq{width:14px;height:14px;border-radius:4px;background:var(--ok);display:block}
.sq.stale{background:var(--stale)}.sq.bad{background:var(--bad)}.sq.err{background:transparent;border:2px solid var(--err)}
.sq.miss{background:var(--miss)}.sq.fail{background:var(--fail)}
.items{margin:0;padding:2px 18px 12px;list-style:none;border-top:1px dashed var(--line)}
.items li{display:flex;align-items:center;justify-content:space-between;gap:10px;padding:7px 0;border-bottom:1px solid var(--line)}
.items li:last-child{border-bottom:0}
.items code{direction:ltr;font:13px ui-monospace,Menlo,Consolas,monospace;overflow-wrap:anywhere}
.b{display:inline-flex;align-items:center;gap:5px;border-radius:999px;padding:1px 10px;font-size:12px;font-weight:600;flex:none}
.b.ok{color:var(--ok);background:var(--okbg)}.b.stale{color:var(--stale);background:var(--stalebg)}
.b.bad{color:var(--bad);background:var(--badbg)}.b.err{color:var(--err);background:var(--errbg)}
.b.miss{color:var(--miss);background:var(--missbg)}.b.fail{color:var(--fail);background:var(--failbg)}
section.note{margin:26px 0;padding:6px 0}
section.note h2{font-size:17px;margin:18px 0 4px}section.note p,section.note li{color:var(--muted);margin:4px 0}
section.note ul{padding-inline-start:20px;margin:6px 0}
footer{border-top:1px solid var(--line);padding:22px 0 44px;color:var(--muted);font-size:13.5px}
footer .row{display:flex;flex-wrap:wrap;gap:6px 18px;margin-top:8px}
@media(max-width:680px){
details.m summary{grid-template-columns:minmax(0,1fr) auto 18px;padding:12px 14px}
.strip{grid-column:1/-1;order:5}
.items{padding:2px 14px 10px}
}

/* --- modern layer --- */
:root{--r:20px;--shadow:0 1px 2px rgba(14,34,24,.04),0 8px 28px -12px rgba(14,34,24,.14);--glow:#157a4a14}
@media(prefers-color-scheme:dark){:root{--shadow:0 1px 0 rgba(255,255,255,.03) inset,0 10px 30px -14px rgba(0,0,0,.6);--glow:#6fd69a12}}
body{background:radial-gradient(1100px 420px at 85% -80px,var(--glow),transparent 70%),var(--bg);min-height:100vh}
.wrap{max-width:1040px}
header{padding-top:22px}header img{box-shadow:var(--shadow)}
h1{font-size:clamp(30px,6vw,52px);letter-spacing:-.025em;margin:26px 0 10px}
h1 span{background:linear-gradient(120deg,var(--primary),var(--ok));-webkit-background-clip:text;background-clip:text;color:transparent}
.lead{font-size:16px}
.verdict{border-radius:var(--r);padding:18px 22px;box-shadow:var(--shadow);border:1px solid color-mix(in srgb,currentColor 18%,transparent)}
.verdict b{font-size:24px;letter-spacing:-.01em}
.nums{display:grid;grid-template-columns:repeat(6,1fr);gap:12px;margin:16px 0 8px}
@media(max-width:900px){.nums{grid-template-columns:repeat(3,1fr)}}
.nums span{background:var(--card);border:1px solid var(--line);border-radius:16px;padding:12px 16px;box-shadow:var(--shadow);font-size:12.5px;line-height:1.5}
.nums b:first-child{display:block;font-size:24px;line-height:1.3;letter-spacing:-.01em}
.nums .t{display:flex;flex-direction:column;gap:2px;cursor:help;transition:border-color .15s,box-shadow .15s,opacity .15s}
.nums .t[role=button]{cursor:pointer}.nums .t[role=button]:hover{border-color:color-mix(in srgb,var(--c) 55%,var(--line))}
.nums .t[aria-pressed=true]{border-color:var(--c);box-shadow:0 0 0 3px color-mix(in srgb,var(--c) 22%,transparent)}
.nums.filtering .t:not([aria-pressed=true]){opacity:.5}
#sres button{font:600 12.5px var(--font);color:var(--primary);background:none;border:0;padding:0 6px;cursor:pointer;text-decoration:underline dotted}
.nums .t em{display:flex;align-items:center;gap:7px;font-style:normal;font-weight:700;font-size:13px;color:var(--fg)}
.nums .t em .sq{flex:none;width:10px;height:10px;box-shadow:none}.nums .t em .sq.err{border-width:1.5px}
.nums .t small{color:var(--muted);font-size:12px;line-height:1.5}
.nums .t.zero{opacity:.55}.nums .t.zero b:first-child{color:var(--muted)}
.nums .t.hot.bad{border-color:color-mix(in srgb,var(--bad) 45%,var(--line));background:color-mix(in srgb,var(--badbg) 100%,var(--card))}
.nums .t.hot.bad b:first-child{color:var(--bad)}
.trend{display:flex;align-items:center;gap:8px;margin-top:4px}
.bars{display:flex;gap:2px;direction:ltr}
.bars .d{width:4px;height:12px;border-radius:2px;background:var(--ok);display:block}
.bars .d.stale{background:var(--stale)}.bars .d.miss{background:var(--miss)}.bars .d.bad{background:var(--bad)}
.bars .d.err{background:var(--err);opacity:.6}.bars .d.none{background:var(--line)}
.trend .pct{color:var(--muted);font-size:11.5px;white-space:nowrap;cursor:help}
section.note.past ul{list-style:none;padding:0}section.note.past li{font-size:13.5px}
.vendors{margin:18px 0 6px;background:var(--card);border:1px solid var(--line);border-radius:var(--r);box-shadow:var(--shadow);overflow:hidden}
.vtitle{padding:14px 20px 8px;display:flex;flex-wrap:wrap;align-items:center;gap:8px 16px}.vtitle>div{flex:1 1 320px}.vtitle h2{font-size:17px;margin:0;line-height:1.5}.vtitle p{margin:0;color:var(--muted);font-size:12.5px}
.vhead,.vrow{display:grid;grid-template-columns:minmax(0,1.3fr) 44px minmax(0,1.3fr) 112px minmax(0,1.1fr);gap:2px 16px;align-items:center;padding:6px 20px}
.vendors.hist .vhead,.vendors.hist .vrow{grid-template-columns:minmax(0,1.3fr) 44px minmax(0,1.1fr) 112px minmax(0,1fr) minmax(0,1.2fr)}
.vfoot{margin:0;padding:12px 20px 14px;border-top:1px solid var(--line);color:var(--muted);font-size:12.5px;line-height:1.9}
.vfoot b{color:var(--fg)}.vfoot a{text-decoration:underline dotted}
.vrepo{text-align:center}.vrepo b{display:block;font-size:15px;line-height:1.3}.vrepo small{color:var(--muted);font-size:11px}
.vpct{cursor:help}
.vhead{font-size:11.5px;font-weight:600;color:var(--muted);border-top:1px solid var(--line);padding-top:7px;padding-bottom:7px}
.vrow{width:100%;font:inherit;color:inherit;text-align:start;background:none;border:0;border-top:1px solid var(--line);cursor:pointer;transition:background .15s}
.vrow:hover,.vrow:focus-visible{background:var(--glow);outline:none}
.vn{min-width:0}.vn bdi{font:600 13px ui-monospace,Menlo,Consolas,monospace}.vn .tag{vertical-align:1px}
.vn small{display:block;color:var(--muted);font-size:11.5px;line-height:1.5}
.vbar{display:flex;gap:2px;height:8px;border-radius:99px;overflow:hidden;background:var(--line);direction:ltr}
.seg{display:block;min-width:3px}.seg.ok{background:var(--ok)}.seg.bad{background:var(--bad)}.seg.stale{background:var(--stale)}
.seg.miss{background:var(--miss)}.seg.fail{background:var(--fail)}.seg.err{background:var(--err);opacity:.6}
.vpct b{font-size:15px;line-height:1.3;display:block}.vpct small{color:var(--muted);font-size:11px}
.vis{font-size:12px;color:var(--muted);line-height:1.6}.vis .bad{color:var(--bad);font-weight:700}
.vh .trend{margin:0}
@media(max-width:680px){.vhead{display:none}
.vrow,.vendors.hist .vrow{grid-template-columns:minmax(0,1fr) auto;padding:11px 16px}
.vbar,.vis,.vh{grid-column:1/-1}.vis.clean{display:none}.vpct{grid-row:1;grid-column:2;text-align:end}
.vrepo{display:none}.vn small:before{content:attr(data-r) " · "}}
.tip{position:fixed;z-index:50;top:0;left:0;max-width:min(360px,calc(100vw - 24px));background:var(--card);color:var(--fg);
border:1px solid var(--line);border-radius:12px;padding:8px 12px;font-size:12.5px;line-height:1.65;
box-shadow:0 12px 32px -12px rgba(0,0,0,.35);pointer-events:none;opacity:0;transition:opacity .12s}
.tip.on{opacity:1}
.tip .tt{display:block;direction:ltr;text-align:left;font:600 12.5px ui-monospace,Menlo,Consolas,monospace;overflow-wrap:anywhere}
.tip .tl{display:flex;align-items:center;gap:7px;font-weight:700}.tip .tl .sq{width:9px;height:9px;box-shadow:none}
.tip .td{display:block;color:var(--muted);overflow-wrap:anywhere}.tip .td[dir=ltr]{text-align:left;font:12px ui-monospace,Menlo,Consolas,monospace}
.search{position:relative;margin:18px 0 4px}
.search input{width:100%;font:500 15px var(--font);color:var(--fg);background:var(--card);border:1px solid var(--line);border-radius:999px;
padding:13px 48px 13px 20px;box-shadow:var(--shadow);outline:none;transition:border-color .15s,box-shadow .15s}
.search input::placeholder{color:var(--muted)}
.search input:focus{border-color:var(--primary);box-shadow:0 0 0 4px color-mix(in srgb,var(--primary) 18%,transparent)}
.search svg{position:absolute;inset-inline-start:auto;right:18px;top:50%;transform:translateY(-50%);width:18px;height:18px;color:var(--muted);pointer-events:none}
.search kbd{position:absolute;left:16px;top:50%;transform:translateY(-50%);font:600 11.5px ui-monospace,Menlo,monospace;color:var(--muted);border:1px solid var(--line);border-radius:6px;padding:1px 7px}
.search input:not(:placeholder-shown)~kbd{display:none}
#sres{color:var(--muted);font-size:13px;min-height:22px;margin:8px 4px 0}
nav.tabs{padding:12px 0}
nav.tabs a{padding:5px 16px;transition:all .15s;box-shadow:var(--shadow)}
nav.tabs a:hover{background:var(--primary);color:#fff;border-color:var(--primary)}
nav.tabs a.off{opacity:.35}
.sort,.vsort{flex:none;display:inline-flex;margin-inline-start:auto;border:1px solid var(--line);border-radius:999px;background:var(--card);padding:2px;box-shadow:var(--shadow)}
.sort button,.vsort button{font:600 12.5px var(--font);color:var(--muted);background:transparent;border:0;border-radius:999px;padding:3px 12px;cursor:pointer}
.sort button[aria-pressed=true],.vsort button[aria-pressed=true]{background:var(--primary);color:#fff}
h2.gt{font-size:23px;letter-spacing:-.015em;margin-top:38px}
.list{border-radius:var(--r);box-shadow:var(--shadow)}
details.m{transition:background .15s}details.m summary{padding:15px 20px}
details.m[open]{background:color-mix(in srgb,var(--glow) 100%,transparent)}
details.m[open] summary{border-bottom:0}
details.m summary:hover{background:var(--glow)}
.who .host{font-size:13.5px;font-weight:600}
.score{font-size:19px}
.sq{width:12px;height:12px;border-radius:50%;box-shadow:0 0 0 2px var(--card)}
.b{padding:2px 11px}
.items li:hover{background:var(--glow)}
.items li{padding:8px 6px;border-radius:8px}
.hide{display:none!important}
.re{transition:all .15s}.re:hover:not(:disabled){background:var(--primary);color:#fff}
section.note{background:var(--card);border:1px solid var(--line);border-radius:var(--r);padding:8px 26px 20px;box-shadow:var(--shadow)}
footer{margin-top:10px}
.verdict details{width:100%}
.verdict summary{list-style:none;cursor:pointer;display:flex;align-items:center;gap:12px}
.verdict summary::-webkit-details-marker{display:none}
.verdict .verdict summary b,.verdict summary b{font-size:19px}
.vhint{margin-inline-start:auto;display:inline-flex;align-items:center;gap:8px;font:600 12.5px var(--font);color:var(--muted);border:1px solid color-mix(in srgb,currentColor 25%,transparent);border-radius:999px;padding:3px 12px}
.vhint:after{content:"";width:6px;height:6px;border:solid currentColor;border-width:0 0 1.5px 1.5px;transform:translateY(-2px) rotate(-45deg);transition:transform .15s}
details[open]>summary .vhint:after{transform:translateY(2px) rotate(135deg)}
.verdict details[open]>summary{margin-bottom:6px}
.verdict .vsub b{font-size:inherit;letter-spacing:0}  /* host names in the details: not the heading's size */
.verdict{padding:12px 20px}
@media(max-width:680px){.search kbd{display:none}.nums{grid-template-columns:repeat(2,1fr)}.search input{font-size:14px}}
@media(prefers-reduced-motion:reduce){*{transition:none!important;scroll-behavior:auto!important}}
"""

SEARCH = r'''<script>
(function(){var q=document.getElementById('q'),res=document.getElementById('sres');if(!q)return;
var groups=[].map.call(document.querySelectorAll('h2.gt'),function(h){
  var note=h.nextElementSibling,list=note.nextElementSibling;
  return{h:h,note:note,list:list,rows:[].slice.call(list.querySelectorAll('details.m')),tab:document.querySelector('nav.tabs a[href="#'+h.id+'"]')}});
var opened=new WeakMap(),st='',stl='',tiles=[].slice.call(document.querySelectorAll('.nums .t[role=button]'));
function norm(t){return t.toLowerCase().replace(/ي/g,'ی').replace(/ك/g,'ک')}
function run(){var v=norm(q.value.trim()),words=v.split(/\s+/).filter(Boolean),hits=0,filt=words.length||st;
  groups.forEach(function(g){var gtext=norm(g.h.textContent),shown=0;
    g.rows.forEach(function(d){
      var hay=norm(d.textContent)+' '+gtext,ok=words.every(function(w){return hay.indexOf(w)>-1})&&(!st||!!d.querySelector('.items .b.'+st));
      d.classList.toggle('hide',!ok);
      if(ok){shown++;
        if(filt){if(!opened.has(d))opened.set(d,d.open);d.open=true;
          var host=d.querySelector('.host').textContent,whole=words.length&&words.every(function(w){return norm(host+' '+gtext).indexOf(w)>-1});
          d.querySelectorAll('.items li').forEach(function(li){
            var w=!words.length||whole||words.every(function(w){return norm(li.textContent+' '+host).indexOf(w)>-1});
            var s=!st||li.classList.contains('req')||!!li.querySelector('.b.'+st);
            li.classList.toggle('hide',!(w&&s))})}
        else{if(opened.has(d)){d.open=opened.get(d);opened.delete(d)}d.querySelectorAll('.items li').forEach(function(li){li.classList.remove('hide')})}}
    });
    var on=shown>0||!filt;
    [g.h,g.note,g.list].forEach(function(e){e.classList.toggle('hide',!on)});
    if(g.tab)g.tab.classList.toggle('off',!on);
    hits+=shown;});
  res.textContent=filt?(hits?hits.toLocaleString('fa-IR')+' میرور'+(st?' با وضعیت «'+stl+'»':'')+' پیدا شد':'چیزی پیدا نشد؛ نام میزبان، اکوسیستم یا بسته را امتحان کنید'):'';
  if(st){var x=document.createElement('button');x.type='button';x.className='unst';x.textContent='برداشتن فیلتر';res.appendChild(x)}}
function status(c){st=st===c?'':c;tiles.forEach(function(t){var on=t.dataset.tc===st;t.setAttribute('aria-pressed',on);if(on)stl=t.dataset.tl});
  document.querySelector('.nums').classList.toggle('filtering',!!st);run()}
document.addEventListener('click',function(e){var t=e.target.closest&&e.target.closest('.nums .t[role=button]');if(t)status(t.dataset.tc);
  else if(e.target.closest&&e.target.closest('#sres .unst'))status('')});
document.addEventListener('keydown',function(e){var t=e.target.closest&&e.target.closest('.nums .t[role=button]');
  if(t&&(e.key==='Enter'||e.key===' ')){e.preventDefault();status(t.dataset.tc)}});
q.addEventListener('input',run);
document.addEventListener('click',function(e){var r=e.target.closest&&e.target.closest('.vrow');if(!r)return;
  q.value=r.dataset.q;run();var to=document.querySelector('nav.tabs');if(to)to.scrollIntoView({behavior:'smooth',block:'start'})});
function order(by){
  groups.forEach(function(g){g.rows.slice().sort(function(a,b){
    if(by==='score'){var d=a.dataset.score-b.dataset.score||a.dataset.bad-b.dataset.bad;if(d)return d}
    return a.dataset.name<b.dataset.name?-1:a.dataset.name>b.dataset.name?1:0}).forEach(function(d){g.list.appendChild(d)})});
  [].forEach.call(document.querySelectorAll('.sort button'),function(b){b.setAttribute('aria-pressed',b.dataset.sort===by)});
  try{localStorage.setItem('sort',by)}catch(e){}}
document.addEventListener('click',function(e){var b=e.target.closest&&e.target.closest('.sort button');if(b)order(b.dataset.sort)});
try{if(localStorage.getItem('sort')==='name')order('name')}catch(e){}
// provider table: score by default; the visitor can sort by share ok, repositories or name
function vorder(by){var box=document.querySelector('.vrows');if(!box)return;
  var f=function(r,k){return parseFloat(r.dataset[k])||0},keys={score:['score','pct'],pct:['pct','score'],repos:['repos','score']}[by];
  [].slice.call(box.children).sort(function(a,b){
    if(keys)for(var i=0;i<keys.length;i++){var d=f(b,keys[i])-f(a,keys[i]);if(Math.abs(d)>1e-9)return d}
    return a.dataset.name<b.dataset.name?-1:a.dataset.name>b.dataset.name?1:0}).forEach(function(r){box.appendChild(r)});
  [].forEach.call(document.querySelectorAll('.vsort button'),function(b){b.setAttribute('aria-pressed',b.dataset.vsort===by)});
  try{localStorage.setItem('vsort',by)}catch(e){}}
document.addEventListener('click',function(e){var b=e.target.closest&&e.target.closest('.vsort button');if(b)vorder(b.dataset.vsort)});
try{var vs=localStorage.getItem('vsort');if(vs&&vs!=='score')vorder(vs)}catch(e){}
document.addEventListener('keydown',function(e){
  if(e.key==='/'&&document.activeElement!==q&&!/input|textarea/i.test(document.activeElement.tagName)){e.preventDefault();q.focus()}
  else if(e.key==='Escape'&&document.activeElement===q){q.value='';run();q.blur()}
  else if(e.key==='Escape'&&st)status('')});
})();
</script>'''


STALE_AFTER = 3 * 3600   # a result older than this is shown as old


def checked_label(iso):
    """('آخرین بررسی ساعت HH:MM', is_old) in Tehran time, from a mirror's checked_at."""
    try:
        t = datetime.strptime(iso, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except (TypeError, ValueError):
        return "در صف بررسی", True
    local = t.astimezone(timezone(timedelta(hours=3, minutes=30)))
    old = (datetime.now(timezone.utc) - t).total_seconds() > STALE_AFTER
    return ("آخرین بررسی " + local.strftime("%H:%M").translate(FA_DIGITS)
            + (" · قدیمی" if old else "")), old


TIP = r'''<script>
(function(){var tip=document.createElement('div'),cur=null;tip.className='tip';tip.setAttribute('aria-hidden','true');document.body.appendChild(tip);
function line(cls,text,ltr){var s=document.createElement('span');s.className=cls;s.textContent=text;if(ltr)s.dir='ltr';return s}
function show(el){var d=el.dataset;if(!d.tt&&!d.td){hide();return}cur=el;tip.textContent='';
  if(d.tt)tip.appendChild(line('tt',d.tt));
  if(d.tl){var l=line('tl',d.tl),q=document.createElement('i');q.className='sq '+(d.tc==='ok'?'':d.tc);l.prepend(q);l.style.color='var(--'+d.tc+')';tip.appendChild(l)}
  if(d.td)tip.appendChild(line('td',d.td,!/[\u0600-\u06FF]/.test(d.td)));
  var r=el.getBoundingClientRect(),w=tip.offsetWidth,h=tip.offsetHeight,x=r.left+r.width/2-w/2,y=r.top-h-8;
  if(y<8)y=r.bottom+8;x=Math.max(8,Math.min(x,innerWidth-w-8));
  tip.style.transform='translate('+Math.round(x)+'px,'+Math.round(y)+'px)';tip.classList.add('on')}
function hide(){cur=null;tip.classList.remove('on')}
function pick(e){return e.target.closest&&e.target.closest('[data-tt],[data-td]')}
document.addEventListener('pointerover',function(e){var el=pick(e);if(el!==cur)el?show(el):hide()});
document.addEventListener('focusin',function(e){var el=pick(e);el?show(el):hide()});
document.addEventListener('focusout',hide);addEventListener('scroll',hide,{passive:true});
})();
</script>'''

SCRIPT = r'''<script>
(function(){var CD=__MIN__*60000;
function fa(n){return String(n).replace(/\d/g,function(d){return '۰۱۲۳۴۵۶۷۸۹'[d]})}
function say(b,t,off){b.nextElementSibling.textContent=t;b.disabled=!!off}
function wait(b,left){say(b,'بررسی بعدی تا '+fa(Math.ceil(left/60000))+' دقیقه‌ی دیگر ممکن است',true)}
document.querySelectorAll('button.re').forEach(function(b){
  if(b.dataset.queued){say(b,'در صف بررسی',true);return}
  var t=Date.parse(b.dataset.checked||'');
  if(t&&CD-(Date.now()-t)>0)wait(b,CD-(Date.now()-t));
});
document.addEventListener('click',function(e){
  var b=e.target.closest&&e.target.closest('button.re');if(!b||b.disabled)return;
  say(b,'در حال ثبت…',true);
  fetch('/api/recheck',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({group:b.dataset.g,mirror:b.dataset.m})})
  .then(function(r){return r.json().then(function(j){return[r.status,j]})})
  .then(function(x){var s=x[0],j=x[1];
    if(j.status==='queued')say(b,'در صف بررسی؛ نتیجه تا چند دقیقه‌ی دیگر می‌آید',true);
    else if(j.status==='cooldown')wait(b,j.retry_after*1000);
    else say(b,'ثبت نشد؛ کمی بعد دوباره امتحان کنید',false)})
  .catch(function(){say(b,'ثبت نشد؛ کمی بعد دوباره امتحان کنید',false)});
});})();
</script>'''


def provider(host):
    """The registrable domain of a host (mirror.arvancloud.ir -> arvancloud.ir, x.ut.ac.ir -> ut.ac.ir):
    mirrors are grouped by it, which says nothing about who runs them."""
    labels = (host or "").lower().rstrip(".").split(".")
    if all(p.isdigit() for p in labels):
        return host
    if len(labels) > 2 and labels[-2] in ("ac", "co", "com", "gov", "id", "net", "org", "sch"):
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


PARTS = [("ok", "ok", "سالم"), ("mismatch", "bad", "ناهمخوان"), ("stale", "stale", "قدیمی"),
         ("missing", "miss", "پیدا نشد"), ("error", "fail", "خطا"), ("unreachable", "err", "بی‌پاسخ")]


def confidence(ok, n, z=1.96):
    """Lower bound of the 95% Wilson interval of ok/n: the share of ok answers we can be confident of.
    It rewards a high share and, for the same share, more checks (11 of 12 beats 1 of 16, and 94 of 94
    beats 3 of 3), without letting size alone win."""
    if not n:
        return 0.0
    p = ok / n
    return (p + z * z / (2 * n) - z * ((p * (1 - p) + z * z / (4 * n)) / n) ** .5) / (1 + z * z / n)


def providers(groups, history, days, fa):
    """One row per provider (domain): its repositories checked here, its score, a bar of its answers by
    status, what the rest were and, once there is history, its last days. The score (0-100) is the
    confidence bound of its share of ok answers; every item of a repository that served a mismatch
    counts as not ok. A row filters the lists to that domain."""
    per = {}
    for g in groups:
        for n, m in g["mirrors"].items():
            p = provider(urllib.parse.urlsplit(m["url"]).hostname)
            v = per.setdefault(p, {"groups": [], "counts": {}, "keys": [], "ours": False, "trusted": 0})
            if g["title"] not in v["groups"]:
                v["groups"].append(g["title"])
            v["keys"].append(f"{g['id']}/{n}")
            v["ours"] = v["ours"] or (bool(BRAND["ours"]) and n == BRAND["ours"])
            refs = m.get("items", g["items"])
            verdicts = [row_of(m["rows"], item)["verdict"] for item in refs]
            for verdict in verdicts:
                v["counts"][verdict] = v["counts"].get(verdict, 0) + 1
            if "mismatch" not in verdicts:  # a repository that served a forged value earns nothing
                v["trusted"] += verdicts.count("ok")
    if not per:
        return ""
    rows = []
    for p, v in per.items():
        c = v["counts"]
        total = sum(n for k, n in c.items() if k != "pending")
        v["score"] = 100 * confidence(v["trusted"], total)
        rows.append((-round(v["score"], 1), -(c.get("ok", 0) / total if total else 0), p, v, c, total))
    out = ""
    for *_, p, v, c, total in sorted(rows, key=lambda r: r[:3]):  # score, then share ok, then name
        ok = c.get("ok", 0)
        segs = "".join(f'<span class="seg {cls}" style="flex:{c[k]}"></span>' for k, cls, _ in PARTS if c.get(k))
        parts = "، ".join(f"{fa(c[k])} {label}" for k, _, label in PARTS if c.get(k))
        rest = " · ".join(f'<span class="{cls}">{fa(c[k])} {label}</span>' for k, cls, label in PARTS[1:] if c.get(k))
        ecos = "، ".join(html.escape(t) for t in v["groups"][:3]) + (f" +{fa(len(v['groups']) - 3)}" if len(v["groups"]) > 3 else "")
        tag = f'<span class="tag">{html.escape(BRAND["ours_label"])}</span>' if v["ours"] else ""
        past = f'<span class="vh">{trend(history, days, v["keys"], fa)}</span>' if days else ""
        repos = len(v["keys"])
        score = fa(round(v["score"])) if total else "—"
        why = (f"سهمی از پاسخ‌ها که با ۹۵٪ اطمینان سالم است، از {fa(total)} بررسی"
               f"{'؛ موردهای مخزنی که ناهمخوانی داشت سالم حساب نشد' if v['trusted'] < ok else ''}.")
        share = ok / total if total else 0
        out += (f'<button type="button" class="vrow" data-q="{html.escape(p)}" data-score="{v["score"]:.2f}" '
                f'data-pct="{share:.4f}" data-repos="{repos}" data-name="{html.escape(p)}">'
                f'<span class="vn"><bdi dir="ltr">{html.escape(p)}</bdi>{tag}<small data-r="{fa(repos)} مخزن">{ecos}</small></span>'
                f'<span class="vrepo"><b>{fa(repos)}</b><small>مخزن</small></span>'
                f'<span class="vbar" data-td="{parts}">{segs}</span>'
                f'<span class="vpct" data-td="{why}"><b>{score}</b>'
                f'<small>{fa(round(100 * ok / total)) + "٪" if total else "—"} سالم · {fa(ok)} از {fa(total)}</small></span>'
                f'<span class="vis{"" if rest else " clean"}">{rest or "همه سالم"}</span>{past}</button>')
    head = ('<div class="vhead"><span>ارائه‌دهنده</span><span>مخزن</span><span>پاسخ‌ها</span><span>امتیاز</span><span>بقیه</span>'
            + (f"<span>{fa(min(len(days), HISTORY_BAR_DAYS))} روز گذشته</span>" if days else "") + "</div>")
    sort = "".join(f'<button type="button" data-vsort="{k}" aria-pressed="{str(k == "score").lower()}">{t}</button>'
                   for k, t in [("score", "امتیاز"), ("pct", "درصد سالم"), ("repos", "تعداد مخزن"), ("name", "الفبا")])
    return (f'<section class="vendors{" hist" if days else ""}"><div class="vtitle"><div><h2>ارائه‌دهنده‌ها</h2>'
            f'<p>میرورها بر اساس دامنه‌ی میزبان؛ برای دیدن میرورهای هر کدام بزنید. معیار امتیاز زیر جدول آمده است.</p></div>'
            f'<span class="vsort" role="group" aria-label="ترتیب ارائه‌دهنده‌ها">{sort}</span></div>'
            f'{head}<div class="vrows">{out}</div>{rank_note()}</section>')


def rank_note():
    """The footnote under the provider table: what the score is, and where to propose a better one."""
    src = BRAND["source_url"].rstrip("/")
    ask = (f' معیار بهتری به نظرتان می‌رسد؟ در <a href="{html.escape(src)}/issues" rel="noopener">issueها</a> '
           f'پیشنهاد دهید یا pull request بفرستید تا اضافه شود؛ '
           f'<a href="{html.escape(src)}#how-providers-are-ranked" rel="noopener">توضیح کامل</a>.') if src else ""
    return ('<p class="vfoot"><b>امتیاز چطور حساب می‌شود؟</b> امتیاز (۰ تا ۱۰۰) سهمی از پاسخ‌های ارائه‌دهنده است '
            'که با ۹۵٪ اطمینان می‌توان گفت سالم است (کران پایین بازه‌ی ویلسون). پس هم درصد سالم مهم است و هم '
            'تعداد بررسی‌ها: ۱۱ سالم از ۱۲ از ۱ سالم از ۱۶ بالاتر است، و ۹۴ از ۹۴ از ۳ از ۳. بی‌پاسخ و خطا سالم '
            'حساب نمی‌شوند، و اگر مخزنی حتی یک مورد ناهمخوان بدهد، هیچ‌کدام از پاسخ‌هایش سالم حساب نمی‌شود. '
            f'همه‌ی ارائه‌دهنده‌ها، از جمله شکن، با همین فرمول سنجیده می‌شوند.{ask}</p>')


def render_group(g, fa, history=None, days=()):
    mirrors = g["mirrors"]
    summary = []
    for n, m in mirrors.items():
        rows = m["rows"]
        done = sum(r["verdict"] == "ok" for r in rows.values())
        bad = sum(r["verdict"] == "mismatch" for r in rows.values())
        answered = sum(r["verdict"] not in ("unreachable", "error") for r in rows.values())
        ours = bool(BRAND["ours"]) and n == BRAND["ours"]
        refs = m.get("items", g["items"])  # the images of the registry this mirror stands for
        share = done / len(refs) if refs else 0
        host = m["url"].split("://", 1)[-1]
        summary.append((not ours, -share, bad, -answered, host.lower(), n, m, done, bad, answered, ours, refs))
    summary.sort(key=lambda t: t[1:5])  # best score, fewer problems, then by name; ours gets no place of its own
    out = ""
    for _, share, _, _, _, n, m, done, bad, answered, ours, refs in summary:
        seen = checked_label(m.get("checked_at"))
        rows = m["rows"]
        pct = round(100 * done / len(refs)) if refs else 0
        tone = "none" if not answered else "alert" if bad else "good" if done == len(refs) else "warn"
        host = html.escape(m["url"].split("://", 1)[-1])
        key = f'data-score="{share:.4f}" data-bad="{bad}" data-name="{host.lower()}"{" data-ours=1" if ours else ""}'
        tag = f'<span class="tag">{html.escape(BRAND["ours_label"])}</span>' if ours else ""
        strip = ""
        for ref in refs:
            cls = BADGE[row_of(rows, ref)["verdict"]][0]
            label, detail = BADGE[row_of(rows, ref)["verdict"]][2], row_of(rows, ref)["detail"]
            strip += (f'<i class="sq {"" if cls == "ok" else cls}" role="img" aria-label="{html.escape(f"{ref}: {label}")}" '
                      f'data-tt="{html.escape(ref)}" data-tc="{cls}" data-tl="{label}" data-td="{html.escape(detail)}"></i>')
        items = ""
        if BRAND["recheck_minutes"] > 0:
            items += (f'<li class="req"><button type="button" class="re" data-g="{html.escape(g["id"])}" '
                      f'data-m="{html.escape(n)}" data-checked="{html.escape(m.get("checked_at") or "")}"'
                      f'{" data-queued=1" if m.get("queued") else ""}>درخواست بررسی مجدد</button>'
                      f'<span class="rs" aria-live="polite"></span></li>')
        for ref in sorted(refs, key=lambda r: row_of(rows, r)["verdict"] == "ok"):  # problems first
            cls, icon, label = BADGE[row_of(rows, ref)["verdict"]]
            value, detail = row_of(rows, ref)["value"] or "", row_of(rows, ref)["detail"]
            items += (f'<li><code>{html.escape(ref)}</code><span class="b {cls}" data-tt="{html.escape(value)}" '
                      f'data-td="{html.escape(detail)}">'
                      f'<span aria-hidden="true">{icon}</span>{label}</span></li>')
        opened = " open" if bad else ""
        out += (f'<details class="m"{opened} {key}><summary><div class="who"><span class="host">{host}</span>{tag}<span class="when{" old" if seen[1] else ""}">{seen[0]}{" · در صف بررسی" if m.get("queued") and m.get("checked_at") else ""}</span>{trend(history, days, f"{g['id']}/{n}", fa)}</div>'
                f'<div class="score {tone}">{fa(pct)}٪<small>{fa(done)} از {fa(len(refs))}</small></div>'
                f'<div class="strip">{strip}</div></summary><ul class="items">{items}</ul></details>')
    return (f'<h2 class="gt" id="{g["id"]}">{html.escape(g["title"])}</h2>'
            f'<p class="gn">{html.escape(g["note"])}</p><div class="list">{out}</div>')


def page(report, history=None):
    # Ecosystems with the most mirrors first; equal ones keep the report's order.
    groups = sorted(report["groups"], key=lambda g: -len(g["mirrors"]))
    counts = {"ok": 0, "stale": 0, "mismatch": 0, "missing": 0, "unreachable": 0, "error": 0}
    total = mirror_hosts = 0
    seen = set()
    for g in groups:
        for n, m in g["mirrors"].items():
            seen.add(m["url"].split("/")[2])
            for row in m["rows"].values():
                counts[row["verdict"]] = counts.get(row["verdict"], 0) + 1
                total += 1
    try:
        stamp = datetime.strptime(report["generated"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        tehran = stamp.astimezone(timezone(timedelta(hours=3, minutes=30)))
        when = tehran.strftime("%Y/%m/%d ساعت %H:%M").translate(FA_DIGITS) + " به وقت تهران"
    except ValueError:
        when = html.escape(report["generated"])
    fa = lambda n: str(n).translate(FA_DIGITS)
    tiles = "".join(
        f'<span class="t {c}{" zero" if not counts[v] and v != "ok" else " hot" if counts[v] else ""}" tabindex="0" '
        f'style="--c:var(--{c})"{" role=button aria-pressed=false" if counts[v] else ""} '
        f'data-tc="{c}" data-tl="{BADGE[v][2]}" data-td="{t}{" برای دیدن میرورهایش بزنید." if counts[v] else ""}">'
        f'<b>{fa(counts[v])}</b>'
        f'<em><i class="sq {"" if c == "ok" else c}" aria-hidden="true"></i>{BADGE[v][2]}</em><small>{s}</small></span>'
        for v, c, s, t in [
            ("ok", "ok", f"از {fa(total)} پاسخ، همان مقدار منبع رسمی", "میرور همان مقداری را داد که منبع رسمی می‌دهد."),
            ("mismatch", "bad", "مقداری که منبع رسمی ندارد",
             "میرور مقداری داد که منبع رسمی هیچ‌وقت نداده؛ باید بررسی شود."),
            ("stale", "stale", "نسخه‌ی قبلیِ یک تگ Docker",
             "فقط در Docker: تگ در منبع رسمی جابه‌جا شده و میرور هنوز نسخه‌ی قبلی را دارد. حمله نیست."),
            ("missing", "miss", "میرور این مورد را ندارد", "میرور جواب داد ولی این ایمیج یا بسته را ندارد."),
            ("error", "fail", "۴۰۳، ۵۰۰ یا پاسخ نامعتبر",
             "میرور جواب داد ولی با خطای دیگری (مثلاً ۴۰۳ یا ۵۰۰) یا پاسخی که خوانده نشد."),
            ("unreachable", "err", "تایم‌اوت یا قطع اتصال", "از میرور جوابی نیامد: تایم‌اوت یا قطع اتصال.")])
    def who(verdict, limit=6):
        """`host (ecosystem): item, item` lines for every mirror with that verdict, worst first."""
        found = {}
        for g in groups:
            for n, m in g["mirrors"].items():
                items = [i for i, r in m["rows"].items() if r["verdict"] == verdict]
                if items:
                    found.setdefault(n, []).append((g, m, items))
        lines = []
        for n, entries in sorted(found.items(), key=lambda kv: -sum(len(e[2]) for e in kv[1])):
            host = html.escape(entries[0][1]["url"].split("://", 1)[-1].split("/")[0])
            ours = bool(BRAND["ours"]) and n == BRAND["ours"]
            tag = f' <em>{html.escape(BRAND["ours_label"])}</em>' if ours else ""
            parts = []
            for g, m, items in entries:
                shown = "  ·  ".join(html.escape(i) for i in items[:3])
                more = f' <span class="more">+{fa(len(items) - 3)}</span>' if len(items) > 3 else ""
                parts.append(f'<span class="eco"><a href="#{g["id"]}">{html.escape(g["title"])}</a>'
                             f'<bdi dir="ltr">{shown}</bdi>{more}</span>')
            lines.append(f'<li><b><bdi dir="ltr">{host}</bdi>{tag}</b>{"".join(parts)}</li>')
        extra = f"<li>و {fa(len(lines) - limit)} میرور دیگر</li>" if len(lines) > limit else ""
        return "<ul>" + "".join(lines[:limit]) + extra + "</ul>" if lines else ""

    days = history_days(history)
    if counts["mismatch"]:  # the only banner: a mirror served a value the official source never had
        verdict = (f'<div class="verdict alert"><details class="vd" open><summary>'
                   f'<b>{fa(counts["mismatch"])} مورد ناهمخوان با منبع رسمی</b><span class="vhint">جزئیات</span>'
                   f'</summary><div class="vsub">{who("mismatch")}</div></details></div>')
    else:
        verdict = ""
    nav = "".join(f'<a href="#{g["id"]}">{html.escape(g["title"])}</a>' for g in groups)
    nav += ('<span class="sort" role="group" aria-label="ترتیب">'
            '<button type="button" data-sort="score" aria-pressed="true">بیشترین امتیاز</button>'
            '<button type="button" data-sort="name" aria-pressed="false">الفبا</button></span>')
    sections = "".join(render_group(g, fa, history, days) for g in groups)
    past = mismatch_log(history, days, fa)

    src = BRAND["source_url"]
    src_label = html.escape(src.split("://", 1)[-1].rstrip("/"))
    src_link = f'<a class="src" href="{html.escape(src)}" rel="noopener">{src_label} ↗</a>' if src else ""
    src_note = (f'<p>کد این بازرس متن‌باز است و هر کسی می‌تواند بخواند، اجرا کند و میرور خودش را اضافه کند: '
                f'<a href="{html.escape(src)}" dir="ltr">{src_label}</a>.</p>') if src else ""
    credits = BRAND["credits_html"]
    script = SCRIPT.replace("__MIN__", str(int(BRAND["recheck_minutes"]))) if BRAND["recheck_minutes"] > 0 else ""
    social = ""
    if BRAND["site_url"]:
        base = BRAND["site_url"].rstrip("/")
        img = html.escape(base + BRAND["og_image"])
        t, d = html.escape(BRAND["title"]), html.escape(BRAND["description"])
        social = (f'<link rel="canonical" href="{html.escape(base)}/"><meta name="theme-color" content="#0f1916">'
                  f'<meta property="og:type" content="website"><meta property="og:locale" content="fa_IR">'
                  f'<meta property="og:url" content="{html.escape(base)}/"><meta property="og:title" content="{t}">'
                  f'<meta property="og:description" content="{d}"><meta property="og:image" content="{img}">'
                  f'<meta property="og:image:width" content="1200"><meta property="og:image:height" content="630">'
                  f'<meta name="twitter:card" content="summary_large_image"><meta name="twitter:title" content="{t}">'
                  f'<meta name="twitter:description" content="{d}"><meta name="twitter:image" content="{img}">')
    return f"""<!doctype html>
<html lang="fa" dir="rtl"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{html.escape(BRAND["title"])}</title>
<meta name="description" content="{html.escape(BRAND["description"])}">
{social}<link rel="icon" href="/favicon.svg" type="image/svg+xml"><style>{CSS}</style></head>
<body><div class="wrap">
<header><img src="/favicon.svg" alt="" width="44" height="44">
<div class="brand">{html.escape(BRAND["name"])}<small>{html.escape(BRAND["tagline"])}</small></div>{src_link}</header>
<h1>پایش <span>میرورها</span></h1>
<p class="lead">بسته‌ها و ایمیج‌های پرکاربرد را از هر میرور می‌پرسیم و با پاسخ منبع رسمی مقایسه می‌کنیم،
از سروری مستقل از میرورها: {fa(len(seen))} میزبان در {fa(len(groups))} اکوسیستم. آخرین بررسی: {when}. هر ساعت تکرار می‌شود.</p>
{verdict}<div class="nums">{tiles}</div>
{providers(groups, history, days, fa)}
<div class="search"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" aria-hidden="true"><circle cx="11" cy="11" r="7"/><path d="M20 20l-3.5-3.5"/></svg>
<input id="q" type="search" placeholder="جست‌وجو: liara، npm، lodash…" autocomplete="off" aria-label="جست‌وجو" dir="auto"><kbd>/</kbd></div>
<div id="sres" role="status" aria-live="polite"></div>
<nav class="tabs">{nav}</nav>
{sections}
{f'<section class="note past">{past}</section>' if past else ""}
<section class="note"><h2>این صفحه چه چیزی را نشان می‌دهد؟</h2>
<p>برای هر اکوسیستم، همان داده‌ای را از میرور و از منبع رسمی می‌گیریم که ابزار نصب به آن اعتماد می‌کند
(digest در Docker، هش در npm و PyPI، cksum در Cargo، sha1 در Maven، فایل checksum نصب‌کننده‌ها) و مقایسه می‌کنیم.
بسته‌ها روی نسخه‌ی ثابت سنجیده می‌شوند، پس هر تفاوتی باید توضیح داشته باشد.</p>
<h2>چه چیزی را نشان نمی‌دهد؟</h2>
<ul><li>سبز یعنی بازرس ما جواب درست گرفته؛ نه اینکه همه‌ی کاربران و در همه‌ی زمان‌ها همین را می‌گیرند.</li>
<li>حمله‌ای که فقط برای بعضی نشانی‌ها یا فقط هنگام قطعی اینترنت اجرا شود، با این بررسی دیده نمی‌شود.</li>
<li>فایل بسته دانلود نمی‌شود (جز ZIP ماژول‌های Go که برای محاسبه‌ی هش دانلود می‌شود)؛ مقدار هش و checksumی سنجیده می‌شود که ابزار نصب از میرور می‌گیرد.</li>
<li>نام ستون‌ها فقط نشانی میزبان است؛ اینکه کدام شرکت اداره‌اش می‌کند را خودش باید تأیید کند.
میرورهایی که بدون ثبت‌نام یا اعتبار پاسخ نمی‌دهند بررسی نشده‌اند.</li></ul>
<h2>کد منبع</h2>
{src_note}
<h2>برای پروژه‌های حساس</h2>
<p>هش را از منبع رسمی ثابت کنید: lockfile با هش (<bdi dir="ltr">package-lock.json</bdi>، <bdi dir="ltr">uv.lock</bdi>،
<bdi dir="ltr">pip --require-hashes</bdi>)، <bdi dir="ltr">distributionSha256Sum</bdi> در Gradle Wrapper، و در Docker
<bdi dir="ltr">alpine:3.20@sha256:…</bdi>. آن‌وقت هیچ میرور نمی‌تواند محتوای دیگری بدهد. خروجی کامل:
<a href="/report.json" dir="ltr">report.json</a>.</p></section>
<section class="note credits"><h2>ابزارها و فونت‌های متن‌باز</h2>
<p>این صفحه با ابزارهای آزاد ساخته شده و اجرا می‌شود؛ حقوق و مجوز هر کدام برای صاحبان آن‌هاست:</p>
<ul>
<li><a href="https://www.python.org" rel="noopener" dir="ltr">Python</a> (مجوز PSF): بازرس و سرور این صفحه فقط با کتابخانه‌ی استاندارد پایتون نوشته شده‌اند، بدون وابستگی بیرونی.</li>
<li><a href="https://github.com/rastikerdar/vazirmatn" rel="noopener" dir="ltr">Vazirmatn</a>، اثر زنده‌یاد صابر راستی‌کردار (مجوز SIL Open Font License 1.1): فونت این صفحه.</li>
{credits}</ul></section>
<footer>{BRAND["footer_html"]}</footer>
</div>{SEARCH}{TIP}{script}</body></html>"""


def write_atomic(path, text):
    tmp = Path(path + ".tmp")
    tmp.write_text(text)
    tmp.replace(path)


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("images", help="file with one name:tag per line")
    ap.add_argument("mirrors", help="file with `name https://host [registry] [ip]` per line (Docker registries)")
    ap.add_argument("--packages", help="file with `kind item` per line (npm, pypi, cargo, maven, rubygems, nodejs, golang, gomod, gradle, helm, k8s, hashicorp, debian, ubuntu, almalinux, rocky, epel, fedora, centos, alpine, archlinux, kali, opensuse)")
    ap.add_argument("--targets", help="file with `kind name base-url` per line: the mirrors to check for those kinds")
    ap.add_argument("--brand", help="JSON file overriding the page branding (keys of DEFAULT_BRAND)")
    ap.add_argument("--max-seconds", type=int, default=1200,
                    help="stop starting new checks after this long and report the rest as skipped (default %(default)s)")
    ap.add_argument("--workers", type=int, default=6,
                    help="hosts checked at the same time; each host still gets one request at a time (default %(default)s)")
    ap.add_argument("--state", help="previous report.json: mirrors not checked in this run keep their last result "
                                    "(and its time) until their turn comes")
    ap.add_argument("--slots", type=int, default=1,
                    help="spread the hosts over this many runs: a run checks 1/N of them (default 1 = all every run)")
    ap.add_argument("--slot-minutes", type=int, default=5,
                    help="how often the job runs; with --slots it picks this run's turn from the clock (default %(default)s)")
    ap.add_argument("--slot", type=int, help="force this turn (0..slots-1) instead of reading the clock")
    ap.add_argument("--queue", help="re-check requests (written by serve.py): the mirrors in it are checked in this "
                                    "run whatever their turn, then removed from it")
    ap.add_argument("--history", help="history file (JSON) to add this run's results to: daily counts per mirror "
                                      "and every change of an item's verdict")
    ap.add_argument("--json", help="write the report here")
    ap.add_argument("--html", help="write the static page here")
    args = ap.parse_args()
    global DEADLINE
    DEADLINE = time.monotonic() + args.max_seconds
    if args.brand:
        BRAND.update(json.loads(Path(args.brand).read_text()))
    refs = [line[0] for line in read_list(args.images)]
    docker_mirrors = parse_docker_mirrors(read_list(args.mirrors))
    items, targets = {}, {}
    if args.packages and args.targets:
        for kind, item in read_list(args.packages):
            items.setdefault(kind, []).append(item)
        for kind, name, base in read_list(args.targets):
            targets.setdefault(kind, []).append((name, base))
    kinds = [k for k in OFFICIAL if items.get(k) and targets.get(k)]

    prior = load_state(args.state) if args.state else {}
    slots = max(1, args.slots)
    slot = args.slot if args.slot is not None else int(time.time() // (args.slot_minutes * 60)) % slots
    on_registry = {}
    for ref in refs:
        on_registry.setdefault(split(ref)[0], []).append(ref)
    docker_mirrors = mirrors_with_images(docker_mirrors, on_registry)
    # One group per official registry, Docker Hub first; a registry without a mirror makes none.
    registries = sorted({m[2] for m in docker_mirrors}, key=lambda u: (u != HUB_HOST, u))
    by_registry = [(u, on_registry[u], [m for m in docker_mirrors if m[2] == u]) for u in registries]
    specs = [(docker_group_id(u), images, [(m[0], m[1]) for m in ms]) for u, images, ms in by_registry]
    specs += [(k, items[k], targets[k]) for k in kinds]
    active = pick_active(specs, prior, slots, slot)
    asked = set()
    if args.queue:  # visitors' re-check requests
        asked = asked_pairs(queue_read(args.queue), specs)
        active |= asked
    names = lambda gid: {n for g, n in active if g == gid}
    plans = [docker_group(images, ms, names(docker_group_id(u)), prior.get(docker_group_id(u)))
             for u, images, ms in by_registry]
    plans += [package_group(k, items[k], targets[k], names(k), prior.get(k)) for k in kinds]
    # Phase 1: ask every official source that is needed now (different sources at the same time).
    run_jobs([job for _, officials, _ in plans for job in officials], args.workers)
    # Phase 2: ask this run's mirrors; one request at a time per host, several hosts at once.
    mirror_jobs = [job for _, _, after in plans for job in after()]
    run_jobs(mirror_jobs, args.workers)
    report = {"generated": now_iso(), "groups": [g for g, _, _ in plans if g["items"]]}
    settle(report, active)
    for g in report["groups"]:  # say in the report which mirrors were asked from inside Iran
        for m in g["mirrors"].values():
            if via_tunnel(m["url"]):
                m["via"] = "tunnel"
    if args.queue:
        queue_remove(args.queue, [f"{gid}/{name}" for gid, name in asked])
        waiting = queue_read(args.queue)
        for g in report["groups"]:
            for name, m in g["mirrors"].items():
                m["queued"] = f"{g['id']}/{name}" in waiting
    history = record_history(args.history, report, active) if args.history else None
    if args.json:
        write_atomic(args.json, json.dumps(report, indent=2) + "\n")
    if args.html:
        write_atomic(args.html, page(report, history))
    bad = 0
    print(f"turn {slot + 1}/{slots}: {len(active)} mirror entries checked, "
          f"{sum(len(g['mirrors']) for g in report['groups']) - len(active)} kept from the previous run")
    for g in report["groups"]:
        for name, mirror in g["mirrors"].items():
            if (g["id"], name) not in active:
                continue
            counts = {}
            for row in mirror["rows"].values():
                counts[row["verdict"]] = counts.get(row["verdict"], 0) + 1
            bad += counts.get("mismatch", 0)
            print(f"{g['id']:7} {name:28} " + "  ".join(f"{k}={v}" for k, v in sorted(counts.items())))
            for ref, row in mirror["rows"].items():
                if row["verdict"] in ("mismatch",) + FAILED:
                    print(f"   {row['verdict'].upper()} {ref} {row['value']} {row['detail']}")
    sys.stdout.flush()
    os._exit(2 if bad else 0)  # abandoned threads must not keep the process alive


if __name__ == "__main__":
    main()
