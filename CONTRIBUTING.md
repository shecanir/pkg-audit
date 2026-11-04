# Contributing

Thanks for helping make mirror audits more trustworthy. Issues and pull requests are welcome in
English or Persian.

## Run it locally

Python 3.8+ and nothing else (standard library only).

```bash
git clone https://github.com/shecanir/pkg-audit.git && cd pkg-audit
python3 tests/test_pkg_audit.py && python3 tests/test_serve.py && python3 tests/test_tunnel.py   # offline, no network
python3 pkg_audit.py examples/images.txt examples/docker-mirrors.txt \
  --packages examples/packages.txt --targets examples/targets.txt --brand examples/brand.json \
  --json site/report.json --summary site/summary.json --html site/index.html --history site/history.json
cp assets/* site/ && python3 serve.py --site site --queue queue.json --port 8080   # http://localhost:8080
```

A real run asks the listed mirrors and official sources over the internet: keep your lists small
and do not run it in a loop against other people's servers.

## How the code is laid out

- `pkg_audit.py`: the auditor. `docker_group` / `package_group` plan the checks of one group;
  `fetch_value` and `Registry` ask one source; `check_rows` runs the items of one mirror;
  `run_jobs` runs hosts in parallel, one request at a time per host; `add_history` keeps the daily
  counts; `provider_stats` computes the score; `summary` writes the machine-readable view; `page`
  renders the static page.
- `serve.py`: serves the page and takes re-check requests into a queue file.
- `schema/summary-v1.schema.json`: the contract of `summary.json`.
- `METHODOLOGY.md`: what is measured and how it is scored. **Any change to a verdict, the items'
  handling or the score must update it and bump `METHODOLOGY_VERSION`.**

## Proposing a change

- A wrong result: open an issue with the group, mirror, item and time (the page's tooltip shows the
  value and detail).
- A new mirror or ecosystem: open an issue or a pull request with the list lines (`examples/`
  shows the formats). Mirrors that need an account or credit are not listed.
- A fairer score: explain what it rewards and what it can be gamed by; include its effect on a
  real `report.json`.

Pull requests: keep them small, add an offline test for the behaviour, run the three test files,
and describe how you verified it. CI runs the same tests on every push.

## Code of conduct

Be respectful and assume good faith. Mirror operators named on the page are people running a
public service; report problems about them factually.
