## What and why

## How it was verified

- [ ] `python3 tests/test_pkg_audit.py && python3 tests/test_serve.py && python3 tests/test_tunnel.py`
- [ ] New behaviour has an offline test
- [ ] If a verdict, the items' handling or the score changes: `METHODOLOGY.md` updated and `METHODOLOGY_VERSION` bumped
- [ ] If `summary.json` changes: `schema/summary-v1.schema.json` and README updated (a removed or redefined field needs a new schema version)
