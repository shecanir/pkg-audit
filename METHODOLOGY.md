# Methodology

This is what `pkg-audit` measures, how a verdict and the provider score are reached, and what the
numbers do not say. The version below is published in `report.json` (`methodology`) and
`summary.json` (`methodology.version`) and on the page. Results made under different versions should
not be compared as if they were alike.

Current version: **2026.11.1**

## 1. What is measured

For every listed mirror and every pinned item of its ecosystem, the auditor asks the mirror and the
official source for **the value a client trusts** and compares the two:

| Ecosystem | Value | Official source |
| --- | --- | --- |
| Docker and OCI registries | digest of a tag, and that the manifest served by that digest hashes to it | Docker Hub or the registry the image name starts with |
| npm | `dist.integrity` of a pinned version | registry.npmjs.org |
| PyPI | sha256 of every file of a pinned version | pypi.org |
| Cargo | `cksum` in the sparse index | index.crates.io |
| Maven | `.jar.sha1` | Maven Central |
| RubyGems | `checksum` in the compact index | index.rubygems.org |
| Go modules | `h1:` hash computed from the module zip | proxy.golang.org |
| Release downloads, OS repositories | sha256 of a small immutable file (checksum file, GPG key, pinned package) | the project's own download host |

Items are pinned (a version, a fixed file), so the official value does not change and any difference
needs an explanation. Package files are not downloaded (except Go module zips, which are hashed);
equal hashes mean equal content because the client verifies the file against that hash.

### Verdicts

| Verdict | Meaning | Counts as an answer |
| --- | --- | --- |
| `ok` | same value as the official source | yes |
| `stale` | Docker only: a digest the official registry still serves for that repository, but no longer the tag's | yes |
| `mismatch` | a value the official source does not have: investigate | yes |
| `missing` | the mirror answered 404 or 410 | yes |
| `error` | any other HTTP status or an unusable answer | yes |
| `unreachable` | no answer: timeout, connection refused or reset | **no** |
| `pending` | not checked yet | no |

An item whose official value could not be fetched in a run is not compared in that run (no verdict is
made up for it). A run cut short by its time budget leaves the unfinished items without a row, so they
read `pending` and are checked next time; nothing is reported that was not measured.

### Time per check

Every check that gave a value records `ms`: the wall time of all its requests (retries included; for
Docker the token and manifest requests too). `summary.json` publishes per mirror the median and 90th
percentile (nearest-rank, never interpolated) and the number of checks, `n`.

- It is **not** a download speed and **not** part of the score.
- It is comparable only between mirrors of one group asked the same way (`via`). Through the tunnel
  every mirror pays the same extra path, but the tunnel's far end is a server of the operator inside
  Iran, so mirrors on or near that network can answer faster for that reason alone.
- Up to `--workers` hosts are checked at the same time; one host never gets more than one request at
  a time. Items may be cached on one mirror and not on another; that changes time, never the verdict.

## 2. Fair comparison

- Every mirror of a group is asked **the same items, in the same order, the same way**, on the same
  schedule (hosts are spread evenly over the hour; a mirror's turn depends on its host name only).
- Official sources are always asked directly; mirrors through the tunnel unless their line says
  `via=direct`. `via` is published per mirror; `vantage` names where each way is measured from,
  at country level.
- The operator's own mirrors get no mark, no weight and no place of their own: the same code path
  (a test checks that renaming the operator's mirror changes no score).
- Re-check requests by visitors are bounded by a cooldown per mirror, so nobody can make a mirror be
  checked more often than others.

## 3. Score and ranking

Providers are grouped by the registrable domain of a mirror's host (that says nothing about who runs
it). A **repository** is one mirror of one group.

1. A repository is **healthy** when none of its items is `mismatch` and at least **90%** of its items
   are `ok` (`pending` and `unreachable` items are not `ok`).
2. Its **history weight** is its share of `ok` among answered checks over the last **30** days with
   results. Until **14** days of history exist the weight is 1 for everyone, so nobody gains or loses
   from the time before it.
3. A provider's **score** is the sum of the history weights of its healthy repositories.
4. Ties: fewer mismatches, then the higher share of `ok` answers, then the name.

A repository in a group where it is the **only provider checked** scores like any other: offering a
mirror nobody else offers is worth something to a user. Which ecosystems and mirrors are listed is
the operator's choice, so this is stated openly: `summary.json` gives each group's `providers` count
and each provider's `healthy_alone`, and the page marks such groups. To compare providers only where
they compete, sum `score_points` over groups with `providers >= 2`.

Everything is reproducible: `summary.json` carries per repository `score_points` (its contribution)
and per provider `score` and `rank`, and both are computed by the same functions as the page from
`report.json` and `history.json`.

### Missing data

- No answer (`unreachable`) is neither good nor bad for the history weight: it is left out of the
  share (it is often the network between the auditor and the mirror).
- A mirror with nothing measured has `healthy: null` in `summary.json`; a history share without
  enough days is `null`, not 100%.
- A result older than 3 hours is shown as old on the page; `checked_at` is published per mirror.

## 4. What a green result does not prove

- That every client, from every network, at every time, gets the same answer: only that the auditor
  did, from its vantage point.
- That the official source is uncompromised.
- Anything about items that are not listed, or about the mirror's speed, capacity or uptime.
- A score is not a security certification.

## 5. Safety of the measurement

- Only mirrors and items in the operator's lists are ever asked; visitors can only queue a re-check of
  a listed (group, mirror) pair.
- Redirects and registry token realms are followed only to `http`/`https`, at most 5 hops, and never
  from a public address to a private, loopback, link-local (cloud metadata) or reserved one. Through
  the tunnel only literal addresses and localhost-like names can be checked, as the name is resolved at
  the tunnel's end. A name that changes its answer between the check and the connection (DNS
  rebinding) is a remaining risk, limited because only hashes and short error texts are published.
- Every answer is read up to 128 MiB at most; a Go module zip, and its unpacked files, up to 200 MiB.
- Timeouts on every request, at most 3 tries with back-off, at most 3 consecutive no-answers before
  the rest of a mirror is skipped for the run, one request at a time per host, and a time budget per run.

## Changes

- **2026.11.1** (2026-11-04): first versioned methodology. Same verdicts and score as before;
  adds guarded redirects and token realms, a size limit on every answer, and the time per check
  (published, not scored).
