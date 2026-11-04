# Security policy

## Reporting a vulnerability

Please do not open a public issue for a vulnerability in the auditor or the page server. Use
GitHub's private reporting instead: **Security → Report a vulnerability** on
https://github.com/shecanir/pkg-audit. If that is not available to you, open an issue that only asks
for a private contact, without details. We answer within a few working days and credit reporters who
want it.

In scope: anything that lets a mirror or a visitor make the auditor request addresses it should not
(SSRF), read or exhaust resources of the check server, change results, or run code; XSS on the page;
bypassing the re-check limits.

## A mirror serving altered content

That is what this tool exists to find, and it is shown publicly as `mismatch`. If you believe a
mirror is compromised, also tell its operator. Report a wrong `mismatch` (a bug of ours) as a normal
issue with the group, mirror, item and time.

## Supported versions

Only the latest commit of `main` is supported; the deployment at audit.shecan.ir follows it.
