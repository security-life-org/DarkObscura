# Security Policy

## Scope

This policy covers vulnerabilities **in DarkObscura itself** (the scanner, its GUI,
API, or dependencies) — for example an SSRF/scope-guard bypass, an auth bypass on the
`/api/*` endpoints, RCE via a crafted response, or a path-traversal in report output.

It does **not** cover vulnerabilities you find *using* DarkObscura in third-party
systems — those belong to that system's own disclosure program.

## Reporting a vulnerability

Please report privately — **do not open a public issue** for security bugs.

1. Use GitHub's **"Report a vulnerability"** (Security → Advisories) on
   `https://github.com/security-life-org/DarkObscura`, or
2. Contact the maintainers listed on the organization profile.

Include:
- A description and impact assessment.
- Steps to reproduce (a minimal PoC is ideal).
- Affected version / commit.

## What to expect

- Acknowledgement of your report as soon as the maintainers are able.
- A fix or mitigation plan, and coordinated disclosure once a patch is available.
- Credit in the changelog if you'd like it.

## Safe-harbor

Good-faith security research on DarkObscura's own code is welcome. Please:
- Only test against your own local instance.
- Do not access data that isn't yours, and do not run denial-of-service attacks.
- Give the maintainers reasonable time to remediate before public disclosure.
