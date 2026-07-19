# Changelog

All notable changes to DarkObscura are documented here. This project adheres to
[Semantic Versioning](https://semver.org).

## [0.1.0] — Community Preview

First public release.

### Verification engine (zero false positives)
- Four-stage pipeline: baseline → structural differential → time-series (z-score) →
  out-of-band canary (DNS/HTTP).
- Detection classes: time-based & error-based SQLi, reflected XSS, SSTI, LFI/path
  traversal, open redirect, SSRF/RCE/XXE (OOB), structural differential.
- Endpoint noise-floor modelling so dynamic pages (challenge/CSRF nonces) never
  produce differential false positives.

### Discovery
- Same-origin crawler: HTML links/forms **and** JS-mined endpoints (fetch/axios,
  template literals, absolute URLs), `robots.txt` + `sitemap.xml` seeding, POST forms.
- Dynamic surface harvester and OpenAPI/Swagger import.

### Recon & intelligence
- Confidence-graded fingerprinting (CMS/framework/language/server/CDN/WAF/analytics);
  only deterministic signals are `confirmed`.
- Version → CVE correlation for confirmed versions.
- Secret & Shannon-entropy scanning with redaction.
- Subdomain-takeover detection (dangling CNAME + provider signature).

### APIs & advanced classes
- IDOR/BOLA multi-identity engine (with public-resource exclusion).
- Business-logic state-machine testing (tamper + invariants).
- GraphQL: introspection, alias/batch abuse, field-suggestion leak, dangerous-mutation
  exposure.
- gRPC reflection enumeration + unary fuzzing.
- JWT `alg=none` detection and HS256 weak-secret cracking.
- Persistent blind/stored-XSS via out-of-band beacons.
- Deterministic attack-chain orchestration.

### Client-side
- CORS (reflection/null-origin/wildcard), web cache poisoning (deterministic
  re-fetch proof), CSP analysis, DOM-XSS source→sink analysis.
- Optional headless DOM rendering behind `-tags chromedp`.

### Ops & UX
- WAF/block detection with a live "you are being blocked" signal during scans.
- WAF-evasion payload mutation (17 techniques).
- 300+ bundled official ProjectDiscovery Nuclei templates + `--dir` to load the full
  repo (single-request/word/regex/status subset, filtered to stay FP-free).
- SARIF + HTML reporting; CI gate (`ci`) that fails on new findings.
- Embedded WebGL dashboard: pan/zoom attack graph, live activity console with busy
  indicators, Recon menu, About.
- Safety: SSRF/scope guard, bearer-token API auth, `--i-have-authorization` gate,
  distroless Docker image.
