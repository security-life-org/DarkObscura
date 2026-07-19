# Features

A complete, honest catalogue of what DarkObscura does — and where it does **not**
compete with mature interactive proxies.

## Verification engine (the core promise)

Every `confirmed` finding passes a deterministic oracle:

| Class | How it is confirmed |
|---|---|
| Time-based SQLi | Reproducible statistical latency outlier (z-score, 2 trials) |
| Error-based SQLi | Database error string introduced by the payload (absent from baseline) |
| Reflected XSS | Unique dangerous marker reflected **unescaped** |
| SSTI | Injected arithmetic expression **evaluated** by the engine |
| LFI / path traversal | Real `/etc/passwd` (or `win.ini`) signature in the response |
| Open redirect | 3xx `Location` to an attacker-controlled host |
| SSRF / RCE / XXE | Out-of-band DNS/HTTP callback to the canary server |
| Structural differential | Reproducible structural/status change beyond the endpoint's noise floor |

The baseline models each endpoint's **noise floor**, so dynamic pages (challenge/CSRF
nonces, timestamps) never yield differential false positives.

## Discovery

- **Crawler** — same-origin spider that reads HTML links/forms **and** mines endpoints
  from JavaScript (fetch/axios, template literals, absolute URLs), seeds from
  `robots.txt` + `sitemap.xml`, and surfaces POST forms.
- **Dynamic harvester** — extracts endpoints/params/GraphQL/WebSockets/source-maps from
  a page and its scripts.
- **OpenAPI/Swagger import** — turns a spec into scannable endpoints.
- **HAR import** — turns a recorded browser session into endpoints + captured auth.

## Recon & intelligence

- **Fingerprinting** — CMS, framework, language, server, CDN, WAF, analytics.
  Confidence-graded: only deterministic, unforgeable signals are `confirmed`.
- **CVE correlation** — maps confirmed versions to known CVEs (version-range match).
- **Secret scanning** — typed detectors (cloud keys, tokens, private keys, DB URLs)
  plus a Shannon-entropy gate; matches are redacted.
- **Subdomain takeover** — confirmed only when a dangling CNAME **and** the provider's
  unclaimed-page signature both match.

## Access control & business logic

- **IDOR/BOLA engine** — replays requests across identities (owner / attacker /
  anonymous); flags a violation only when a lower-privileged identity gets the owner's
  resource, and excludes genuinely public resources.
- **Business-logic testing** — runs a recorded multi-step flow and tampers one step
  (negative/zero/huge/swap); a finding fires only when the server *accepts* a state it
  should reject, or a numeric invariant is violated.

## APIs

- **GraphQL** — introspection exposure, alias/batch abuse, field-suggestion leakage,
  and dangerous-mutation exposure.
- **gRPC** — enumerates services/methods via server reflection (no `.proto` needed) and
  fuzzes unary methods.
- **JWT** — detects `alg=none` and cracks weak HS256 secrets (cryptographic proof);
  can forge tokens for authorized impact demonstration.

## Client-side

- **CORS** — origin reflection, `null` origin, wildcard-with-credentials.
- **Web cache poisoning** — deterministic proof: poison a cache key you own, then prove
  a header-less request is served the poisoned value from cache.
- **CSP** — missing/`unsafe-inline`/`unsafe-eval`/wildcard analysis.
- **DOM-XSS** — static source→sink analysis (`possible` confidence); optional headless
  rendering with `-tags chromedp` for runtime DOM + endpoints.

## Offensive ops

- **Blind/stored XSS** — canary-token beacons with persistent out-of-band correlation.
- **Attack-chain orchestration** — deterministic escalation graph (e.g. SSRF → cloud
  metadata → credential theft), no LLM guesswork.
- **WAF/block detection** — classifies clean/blocked/rate-limited/challenge, names the
  vendor, and raises a live "you are being blocked" signal so empty results aren't
  mistaken for "safe".
- **WAF-evasion** — 17 payload-mutation techniques.
- **Nuclei templates** — 300+ bundled official ProjectDiscovery checks; `--dir` loads a
  full cloned repo (filtered to the single-request word/regex/status subset to stay
  false-positive-free).

## Reporting & workflow

- **SARIF 2.1.0** — for CI/CD security dashboards.
- **HTML** — printable client/bounty report.
- **Findings DB** — cross-scan dedup, suppression allowlist, "new since last scan".
- **CI gate** — `ci` exits non-zero on new findings.

## User interface

- Embedded WebGL attack graph (pan / zoom / fit / right-click attack menu).
- Live activity console with busy indicators for every operation.
- Recon menu, command palette (Ctrl+K), report export, About.

## Safety

- SSRF/scope guard enforced at dial time (rebind-proof) and handler entry.
- Bearer-token API auth; explicit `--i-have-authorization` gate.
- Distroless, read-only, non-root Docker image bound to loopback.

---

## Honest comparison: where DarkObscura is **not** Burp/Caido/ZAP

DarkObscura is an **automated precision scanner**, not an interactive proxy suite. It
does **not** (yet) provide:

- A full intercepting-proxy UI with searchable HTTP history and in-flight edit/drop.
- A Burp-Repeater-grade iterative request editor, or an Intruder-style fuzzing UI.
- A plugin/extension marketplace.
- The breadth, protocol coverage, and years of polish of a commercial scanner.

**Where it wins:** deterministic zero-false-positive findings, and vulnerability
classes those tools don't do out of the box (deterministic IDOR, business-logic
testing, attack-chains, persistent blind-XSS, gRPC fuzzing, version→CVE). Use it
alongside your proxy of choice, not instead of it.
