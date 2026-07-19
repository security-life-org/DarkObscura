# Usage Guide

> **Authorized use only.** Every network-touching command requires
> `--i-have-authorization` (CLI) or the *authorized* checkbox / `authorized=1`
> parameter (GUI).

## Table of contents
- [Global flags](#global-flags)
- [Desktop GUI](#desktop-gui)
- [Core scanning](#core-scanning)
- [Recon & detection](#recon--detection)
- [APIs](#apis)
- [Client-side](#client-side)
- [Access control & logic](#access-control--logic)
- [Reporting & CI](#reporting--ci)
- [Utilities](#utilities)
- [Safety & scope](#safety--scope)

---

## Global flags

```
dobscura [--gui] [--wizard] [--version]
         [--gui-addr 127.0.0.1:8422] [--no-open]
         [--scope hosts,.domains,CIDRs] [--allow-private]
         [--no-auth] [--token <token>]
```

| Flag | Purpose |
|---|---|
| `--gui` | Launch the embedded desktop dashboard |
| `--wizard` | Guided interactive scan in the terminal |
| `--scope` | Restrict the engagement to in-scope hosts/domains/CIDRs |
| `--allow-private` | Permit private/loopback/metadata targets (off by default — SSRF guard) |
| `--no-auth` | Disable the API bearer token (only for local use) |
| `--token` | Set the API token (auto-generated otherwise) |

---

## Desktop GUI

```bash
dobscura --gui                              # public targets, auth on
dobscura --gui --allow-private --no-auth    # local testing (127.0.0.1)
```

In the dashboard:
- **Target bar** — enter a URL, tick *authorized*.
- **Analyze** — verification-gated scan of one URL (live streamed).
- **🕸 Deep Scan** — crawl the origin and scan every discovered endpoint.
- **🧰 Recon** menu — fingerprint+CVE, Nuclei templates, secrets, CORS/cache/CSP,
  DOM-XSS, WAF/block check, subdomain takeover, gRPC.
- **☰** menu — command palette, crawl, export report/findings, About.
- **Attack graph** — scroll to zoom, drag to pan, double-click to fit; right-click a
  node for the attack menu.

---

## Core scanning

### `scan` — single URL, full verification
```bash
dobscura scan "https://target/search?q=1" --i-have-authorization \
  [--rps 10] [--timeout 2m] \
  [--canary-zone canary.example.com --canary-dns :53 --canary-http :8081]
```
Runs the four-stage pipeline against every query parameter and trusted header. With a
`--canary-zone`, SSRF/RCE/XXE are confirmed out-of-band. WAF/blocking is signalled with
`[!]` lines so an empty result is never mistaken for "safe".

### `classify` — risk of a parameter name
```bash
dobscura classify user_id
```

---

## Recon & detection

```bash
# CMS / framework / server / CDN fingerprint (confidence-graded)
dobscura fingerprint https://target --i-have-authorization [--confirmed]

# version -> known CVE correlation (only for confirmed versions)
dobscura cve https://target --i-have-authorization

# bundled 300+ official Nuclei templates (+ full repo via --dir)
dobscura templates https://target --i-have-authorization [--dir ./nuclei-templates]

# leaked-secret scan (page + linked scripts, entropy + typed detectors)
dobscura secrets https://target --i-have-authorization

# JS-mined attack surface (endpoints, params, GraphQL, WebSockets, source maps)
dobscura surface https://target --i-have-authorization

# WAF present? does it block attacks? (so empty results aren't "safe")
dobscura waf https://target --i-have-authorization
```

---

## APIs

```bash
# GraphQL: introspection, alias/batch abuse, dangerous mutations
dobscura graphql https://target/graphql --i-have-authorization

# gRPC: enumerate + fuzz via server reflection (no .proto needed)
dobscura grpc host:443 --i-have-authorization [--tls] [--enumerate-only]

# JWT: alg=none + weak HS256 secret (cryptographic proof)
dobscura jwt <token> [--forge]
```

---

## Client-side

```bash
# CORS / cache-poisoning / CSP / security headers
dobscura clientside https://target --i-have-authorization

# static DOM-XSS source->sink analysis (headless with -tags chromedp)
dobscura dom https://target --i-have-authorization

# reconstruct original source from a leaked .map and scan it
dobscura sourcemap https://target/app.js.map --i-have-authorization

# fuzz a WebSocket endpoint (FUZZ marks the injection slot)
dobscura wsfuzz wss://target/ws --template '{"msg":"FUZZ"}' --i-have-authorization
```

---

## Access control & logic

```bash
# IDOR / BOLA across owner vs attacker identities
dobscura idor "https://target/account?id=5" --i-have-authorization \
  --owner-cookie "session=..." --attacker-cookie "session=..."

# business-logic flow testing (tamper + invariants), spec in JSON
dobscura logic flow.json --i-have-authorization

# import a recorded browser session (HAR) -> endpoints + captured auth
dobscura harimport session.har

# subdomain takeover (confirmed only: dangling CNAME + provider signature)
dobscura takeover sub.target.com --i-have-authorization
```

A minimal `flow.json`:
```json
{
  "vars": {"base": "https://target"},
  "steps": [
    {"name": "login", "method": "POST", "url": "{{base}}/login",
     "body": "user=a&pass=b", "location": "form",
     "extract": {"token": "\"token\":\"([^\"]+)\""}},
    {"name": "checkout", "method": "POST", "url": "{{base}}/checkout",
     "body": "qty=2&token={{token}}", "location": "form", "expectStatus": 200}
  ],
  "tampers": [
    {"name": "negative-qty", "step": "checkout", "field": "qty",
     "mutation": "negative", "expectReject": true}
  ]
}
```

---

## Reporting & CI

```bash
# scan and emit a report
dobscura report "https://target/x?id=1" --format html --out report.html --i-have-authorization
dobscura report "https://target/x?id=1" --format sarif --i-have-authorization > out.sarif

# CI gate: scan, dedup vs history, exit non-zero on NEW findings
dobscura ci "https://target/x?id=1" --db findings.db --i-have-authorization

# build deterministic attack chains from a findings JSON file
dobscura chain findings.json [--db findings.db]
```

---

## Utilities

```bash
# generate context-aware payloads for a class
dobscura payloads xss html          # or: sqli / ssti / lfi / nosqli / cmdi / redirect / ssrf

# generate WAF-evasion mutations of a payload
dobscura evade "<script>alert(1)</script>"

# always-on passive audit: browse through the proxy, get live findings
dobscura liveaudit --addr 127.0.0.1:8080 --db findings.db --i-have-authorization
#   then set your browser HTTP/HTTPS proxy to 127.0.0.1:8080 and trust the CA.

# spray persistent blind-XSS beacons and watch for out-of-band callbacks
dobscura blindxss "https://target/comment" --params body --location form \
  --canary-zone canary.example.com --wait 2m --i-have-authorization
```

---

## Safety & scope

- Targets on private/loopback/metadata ranges are **blocked** unless `--allow-private`.
- `--scope` restricts the engagement; requests outside scope are refused at dial time
  (rebind-proof).
- The GUI API requires a bearer token unless `--no-auth`; the token is auto-generated
  and appended to `?token=` when the browser is opened.
- Enabling headless DOM: `go build -tags chromedp -o bin/dobscura ./cmd/cli`
  (needs a local Chrome/Chromium).
