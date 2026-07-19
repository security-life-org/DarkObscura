# Architecture

DarkObscura is a single Go module (`github.com/security-life-org/DarkObscura`) with
clean package boundaries. Nothing is fetched at runtime — the GUI, templates, and
plugins are embedded into the binary via `go:embed`.

## High-level flow

```
                 ┌──────────────┐
   target  ───▶  │  discovery   │  crawl / dynamic harvest / OpenAPI import
                 └──────┬───────┘
                        │ endpoints + injection points
                        ▼
                 ┌──────────────┐
                 │   fuzzer     │  stateful, per-host rate-limited
                 └──────┬───────┘
                        │ candidate probes
                        ▼
        ┌──────────────────────────────────────┐
        │        Verifier (4 stages)            │
        │  1. baseline (+ noise floor)          │
        │  2. structural / byte differential    │
        │  3. time-series (z-score)             │
        │  4. out-of-band canary (DNS/HTTP)     │
        └──────────────┬───────────────────────┘
                        │ CONFIRMED findings only
                        ▼
           reporting · attack-graph · SARIF/HTML
```

Only a finding that passes its applicable stage(s) is emitted as `confirmed`. This is
the whole point of the tool.

## Package map

| Package | Responsibility |
|---|---|
| `cmd/cli` | `dobscura` CLI (cobra) + GUI launcher |
| `internal/proxy` | MITM forward proxy (HTTP/1.1 + HTTP/2), TLS intercept, interceptor hooks |
| `internal/engine` | Worker pool, per-host token-bucket limiter, stateful `Session` (cookies + CSRF) |
| `internal/exploit` | Verification pipeline, stateful fuzzer, OOB canary, race/smuggle, active exploit proofs |
| `internal/parser` | Parameter extraction + risk classification |
| `internal/crawl` | Same-origin spider (HTML + JS-mined endpoints, robots/sitemap) |
| `internal/dynamic` | JS-runtime surface harvester |
| `internal/importer` | OpenAPI/Swagger → endpoints |
| `internal/fingerprint` | Confidence-graded tech detection |
| `internal/cve` | Version → CVE correlation |
| `internal/secrets` | Typed + entropy secret detection |
| `internal/access` | IDOR/BOLA multi-identity engine |
| `internal/logicflow` | Business-logic state-machine testing |
| `internal/graphql` | GraphQL introspection/abuse checks |
| `internal/grpcfuzz` | gRPC reflection enumeration + fuzzing |
| `internal/jwtattack` | JWT `alg=none` + weak-secret cracking |
| `internal/blindxss` | Persistent blind/stored-XSS beacons |
| `internal/clientside` | CORS / cache-poisoning / CSP checks |
| `internal/dom` | DOM-XSS source→sink analysis (+ optional chromedp renderer) |
| `internal/sourcemap` | Source-map reconstruction + scan |
| `internal/wsfuzz` | WebSocket fuzzing |
| `internal/waf` | WAF/block classification + live signal |
| `internal/evasion` | WAF fingerprint + payload mutation |
| `internal/chain` | Deterministic attack-chain orchestration |
| `internal/templates` | Nuclei-compatible template engine + bundled official set |
| `internal/findings` | Cross-scan findings DB (dedup, suppression, history) |
| `internal/report` | SARIF + HTML reporting |
| `internal/liveaudit` | Always-on passive audit interceptor |
| `internal/passive` | Passive response auditing (headers, cookies, disclosure) |
| `internal/scope` | SSRF/scope guard (enforced at dial + handler) |
| `internal/gui` | Embedded dashboard server + JSON/SSE API |
| `internal/wasm` | wazero plugin runtime |
| `internal/ebpf` | Optional kernel-level visibility (build-tagged) |
| `pkg/diff` | Byte + JSON structural diff |
| `pkg/timeseries` | Statistical latency baseline (z-score) |
| `pkg/certgen` | Root CA + per-SNI leaf cache for MITM |
| `pkg/netutil` | ID/helpers |

## Design principles

1. **Deterministic verification.** No finding is `confirmed` without a provable oracle.
2. **Noise-aware.** The baseline models each endpoint's natural variance, so dynamic
   pages don't produce differential false positives.
3. **Safe by default.** SSRF/scope guard at dial time, auth on the API, explicit
   authorization gate.
4. **Self-contained.** One binary, embedded assets, no runtime downloads.
5. **Extensible.** WASM plugins and a Nuclei-compatible template engine.

## Build tags

| Tag | Effect |
|---|---|
| *(default)* | Pure-Go build, no external runtime needs |
| `chromedp` | Enables headless DOM rendering (`internal/dom`) — needs local Chrome |
| `linux` | Enables the eBPF observer (`internal/ebpf`) |
