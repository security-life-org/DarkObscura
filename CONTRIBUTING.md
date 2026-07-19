# Contributing to DarkObscura

Thanks for your interest in improving DarkObscura! This is a community project and
contributions of all kinds are welcome — code, detection signatures, documentation,
and bug reports.

## Ground rules

DarkObscura is **defensive / authorized-testing** tooling. Contributions must keep it
that way:

- ✅ New detections, verification oracles, reporting, UX, docs, tests.
- ✅ Improvements that **reduce false positives** or make findings more provable.
- ❌ Features whose primary purpose is evading detection for malicious use, mass
  untargeted scanning, or attacking third parties.

By contributing you agree your work is licensed under the project's [MIT License](LICENSE).

## The golden rule: zero false positives

The core promise of DarkObscura is that anything reported as **`confirmed`** is
deterministically verified. When adding a detection:

- A `confirmed` finding **must** be backed by a deterministic oracle — a statistical
  timing outlier, an out-of-band callback, a structural/differential change beyond the
  endpoint's noise floor, a file/product signature, or a cryptographic match.
- Anything heuristic must be labelled `possible` or `likely` — never `confirmed`.
- **Add a negative test** proving your detection does *not* fire on a safe target.

## Development setup

```bash
git clone https://github.com/security-life-org/DarkObscura.git
cd DarkObscura
go build ./...          # everything must compile
go vet ./...            # must be clean
go test ./...           # all tests must pass
make build              # produces bin/dobscura
```

Requirements: Go 1.26+.

### Optional build tags

- `-tags chromedp` enables the headless DOM renderer (requires a local Chrome/Chromium).
  The default build never needs it.

## Pull-request checklist

- [ ] `go build ./...`, `go vet ./...`, and `go test ./...` all pass.
- [ ] New detections include a **positive test** (fires on vulnerable) and a
      **negative test** (does not fire on safe).
- [ ] Code matches the surrounding style; comments explain *why*, not *what*.
- [ ] User-facing changes are reflected in `docs/USAGE.md` / `docs/FEATURES.md`.
- [ ] No secrets, credentials, or real-target data committed.

## Commit / PR style

- Keep PRs focused and reviewable.
- Describe the vulnerability class or capability, and how it is verified.
- Reference any issue the PR closes.

## Reporting bugs & requesting features

Use the GitHub issue templates. For a **security vulnerability in DarkObscura itself**,
follow [SECURITY.md](SECURITY.md) instead of opening a public issue.
