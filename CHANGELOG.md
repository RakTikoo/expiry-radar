# Changelog

All notable changes to Expiry Radar, newest first. Versions are tagged
on GitHub (`v0.1`, `v0.2`, …) and consumers pin them as
`uses: RakTikoo/expiry-radar@v0.2`.

## v0.2 — 2026-11-10

- **SARIF output** (`--sarif`): SARIF 2.1.0 for GitHub code scanning.
  Results cross-check 1:1 against the `--json` findings; unscanned
  files surface as tool-execution notifications and mark the invocation
  unsuccessful — a partial scan never presents as a clean pass.
  `--json` and `--sarif` together are a usage error (exit 3).
- **Epoch expiry values**: epoch-seconds assigned to expiry-semantic
  keys (`exp`, `expires_at`, `*_EXPIRES_AT`, `valid_until`, …) in code,
  fixtures and .env-style files are classified expired / expiring /
  safe like ISO dates. Expiry-key attribution only: durations (`ttl`,
  `expires_in`), millisecond epochs and unrelated timestamps
  (`created_at`, `updated_at`) never flag.
- **JWK / JWKS `exp`**: `exp` fields inside JWK/JWKS-shaped JSON are
  classified like JWT `exp`. No key material is ever printed.
- **OpenSSL text output**: `notAfter=` / `Not After:` lines in
  committed openssl output are classified like certificate dates.
  `notBefore` never flags.
- Corpus grew 22 → 33 cases (planted findings 13 → 19, still 0 false
  positives); test suite 61 → 109 tests, including a three-reviewer
  adversarial fix pass (a quadratic-time regex on long tokens, JWK line
  misattribution, and RSA-exponent / no-expiry-sentinel false positives
  in JWK `exp` were all caught in review and fixed before release).
- Added `consumer-sim/`: a local consumer-repo simulation of the
  weekly living-issue workflow. (The workflow has since been proven
  live on GitHub Actions — see the README's "Proven live" section.)

## v0.1 — 2026-11-10

First public release.

- Scans a repository for artefacts that break on a known future date:
  - **X.509 certificates** — PEM blocks in text files and whole-file
    DER, parsed with a stdlib-only ASN.1/DER reader.
  - **Committed JWTs** — classified by the `exp` claim, fully redacted
    (evidence is truncated; `iss` / `sub` / `aud` are never printed).
  - **Hardcoded ISO valid-until dates** in fixtures and as
    expiry-key values.
- Stdlib-only Python CLI (`expiry_radar.py`, Python 3.9+), a composite
  GitHub Action, and an example weekly workflow that maintains a
  single "⏰ Expiry Radar" tracking issue per repo.
- Output formats: text, `--json`, `--github-annotations`.
- Exit codes: 0 clean, 1 expiring within the window, 2 expired,
  3 usage error.
- `expiry-radar.ignore` file for blessing intentional fixtures
  (listed as unscanned instead of flagged).
- 61 tests; planted corpus 13/13 with 0 false positives;
  multi-agent adversarial review completed before release.
- Includes the deterministic JWT JSON depth-guard fix (commit
  `0244682`) found by the first CI run.
