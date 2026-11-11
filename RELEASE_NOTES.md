# Release notes & tagging checklist — RELEASED (v0.1 + v0.2)

**Status: released record.** The push Rakshit approved was executed on
2026-11-10: tags **v0.1** (→ commit `0244682`) and **v0.2** (→ commit
`0b91492`) were cut and both GitHub releases published; step 6, the
live dogfood proof, completed 2026-11-11. The checklist below is kept
as the record of how the release was executed.
H-1B gate applies: no launch, advertising or monetisation follows from
these notes.

## Tagging checklist (executed 2026-11-10, in this order)

1. ✅ Push the verified v0.2 tree to `RakTikoo/expiry-radar` (web-upload
   method, stored-bytes verification, CI check — the house protocol).
2. ✅ Confirm CI is green on the pushed head.
3. ✅ Tag the **current pushed v0.1 head** (commit `0244682`, the JWT
   depth-guard fix on top of the original 64-file push) as **v0.1**:
   `git tag v0.1 0244682` — this retroactively marks the release that
   has been live since 2026-11-10, so consumers who pinned nothing can
   still reference the exact v0.1 code.
4. ✅ Tag the pushed v0.2 head as **v0.2** and create the GitHub releases
   from the notes below (v0.1 release first, then v0.2).
5. ✅ Verify both tags resolve on the repo page and that
   `uses: RakTikoo/expiry-radar@v0.2` is the form the README documents.
6. Only after the tag exists: the Action-proof step — install the
   Action + weekly workflow in one of our own repos and watch the
   living issue open/update/close for real (the local consumer
   simulation in `consumer-sim/` is the rehearsal, not the proof).
   **DONE 2026-11-11:** proven in
   https://github.com/RakTikoo/expiry-radar-dogfood — three real
   Actions runs: issue #1 opened with both planted findings, edited
   in place on run 2, commented "✅ Expiry Radar is clean" and closed
   on run 3 after the artefacts were fixed
   (https://github.com/RakTikoo/expiry-radar-dogfood/issues/1).

## Release notes — v0.1 (2026-11-10, as published)

First public release.

- Scans a repository for artefacts that break on a known future date:
  X.509 certificates (PEM and whole-file DER, parsed with a stdlib-only
  DER reader), committed JWTs (by `exp`, fully redacted), and hardcoded
  ISO valid-until dates in fixtures / as expiry-key values.
- Stdlib-only Python CLI + composite GitHub Action + an example weekly
  workflow that maintains a single "⏰ Expiry Radar" tracking issue.
- Exit codes: 0 clean, 1 expiring, 2 expired, 3 usage error.
- 61 tests, planted corpus 13/13 with 0 false positives, multi-agent
  adversarial review completed before release.
- Includes the deterministic JWT JSON depth guard (commit `0244682`):
  deeply nested token payloads warn-and-skip identically on every
  Python version.

## Release notes — v0.2 (2026-11-10, as published)

- **SARIF output** (`--sarif`): SARIF 2.1.0 for GitHub code scanning.
  Results cross-check 1:1 against the `--json` findings; unscanned
  files surface as tool-execution notifications and mark the invocation
  unsuccessful — a partial scan never presents as a clean pass.
  `--json` and `--sarif` are mutually exclusive (usage error, exit 3).
- **Epoch expiry values**: numeric epoch-seconds assigned to
  expiry-semantic keys (`exp`, `expires_at`, `*_EXPIRES_AT`,
  `valid_until`, …) in code, fixtures and .env-style files, classified
  expired / expiring / safe like ISO dates. Expiry-key attribution
  only: durations (`ttl`, `expires_in`), millisecond epochs and
  unrelated timestamps (`created_at`, `updated_at`) never flag.
- **JWK / JWKS `exp`**: `exp` fields inside JWK/JWKS-shaped JSON are
  classified like JWT `exp`. No key material is ever printed.
- **OpenSSL text output**: `notAfter=` / `Not After:` lines in
  committed openssl output are classified like certificate dates.
  `notBefore` never flags.
- Corpus grows 22 → 33 cases (planted findings 13 → 19, still 0 false
  positives on clean/edge cases); test suite 61 → 109 tests, including
  the three-reviewer adversarial fix pass (a quadratic-time regex on
  long tokens, JWK line misattribution, and the RSA-exponent /
  no-expiry-sentinel false positives in JWK `exp` were all caught in
  review and fixed before release).
- Local consumer-repo simulation included under `consumer-sim/`
  (clearly labelled simulation evidence; the on-GitHub proof followed
  the v0.2 tag and completed 2026-11-11 — see checklist step 6).

Known limitations remain as documented in ANALYSIS.md §6, plus the
v0.2 notes there.
