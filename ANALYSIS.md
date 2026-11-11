# Expiry Radar — Analysis

Build date: 2026-11-10. Status: local spike build, **not published**
(no repo created, nothing pushed — per the project's H-1B gate).
All measurements below were produced by running the shipped code on this
machine on 2026-11-10 with `--now 2026-11-10` unless stated otherwise.

## 1. Incumbent re-verification (2026-11-10)

Re-checked with three web searches ("repository certificate expiry
scanner fixture JWT exp scan git repo tool", "github action check
expiring certificates in repository PEM files notAfter", "\"expiry\"
scanner committed JWT expired test fixtures tool"), on top of the
original Round-3 research (report §4 #1).

**No direct incumbent found** — no tool that scans a *repository* for all
three artefact classes (cert `notAfter`, JWT `exp`, fixture valid-until
dates) and classifies them against a warning window. What exists is
adjacent, and the adjacencies are worth naming honestly:

- **Live-endpoint cert monitoring** (cert-manager, UptimeRobot-style
  services, and DIY GitHub-Actions tutorials that open a TLS connection
  to a list of domains): checks certs a server *presents*, never certs
  sitting in a repo's fixtures. Different input, different failure.
- **Secret scanners** (gitleaks, GitGuardian, and newer entrants whose
  listings surfaced in search, e.g. a scanner that decodes a Supabase JWT
  to prove its `role` claim): they flag a committed JWT as a *leak*;
  none found classifies committed tokens by `exp` as a *future breakage*.
- **Hand-rolled per-repo scripts**: search surfaced one real repository
  carrying its own `check-certificate-expiry.sh` sweeping its committed
  PEMs, plus gist one-liners running `openssl x509 -checkend` over cert
  directories. This is the strongest evidence *for* the idea — teams feel
  the pain and re-implement a narrow version in-house — and it is not a
  reusable, installable product.
- **JWT decoder websites**: single-token, paste-by-hand, no repo scan.

Residual risk (unchanged from the research report): a feature inside a
larger scanner could exist that targeted searches do not surface. This is
"searched, not proven absent".

## 2. Corpus design

Fixture-first, per the house standard: `make_fixtures.py` generates the
corpus *before* expectations are trusted, and every case carries a
`case.json` manifest (description, `--now`, expected findings as
(kind, status) pairs, expected safe count, expected exit code, expected
unscanned list). Generation is relative-date deterministic: cert
`notAfter`s and near-future JWT/fixture dates are derived from the
generation date, and each manifest's `now` is derived from the same date,
so the corpus is correct whenever it is regenerated.

- **22 cases**: 7 clean, 10 fault, 5 edge.
- Clean cases must produce **zero** findings: no artefacts; far-future
  cert / JWT / fixture date; historical changelog dates; stamp dates in
  sample paths (KiCad title-block regression case, §4); two far-future
  certs chained in one PEM.
- Fault cases plant **one fault each**: expired cert, cert expiring in
  30 d, DER cert expiring, JWT expired (genuinely, `exp` = 2020-01-01),
  JWT expiring in 25 d, fixture date past, fixture dates expiring (same
  date on two lines = two findings, deliberately), an expiry-key date in
  plain code, a mixed chain (1 safe + 1 expiring cert in one file), and a
  mixed expired-JWT + expiring-cert case proving exit 2 outranks exit 1.
- Edge cases: binary blob with cert-like bytes; JWT-shaped strings that
  are not JWTs; malformed PEM (warnings, no crash); a 6 MiB file (must be
  listed unscanned — its planted expired JWT neither found nor silently
  passed); a filename with spaces + unicode containing an expired JWT.
- Expired-cert method (documented in README + generator docstring):
  openssl cannot mint a past `notAfter`, so the case ships a 30-day cert
  and sets `--now` to generation + 60 d. The JWT and fixture-date expired
  cases are genuinely past, no simulation.

Certificates are minted with the openssl CLI at generation time only;
the scanner itself never calls openssl (see §5). Private keys are created
in a temp directory and deleted — no key material is a fixture.

## 3. Corpus results (objective)

| Metric | Result |
|---|---|
| Cases | 22 |
| Planted findings (expired + expiring) | **13** |
| Found | **13** |
| Missed | **0** |
| False positives on clean/edge cases | **0** |
| Planted safe artefacts (counted, not listed) | 6 found as safe, 0 misclassified |
| Corpus precision | **13/13 = 100%** |
| Corpus recall | **13/13 = 100%** |

Caveat, stated plainly: this is a *planted, self-authored* corpus. 100%
there means the scanner does what its specification says; it is not
evidence about arbitrary repos. That evidence is §4.

Tests: `python3 run_tests.py` → **61 tests, all passing** (stdlib
`unittest`; pytest is not installed on this machine and is not needed).
Coverage: DER parser (real cert, UTCTime/GeneralizedTime, garbage
rejection), classification boundaries (expired / window edge / safe,
custom `--days`), JWT decode + redaction + malformed/no-`exp`/no-`alg`
rejection, date heuristics (fixture path, key syntax, doc exemption,
prose rejection, invalid calendar dates), the full corpus, and CLI
end-to-end (exit codes, JSON shape, `--now` reclassification, `--days`,
`--show-safe`, symlink handling, git-tracked-only scanning in a real
temp git repo, non-directory error). The adversarial fix pass (below)
added 43 regression tests: usage-exit-3 pinning, FIFO/non-regular
files, JWT performance and recursion robustness, OID caps and UTCTime
pivot boundaries, DER/PEM warning paths, full-token redaction (T3),
text-report sanitisation, binary handling, cue/key precision and
per-key attribution, doc-exemption counting, the ignore file, walk
`onerror`, the git-fallback warning, and real submodule handling.

## 4. Real-world check (hand-labelled)

Ran on the three sibling project trees plus this repo itself
(`--now 2026-11-10`):

| Tree | Files | Findings | TP | FP | Verdict |
|---|---|---|---|---|---|
| `skillscan-src` | 82 | 0 | — | — | true negative (verified by grep: no `BEGIN CERTIFICATE`, no JWT-shaped strings, no expiry-key dates anywhere in the tree) |
| `kicad-preflight-src` | 282 | 0 | — | — | true negative (same grep verification) |
| `stranger-suite-src` | 47 | 0 | — | — | true negative (same grep verification) |
| **expiry-radar (own repo)** | 61 | 18 | **13** | **5** | precision **13/18 = 72%** |

Own-repo labelling, finding kind by kind:

- **Certificates: 5/5 TP.** All five are the planted fixture certs
  (PEM + DER + chain), correctly subject/issuer/classified.
- **JWTs: 4/4 TP.** The planted expired (×3) and expiring (×1) tokens.
- **Fixture dates: 4 TP, 5 FP (4/9).** TPs are the planted valid-until
  fixtures. All 5 FPs are the *same meta shape*: the expiry-key literals
  (`valid_until`, `LICENSE_VALID_UNTIL`, `expires:`) that exist as
  **source strings inside `make_fixtures.py` (2) and the test file
  (3)** — i.e. the scanner's own code describing its planted patterns.
  This is the known scanner-eats-its-own-test-data problem (SkillScan's
  sample corpus has the same property); the fix on the ladder is an
  ignore/allowlist file, not a weaker rule (§6).

### The heuristic iteration this run forced (measured, in order)

The date rule went through three versions *because of these runs*:

1. **v1 — any ISO date in a fixture-ish path.** KiCad tree: **8 findings,
   8/8 FP** — every one a KiCad title-block *drawing date*
   (`(date "2026-11-09")`) in `samples/`. Own repo: 57 findings, mostly
   noise. Precision on real trees: unusable.
2. **v2 — date also needs an expiry cue word on its line, or key syntax.**
   KiCad: 0 findings. Own repo: 26 findings, 13 TP / 13 FP — remaining
   FPs were prose/path-name uses of "expired" and `case.json` harness
   metadata (`"now": "…"` lines stopped matching at this step).
3. **v3 — dropped bare `expired` / `notAfter` as cue words** (their field
   forms are already caught by the key-syntax rule; as prose they only
   narrate status). KiCad/SkillScan/Stranger: still 0. Own repo: **18
   findings, 13 TP / 5 FP** (table above). Corpus: still 13/13, 0 FP —
   and the KiCad drawing-date shape is now a permanent corpus regression
   case (`clean_stamp_dates_in_samples`).

Net: certs and JWTs are exact (parser/decoding, no heuristics). The date
rule is a precision-tuned heuristic with a measured FP mode, documented
rather than hidden.

Performance: the 282-file KiCad tree scans in ~7.5 s on this shared VM;
the 61-file own repo in ~2 s. Fine for CI/weekly use; not yet optimised
(single-threaded, whole-file reads under the 5 MiB cap).

## 5. Design / security notes

- **Stdlib-only, including certificates.** The `cryptography` package is
  neither required nor imported. X.509 parsing is a purpose-built minimal
  DER reader in `expiry_radar.py` (TLV walk → tbsCertificate → issuer,
  validity, subject; UTCTime + GeneralizedTime; CN/O/OU/C/ST/L name
  rendering). It decodes only the fields the tool reports and rejects
  trailing garbage after a certificate.
- **Static only.** Scanned files are read as bytes, never executed,
  imported, or evaluated. The only subprocess the scanner ever runs is
  `git ls-files` when the target is a git repo (fallback: directory walk
  skipping `.git`, `node_modules`, venvs, caches).
- **Redaction.** JWT evidence = first 8 chars + `…`; `iss`/`sub`/`aud`
  claims are never printed; a T3 test asserts a full planted token (and
  its claims) appears nowhere in stdout/stderr/JSON. Fixture-date
  evidence lines mask JWT-shaped substrings and long `key=value` values
  with `***` *before* the 80-char truncation.
- **No silent passes.** Files > 5 MiB, symlinks, unreadable files,
  non-regular files, submodule entries, non-DER binaries and ignored
  paths are listed under `unscanned` in text *and* JSON. Malformed PEM
  blocks (including bad-body, legacy-header and unterminated blocks)
  and unparseable cert-extension files produce `warnings`, not
  findings and not silence.
- **Binary discipline.** Binary files are trusted only as whole-file DER
  certs (by extension, or any extension when the file starts with the
  DER SEQUENCE byte `0x30`). Embedded PEM text inside binaries is
  deliberately *not* extracted — random bytes form JWT/PEM-like strings
  too easily. This trades recall for precision; it is a documented v1
  choice. Non-DER binaries are now listed as unscanned
  ("binary — not searched") instead of being counted as scanned.
- **Resource bounds.** Non-regular files are never opened; reads are
  bounded at the size cap + 1 byte; JWT scanning is a linear pass over
  token-character runs (the original regex took 25 s on 100 KB of
  'A's; now ~0 ms); line numbers come from one precomputed newline
  index per file; decoded JWT segments cap at 64 KB; OID arcs cap at
  16 encoded bytes.
- **Determinism.** No network, no wall-clock dependence when `--now` is
  given, stable sort order, sorted file traversal. Same tree + same
  `--now` ⇒ byte-identical JSON except the root path.

## 6. Known limitations

1. **Fixture-date heuristic limits.** A valid-until date with *no* cue
   word and *no* key syntax (e.g. a bare date alone in a golden file) is
   missed — deliberate precision-over-recall choice (§4). Conversely,
   cue-word lines that are really stamps ("renewed on 2024-…") can FP.
2. **Scanner's-own-corpus FPs.** Repos that *contain* expiry patterns as
   test data/code strings (including this one) will flag them.
   **Mitigated, not solved:** `expiry-radar.ignore` (fix pass #17) is
   the supported blessing mechanism and this repo ships one; the
   residual limit is that per-key attribution cannot distinguish code
   that *tests* a `key: "DATE"` pattern from the pattern itself —
   measured in the adversarial section below.
3. **DER only as whole files**; no PKCS#12/PKCS#7 bundles, no JWK/JWKS
   `exp`-style fields, no certs embedded base64-in-JSON.
4. **JWT scope:** compact JWS shape with `alg` header + numeric `exp`
   only. No `nbf`, no per-token-type handling, no signature check (by
   design), tokens split across lines/variables are missed.
5. **Date formats:** ISO `YYYY-MM-DD` only — no epochs
   (`"expires_at": 1767…`), no `DD/MM/YYYY`, no RFC-2822 dates, no
   OpenSSL-style `notAfter=Dec 10 …` text (e.g. in captured openssl
   output committed to a repo).
6. **Git mode scans tracked files at their working-tree contents**; a
   tracked file deleted from disk is reported unscanned. Untracked files
   in a git repo are out of scope by design (spec: git-tracked first).
7. **Cert parser scope:** no chain building, no SAN extraction, exotic
   name string encodings are approximated (Teletex as latin-1); a cert
   that fails to parse yields a warning, never a guessed date.
8. **Week-scale freshness:** fixture certs/JWTs are relative to their
   mint dates in the real world; the committed corpus stays correct via
   per-case `--now`, but running the scanner *live* (no `--now`) on
   `fixtures/` will, correctly, report more findings as time passes.

## 7. GitHub integration story

- `action.yml` — composite action: sets up Python, runs the single-file
  CLI, exposes `exit-code` output, fails the job on any finding.
  Install is the standard 3-line form shown in the README.
- `examples/expiry-radar.yml` — the scheduled wedge: weekly cron +
  `workflow_dispatch`; runs the CLI **once** (JSON) and renders the
  text report from that same JSON; a scanner exit code above 2 (usage
  error) fails the workflow as a broken invocation, never as findings;
  a `concurrency` group prevents duplicate runs; then a `gh` shell step
  searches open issues **by the `expiry-radar` label** (`--limit 1000`),
  selects the one titled **⏰ Expiry Radar**, and either creates it
  (with the label), edits it in place with the fresh report, or
  comments-and-closes it when the scan is clean. One living issue per
  repo — a forwardable "your CI will break on this date" artifact,
  never issue spam.
- `.github/workflows/tests.yml` — this repo's own CI: regenerate
  fixtures, run the 61 tests, and self-scan one fault case asserting
  exit code 2.
- **Not done / not verified:** the Action and example workflow are
  written but *not executed on GitHub* (local-only build under the
  H-1B gate; no repo exists yet). YAML is structured per GitHub's
  documented composite-action and `gh issue` usage but must be smoke-
  tested on a real repo before any launch claim.

## 8. Expansion ladder (not built)

1. ~~`.expiry-radar-ignore` / inline allowlist comments~~ — **built**
   in the adversarial fix pass as `expiry-radar.ignore` (glob/substring
   patterns; inline allowlist comments remain unbuilt). This repo now
   dogfoods with it (see the adversarial section).
2. More artefact classes: JWKS/JWK expiry fields, epoch `exp`/`expires_at`
   values in fixtures, `notAfter=` text in committed openssl output,
   PGP key expiry, `.env`-style `*_EXPIRES_AT` values.
3. SARIF output for GitHub code-scanning (the report shape already maps:
   kind/status/path/line).
4. Policy mode: fail only on `<30d` in CI but report `<90d` in the weekly
   issue (two thresholds instead of one).
5. Multi-repo "expiry calendar" across an org (the research report's
   ladder step) — only after the single-repo tool earns its users.
6. Optional `cryptography`-backed verification mode for users who want
   chain/SAN detail — as an *extra*, never a requirement.

## Adversarial review

Three independent reviewers (red team, false-positive hunter, code
auditor) attacked the v0.1 build; the fix pass below was then run
against every finding, with tests re-run after each group and a
regression test per fix. All numbers are `--now 2026-11-10` on this
machine. Status key: **fixed** / **partially fixed** /
**accepted-as-limitation**.

### Critical / high findings

1. **FIFO hang — fixed.** Opening any non-regular file blocked forever
   (a FIFO in the tree hung the scan). Files are now `lstat`-checked
   (`stat.S_ISREG`) into `unscanned` ("not a regular file") before any
   open, and reads are bounded at `max + 1` bytes with overage →
   unscanned. Regression: a real FIFO in a temp dir scans cleanly via
   the CLI (previously: hang).
2. **JWT regex super-quadratic — fixed.** `JWT_RE` took **25.12 s** on
   100 KB of 'A's (measured pre-fix). Replaced with a linear pass over
   maximal token-character runs (`[A-Za-z0-9_.\-]+`, one character
   class, nothing to backtrack) with segment validation and length
   caps in code, plus a per-file token decode cache. Same input now
   scans in **~0.00 s** (test asserts < 1 s); **20,000 copies** of one
   valid JWT in one file complete in **~0.16 s** with 20,000 findings
   (helped by fix 5). The old regex survives only as a documented
   legacy constant.
3. **RecursionError on deeply-nested JWT JSON — fixed.** `json.loads`
   of a ~20,000-deep nested payload raises `RecursionError`; it is now
   caught → warning ("deeply nested payload JSON — skipped") and the
   scan continues to later tokens in the same file (test proves both).
   Decoded header/payload segments are capped at 64 KB → "oversized
   segment" warning. (Measured nuance: at depth 5,000 this CPython's
   C scanner parses successfully, so such a token is — correctly — a
   normal finding; the crash path starts deeper.)
4. **OID quadratic bigint + first-arc bug — fixed.** `_parse_oid` now
   rejects any arc encoded in > 16 bytes and any OID > 64 bytes
   (`DerError` → the cert becomes a warning, per fix 7), bounding the
   bigint arithmetic. The multi-byte first sub-identifier is decoded
   as a base-128 arc: `2.999.3` previously rendered **`2.56.55.3`**,
   now renders **`2.999.3`** (unit-tested with `2.5.4.3`, `1.2`).
5. **Quadratic `_line_of` — fixed.** Newline offsets are precomputed
   once per file (C-speed `finditer`) and line numbers are a `bisect`;
   a unit test cross-checks every offset of a sample file against the
   naive count, and the 20k-token test pins the last finding's line
   at exactly 20,000. (The legacy `_line_of` remains for API compat.)
6. **Exit-code collision — fixed.** Findings keep 0/1/2; **usage
   errors exit 3**: a custom `ArgumentParser.error` (covers argparse
   failures and invalid `--now`), plus explicit checks for
   `--days < 0` and `--max-file-size < 0`, and the non-directory path
   now returns 3 (was 2 — indistinguishable from "expired"). Tests pin
   the exact code (T2). README exit table and `action.yml` document 3.
7. **DER / PEM silent passes — fixed.** A file with a cert extension
   (`.der`/`.crt`/`.cer`) that fails DER parse now warns (a PEM-text
   `.crt` is exempted — it is handled by the PEM path and does not
   warn; test-pinned). PEM detection is loose: every
   `BEGIN CERTIFICATE` marker is accounted for — non-base64 body →
   warning, legacy-header block → warning, missing `END` → warning.
   The corpus malformed-PEM case now yields 2 warnings (was 1: the
   `!!!` block used to be silently invisible to the strict regex).
8. **Claims / evidence leaks (F5/F6) — fixed.** JWT `iss`/`sub`/`aud`
   were printed in full in `detail`; they are **no longer printed at
   all** (the exp date is the finding). Fixture-date evidence now
   masks JWT-shaped substrings and `key=value`-style values > 8 chars
   with `***` **before** the 80-char truncation. The redaction test was
   strengthened to T3: a planted full token, its claims, and a token
   embedded in a fixture-date line appear **nowhere** in stdout,
   stderr, or JSON.
9. **Text-report injection — fixed.** All attacker-controlled strings
   in the text report (cert subject/issuer, paths, evidence, warnings,
   unscanned reasons, the root path) have C0 control characters
   (incl. `\n`, `\r`, ESC) and DEL replaced with spaces; subject,
   issuer and detail strings are capped at 120 chars and warning
   exception text at 120 chars at the source. A crafted finding with
   embedded newlines/ESC and a 300-char detail renders as one
   sanitised line (test-pinned).
10. **Binary handling — fixed.** Binary files (NUL in first 8 KB)
    with a non-DER extension are listed as unscanned
    ("binary — not searched") and **no longer counted as scanned**
    (previously counted, with embedded text silently ignored). Any
    binary starting with `0x30` (DER SEQUENCE) gets a DER parse
    attempt whatever its extension — a DER cert renamed `.bin` is now
    found (test-pinned). Corpus change: `edge_binary_certlike_bytes`
    now expects `blob.bin` in `expected_unscanned` (generator and
    manifest updated together).
11. **Unsigned JWTs — fixed.** The `alg=none` form `header.payload.`
    (empty signature segment) is accepted and classified by `exp`
    (test-pinned), as is a token followed by a sentence period.
12. **CLI / collection edge cases — fixed.** `--max-file-size < 0` →
    usage exit 3 (and `scan()` raises `ValueError`). `os.walk`
    `onerror` errors become unscanned entries instead of being
    swallowed (unit-tested via a patched walk). Submodules are
    detected both ways — git mode parses `git ls-files -s` mode
    160000, walk mode spots a child dir holding a `.git` file — and
    reported as unscanned, "submodule (not scanned)" (integration
    test builds a real two-repo submodule). When a `.git` entry
    exists but `ls-files` fails, the walk fallback adds a warning
    that the scan scope changed (untracked files now included); a
    plain non-git directory gets no such warning (test-pinned).

### False-positive findings

13. **Cue word boundaries — fixed.** Cues are whole words: `invalid`,
    `validation` and `renewable` no longer trip `\bvalid` /
    `\brenew(?:s|ed|al|ing)?\b`; plain-English **"before" was removed
    as a cue entirely**. Real cues (`valid until`, `renewal`,
    `regenerate`, `deadline`) still flag (tests both ways).
14. **Generic domain keys removed — fixed.** `due_date` and `end_date`
    (and `renew_by`) are out of the key set. Keys are expiry-semantic
    only: `expir*`, `valid_until`/`valid-until`/`valid_to`-family,
    `not_after`, `exp`. **`ttl` was considered and excluded by
    decision**: TTL values are overwhelmingly second-count durations,
    not ISO dates, so a `ttl:` key adjacent to a date is more likely
    a stamp than a bound.
15. **Per-key attribution — fixed.** A line flags a date only if the
    date *is* the value of an expiry key on that line
    (`key: "DATE"`, `key=DATE`, `key = "DATE"` adjacency), or —
    fixture path + cue word — it is the **only** date on the line.
    Multi-date lines no longer flag every date (test: a
    `valid_until`/`created`/`dob` line flags exactly the
    `valid_until` date). **Accepted trade-off:** a "valid from X
    until Y" fixture line (cue, two dates, no key syntax) now flags
    nothing — precision was chosen over that recall shape, and the
    key form of the same fact is still caught.
16. **Doc exemption — fixed, and made consistent + counted.**
    `_is_doc_file` was wrong both ways (extensionless docs missed;
    `src/readme.py` exempted by stem alone). Now: `.md`/`.rst`/`.adoc`
    exempt at any stem; extensionless files exempt on a doc stem
    (`CHANGELOG`, `LICENSE`, `README`); `.txt` exempts only with a
    doc stem (so `tokens.txt` still scans); code extensions defeat
    the stem (`src/readme.py`, `CHANGELOG.py` NOT exempt — tests).
    `release_notes` / `release-notes` stems added. The exemption now
    applies to **certs and JWTs too**, not just dates — an expired
    RFC 7519 example token in a README was a live FP — and suppressed
    findings are counted as **`suppressed_in_docs`** in JSON (top
    level and summary) and noted in the text report. It is a count,
    not silence.
17. **Suppression mechanism — built.** `expiry-radar.ignore` in the
    scan root: one glob/substring pattern per line, `#` comments;
    matched paths are listed as unscanned ("ignored by
    expiry-radar.ignore"). Documented in README as the way to bless
    intentional expired fixtures (auth negative tests, TLS
    expired-cert fixtures, VCR cassettes). **Decision, recorded:**
    `cassettes/` paths are **not** auto-suppressed — a cassette tree
    can hold a genuinely leaked live token, and an explicit,
    reviewable ignore file beats a silent path heuristic (test: a
    cassette token flags until the ignore file blesses it).
18. **Boundary tests — added.** UTCTime pivot: `49…` → **2049**,
    `50…` → **1950** (both were already correct in the parser; now
    pinned). Plus regression tests for fixes 1, 2, 3, 7, 8, 10, 11,
    13, 14, 15, 16 as itemised above: **tests 18 → 61, all passing.**

### Example workflow (examples/expiry-radar.yml)

Rewritten per the audit: **one** scanner run (`--json` only) with the
text report rendered from that JSON (the old version ran the CLI
twice and the two runs could disagree); exit code **> 2 fails the
workflow as a broken invocation**, not as findings; a `concurrency`
group (`expiry-radar`, no cancel-in-progress) prevents duplicate
tracking issues; the issue search is **by label `expiry-radar`** with
`--limit 1000` (was title-match at `--limit 100`), the label is
created idempotently, and created issues carry it. YAML parses;
still **untested on GitHub** (local-only build under the H-1B gate),
and the file says so in its header.

### Re-measured numbers (fix pass, 2026-11-10)

| Check | Before | After |
|---|---|---|
| Corpus (planted) | 13/13 found, 0 FP | **13/13 found, 0 FP** (unchanged) |
| Test suite | 18 passing | **61 passing** |
| FP spot-check tree (invoices `due_date`, events `end_date`, invalid-coupon JSONL, renewable/validation readings, RFC 7519 token in docs, one true `valid_until`) | **12 findings: 1 TP, 11 FP** | **1 finding (the TP); RFC token counted as `suppressed_in_docs: 1`** — every named FP class now clean |
| Own repo, no ignore file | 18 findings: 13 TP / 5 FP (precision 72%) | 35 findings: 13 TP / 22 FP — see note |
| Own repo, shipped `expiry-radar.ignore` | (no ignore file existed) | **0 findings, exit 0**; 53 unscanned (51 ignored + 1 binary + 1 oversize); 3 warnings |
| 100 KB dotless JWT blob | 25.12 s | ~0.00 s |
| KiCad / SkillScan / Stranger trees | 0 findings | 0 findings (re-run, unchanged) |

**Own-repo note, stated honestly:** the rule fixes (13/14/15) did
**not** reduce the 5 known meta-FPs, and the raw count rose from 18
to 35. Inspection shows why: all 5 originals — and ~17 new ones —
are *literally* `key: "DATE"` strings inside this repo's own test
and generator code (the fix pass's regression tests added many).
Per-key attribution cannot distinguish code that tests the pattern
from the pattern itself, and weakening the rule to try would cost
real detections. These are exactly the §6.2 scanner-eats-its-own-
test-data class, and the shipped **`expiry-radar.ignore`** (patterns:
`fixtures/`, `tests/`, `make_fixtures.py`) is the designed answer:
with it, the dogfood run is clean at exit 0 while the corpus tests —
which scan the fixture case directories directly, without the
ignore file — still verify all 13 planted detections. The 3
remaining dogfood warnings are also honest: `expiry_radar.py`'s own
source contains the literal `-----BEGIN CERTIFICATE-----` /
`-----END CERTIFICATE-----` constants (2 warnings), and this
ANALYSIS file quotes the same literals in this very paragraph
(1 warning), so the loose-PEM rule (fix 7) reports the spans
between them as non-certificate blocks. That is the rule working
as specified, on the scanner itself.

### Accepted as limitations (not fixed, with reasons)

- **Fix 15 trade-off** (above): cue + multi-date lines with no key
  syntax flag nothing — deliberate precision-over-recall.
- **`ttl` excluded** from the key set (fix 14 reasoning, above).
- **DER certs in base64-without-PEM-headers** text files (some `.crt`
  files in the wild) still fail the DER parse — but since fix 7 they
  produce a warning instead of silence.
- The race between `lstat` and `open` (a file swapped for a FIFO in
  between) is bounded by the capped read but not eliminated; closing
  it needs `O_NOFOLLOW`/`dir_fd` plumbing disproportionate to this
  tool's threat model (local repos, CI checkouts).

## v0.2 (built 2026-11-10, unreleased — local tree only)

Built in `expiry-radar-v02/` from the pushed v0.1 tree (which is
untouched). Scope, per the approved v0.2 wave: SARIF output, three new
artefact classes from the §8 ladder item 2, corpus first, and
Action-proof *preparation* (release notes + a local consumer
simulation — no tag, no push, nothing run on GitHub).

### What was added

- **`--sarif`** — SARIF 2.1.0, following the CI Command Truth v0.2
  pattern: results are exactly the findings the JSON report lists
  (expired/expiring; safe added with `--show-safe`), every ruleId
  resolves to a driver rule, unscanned files become tool-execution
  notifications and set the invocation's `executionSuccessful` to
  false, warnings become notifications too. `--json` + `--sarif` is a
  usage error (exit 3). Exit codes are unchanged in SARIF mode. Tests
  parse the SARIF and cross-check it result-for-result against the
  JSON report (ruleId, URI, line, status).
- **Epoch expiry values** (`epoch-expiry`) — a number that *is the
  value* of an expiry-semantic key on its line. The key rule is
  final-segment attribution: `exp`, `…expires_at`, `…valid_until`,
  `…not_after`, `…expiry` qualify; trailing segments disqualify
  (`expiry_check_interval`, and OAuth's `expires_in`, which is a
  duration). Values must sit in the plausible epoch-seconds window
  [100 000 000, 4 102 444 800] (1973-03-03 … 2100-01-01): the lower
  bound rejects durations-in-disguise (ttl=3600), the upper bound
  rejects millisecond epochs (1.7e12) outright. Fractional values are
  rejected except the exact `.0` spelling. Classification is the exact
  instant (unlike the ISO rule's end-of-day convention — an epoch *is*
  an instant).
- **JWK/JWKS `exp`** (`jwk-expiry`) — the document must parse as JSON
  (behind the same deterministic depth guard as JWT segments) and
  validate shape: a top-level `keys` array whose members carry `kty`,
  or a single object with `kty`. Only `exp` and `kty` are read; key
  material and `kid` never reach a finding (test-pinned). Non-numeric /
  non-integer / out-of-range `exp` warns once per class per file.
  Malformed candidates are silent unless the filename claims to be a
  JWKS file. Lines claimed by a JWK finding are excluded from the
  epoch scan, so a JWKS `exp` is reported once, as a JWK finding.
- **OpenSSL text output** (`openssl-expiry`) — `notAfter=…` (the
  `-dates`/`-enddate` form) and `Not After : …` (the `-text` form),
  full timestamp + `GMT` required. `notBefore` never matches.

### Corpus (regenerated, relative-date deterministic as before)

33 cases (was 22): +4 clean, +6 fault, +1 edge. Planted findings
19/19 found (13 old + 6 new: epoch ×2, JWK ×2, openssl ×2), 0 missed,
0 false positives on clean/edge cases; the old 13/13 are unchanged.
New FP traps live in `clean_epoch_traps` (ttl, `expires_in`, ms
epochs, `created_at`/`updated_at`, sub-plausibility `exp`) and
`clean_openssl_dates` (past `notBefore` + safe 2049 `notAfter`).
Tests: 61 → 92 at first green (unit classes for all three new
scanners + a SARIF class that cross-checks against JSON), → **109
after the adversarial fix pass** below.

### Real-world runs (`--now 2026-11-10`, v0.2 scanner)

| Tree | Files | Findings | Verdict |
|---|---|---|---|
| skillscan-src | 91 | 0 | true negative (unchanged from v0.1; tree grew since v0.1's 82 files) |
| stranger-suite-src | 47 | 0 | true negative (unchanged) |
| kicad-preflight-src | 304 | 0 (26 unscanned) | true negative (unchanged); tree grew since v0.1's 282 files. Runtime ~11 s vs v0.1's ~7.5 s at 282 files — the three new line scanners cost real time on large trees; fine for CI/weekly use, noted honestly |
| round4-pair/handoff-reconciler | 97 | 0 | true negative |
| round4-pair/living-contract-diff | 55 | 0 | true negative |
| round3-trio/ci-command-truth (v0.2 tree) | 143 | 0 | true negative |
| round3-trio/expiry-radar (v0.1 tree) | 11 scanned, 53 unscanned (its ignore file) | 0 findings, 3 warnings | matches v0.1 dogfood behaviour |
| expiry-radar-v02 (own tree, shipped ignore file incl. `consumer-sim/`) | 12 scanned, 86 unscanned | 0 findings, 1 safe, 3 warnings | the 1 safe is the scanner's own docstring quoting a full `notAfter=Dec 10 23:59:59 2027 GMT` example — the documented scanner-eats-its-own-docs class, safe status, exit 0; the 3 warnings are the known PEM-marker literals (as in v0.1) |

New classes produced **0 false positives on every clean tree scanned**.

### Action-proof preparation (local only)

- `RELEASE_NOTES.md` — tagging checklist (v0.1 tag retroactively on
  the pushed head `0244682`, v0.2 tag on the v0.2 head once pushed)
  and draft release notes for both versions. Nothing tagged/pushed.
- `consumer-sim/` — a throwaway consumer repo that installs the
  scanner the documented vendored way, plants an expiring cert +
  expired JWT, and executes the example weekly workflow's core steps
  locally: single `--json` run → text report rendered from that JSON
  by the workflow's own rendering code → the living-issue body, plus a
  demonstration that exit 2 is findings while a broken invocation
  exits 3. Evidence files under `consumer-sim/evidence/`. Labelled
  simulation everywhere; the on-GitHub proof still requires the tag
  (RELEASE_NOTES.md checklist step 6).

### New limitations (v0.2)

- Epoch values in *string* form with non-`.0` fractional parts, and
  epochs written as scientific notation or hex, are not recognised —
  precision over recall, consistent with §6.1.
- The epoch rule is line-based like the ISO rule: a key and its value
  split across lines (pretty-printed JSON always keeps them together;
  a hand-wrapped file might not) is missed.
- JWKS detection requires the literal substrings `"kty"`/`"keys"` and
  `"exp"` before parsing (a cheap gate); a JWKS document using
  single-quoted or otherwise non-JSON syntax is out of scope — it is
  not JSON.
- OpenSSL output without the `GMT` suffix (localised openssl output)
  is not recognised.
- SARIF results mirror the JSON findings list; safe artefacts appear
  only with `--show-safe`, exactly as in JSON mode.

### Adversarial review — v0.2 fix pass (three reviewers, all findings
### hands-on reproduced by them and re-verified after the fix)

**Closed:**
1. **CRITICAL DoS (red team)** — the epoch assignment regex was
   quadratic on long unbroken alphanumeric tokens (100 KB token
   ≈ 370 s). Left-boundary lookbehind + 64-char key cap: the same
   input now scans in ~0.00 s. Per-finding evidence masking over
   unbounded lines was likewise quadratic (mask once per line, over
   at most 2048 chars) and JWKS line lookup was O(keys × lines)
   (one-pass candidate map). Perf regression tests pin all three.
2. **HIGH (auditor + red team)** — JWK line attribution by substring
   search put findings on wrong lines (duplicate values, prefix
   collisions, values inside `kid`s) and the wrong line then defeated
   the epoch dedupe, double-counting artefacts. Attribution is now
   one-pass candidate consumption in document order.
3. **HIGH (auditor + red team)** — the epoch dedupe excluded whole
   lines, silently dropping a genuine expired `expires_at` sharing a
   (minified) line with a JWK finding — exit 0 on an expired artefact.
   Dedupe is now occurrence-level: (line, value) claims, consumed one
   by one; unrelated values on the same line still report. Pinned by
   an integration test (compact mixed file → both findings, exit 2).
4. **HIGH (FP hunt)** — the JWK scanner had no plausibility window:
   `exp: 65537` (the RSA public exponent in some export formats) and
   the no-expiry sentinels `exp: 0` / `exp: -1` flagged as 1970
   expiries. The epoch window now applies; implausible values are
   silently not expiries. Digit-string exps are accepted as values
   (and reported once, as JWK findings — the first version both
   warned "non-numeric" *and* flagged them as epochs).
5. **HIGH (FP hunt)** — bare `exp` is overloaded (game experience
   points at exactly epoch magnitudes, "expected" in test code,
   experiment ids). A bare `exp` now requires token context (a sibling
   `iat`/`sub`/`iss`/`aud` key in the file); suffixed forms are
   unambiguous and unchanged.
6. **MEDIUM (FP hunt)** — doc exemption missed the containers
   historical expiry data lives in: `.log` files (historical records,
   like changelogs), files under a `docs/` path part, doc stems with
   data extensions (`CHANGELOG.json`, `HISTORY.yaml`), template
   suffixes (`.env.example`, `*.sample`, `*.template`, `*.dist`) and
   extensionless `NOTES`. All are now exempt *and counted* as
   `suppressed_in_docs`; code extensions still defeat stems.
7. **MEDIUM (auditor)** — epoch values with trailing junk flagged
   (`1577836800abc`, `…_000`, and `1577836800.0e3`, a ms-scale value
   misread as seconds). The terminator now rejects any word char or
   dot after the value.
8. **MEDIUM (auditor)** — evidence masking leaked space-separated
   secrets inside quoted strings on the finding's line. Quoted
   contents > 12 chars and standalone 24+ char token runs are now
   masked before the cap.
9. **MEDIUM (red team)** — unicode-escaped JWKS keys (`\u0065xp`)
   evaded the literal substring gates entirely. Gates now admit any
   brace-led document mentioning the markers or containing escapes;
   `json.loads` decodes. (Line attribution for escaped keys falls
   back to line 1 — the value/kind/status are right, the line is
   approximate; documented here rather than hidden.)
10. **LOW (auditor)** — `kty` evidence is whitelisted
    (RSA/EC/oct/OKP, else `unknown`) instead of echoing file text;
    README's epoch/ISO classification wording and the 1973 bound
    (1973-03-03, epoch 100 000 000) corrected; the midnight-epoch
    instant semantics pinned by test. SARIF `executionSuccessful`
    semantics (unscanned flips it, warnings don't) documented in the
    README rather than changed — the scan *did* complete when only
    warnings exist, and the warnings are themselves notifications.

**Accepted as limitations (with reasons):**
- FP hunt: expiry assignments inside comments/string literals in code
  (#8), prose quoting an assignment inside a JSON string value (#9),
  and parser-test openssl captures (#14) still flag. The rule is
  textual by design (v0.1 doctrine); distinguishing them needs
  per-language parsing, and the ignore file is the blessed route.
  Snapshot/golden API responses (#12) and docs samples outside
  `docs/` (#13) likewise — the v0.1 no-auto-suppress decision stands.
  `valid_until: 999999999` (a pre-2001 "indefinite" sentinel) flags as
  2001 — the scanner's claim is literally true of the value.
- Red team: openssl forms without `GMT` / with full month names, and
  epoch spellings in scientific/hex/`+`-prefixed form, remain
  unrecognised (canonical forms only) — precision over recall.
- Noted for a future version (found by the FP hunt, **outside the
  locked v0.2 scope**): full ISO datetimes (`"expires":
  "2020-01-01T00:00:00Z"`) evade the v0.1 ISO rule — the date regex's
  trailing `\b` fails before `T` — so AWS/HAR-style datetime
  expirations are missed entirely; and camelCase keys (`ExpiresAt:`)
  evade the epoch rule, which is snake/kebab-case by design.
- Doc-file JWK/PEM *warnings* still print even though findings in
  docs are suppressed+counted (auditor #8): uniform with v0.1's
  warning behaviour for all scanners; noisy but never silent.

**Re-measured after the fix pass:** tests **109/109**; corpus
33 cases, planted **19/19**, 0 FP (unchanged); real-world table above
re-run — every clean tree still 0 findings (own tree: 0 findings,
1 safe, 3 warnings, 1 suppressed); consumer simulation re-run green
(exit 2, exactly the 2 planted findings, broken invocation exit 3);
100 KB single-token file: ~370 s → ~0.00 s; KiCad tree (304 files)
~9 s.
