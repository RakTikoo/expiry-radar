# ⏰ Expiry Radar

**Expiry Radar finds everything in your repo that will break on a known future date — expiring X.509 certificates, committed JWTs past their `exp`, and hardcoded valid-until dates in test fixtures — before your CI finds out the hard way.**

One job, done deterministically: walk the git-tracked files, parse the
dates that are already sitting there, and report days-to-expiry per item.
Python standard library only. No network, no account, no token, no LLM.
Scanned files are read as bytes and never executed.

## Why

Fixture certs, canned tokens and "valid until" dates are minted once and
never re-read. They fail silently later — a test suite that goes red on a
random Tuesday, a demo that dies mid-presentation. The expiry dates are
knowable *today*, from the repo alone. Expiry Radar is the calendar check
nobody runs.

## Install & run

```bash
python3 expiry_radar.py /path/to/repo
```

That's it — a single file, Python 3.9+, nothing to install.

```bash
python3 expiry_radar.py .                     # text report
python3 expiry_radar.py . --json              # JSON report
python3 expiry_radar.py . --days 30           # warn only within 30 days
python3 expiry_radar.py . --show-safe         # also list safe artefacts
python3 expiry_radar.py . --now 2027-01-01    # "what breaks by New Year?"
```

### Exit codes

| Code | Meaning |
|------|---------|
| 0 | clean — nothing expired or expiring within the window |
| 1 | something expiring within `--days` (default 90) |
| 2 | something already expired |
| 3 | usage error — bad arguments, invalid `--now`, `--days` / `--max-file-size` < 0, or a non-directory path. Never a finding; CI should treat 3 as a broken invocation, not as expiry. |

### What it finds

1. **X.509 certificates** — PEM blocks anywhere in a text file (including
   several certs chained in one file) and whole-file DER certs
   (`.der` / `.crt` / `.cer`). `notAfter` is parsed with a small
   stdlib-only ASN.1/DER parser written for this tool — the
   `cryptography` package is *not* required and not used. Subject and
   issuer are reported. Signatures are not checked (irrelevant to expiry).
2. **Committed JWTs** — JWT-shaped strings whose header decodes to JSON
   with an `alg` and whose payload carries an `exp` claim (the unsigned
   `alg=none` form `header.payload.` counts too). The token is
   **never printed in full**: evidence is the first 8 characters + `…`,
   and the `iss` / `sub` / `aud` claims are **never printed at all**.
   Signatures are not verified — this answers "when does it stop
   working", not "is it authentic".
3. **Hardcoded dates** — ISO `YYYY-MM-DD` dates that bound validity:
   a date that *is the value* of an expiry-semantic key anywhere
   (`valid_until = "…"`, `"expires": "…"`, `LICENSE_VALID_UNTIL = "…"`,
   `"exp": "…"` — other dates on the same line are not flagged), and a
   date on a line carrying a whole-word validity cue (valid / until /
   regenerate / renew / deadline / cutoff) that is the *only* date on
   its line, inside fixture-ish paths (`test/`, `fixtures/`, `testdata/`,
   `snapshots/`, `samples/`, test file names…). Generic scheduling keys
   (`due_date`, `end_date`) are **not** expiry keys and never flag.
   Changelog and documentation files are exempt for all three artefact
   kinds — a 2019 date (or an RFC example token) in a changelog is
   history, not a time-bomb — but suppressed findings are counted as
   `suppressed_in_docs` in the JSON report, never silently dropped.
   This conservatism is deliberate and measured in
   [ANALYSIS.md](ANALYSIS.md).

Safe artefacts (> window) are counted in the summary but not listed
unless `--show-safe` is passed. Files over 5 MiB, symlinks, non-regular
files (FIFOs, devices), submodule entries, and binary files that are
not whole-file DER certificates are listed as **unscanned** — never
silently passed. A binary file starting with the DER SEQUENCE byte
(`0x30`) is tried as a certificate whatever its extension. A file with
a certificate extension (`.der` / `.crt` / `.cer`) that fails to parse,
and any `BEGIN CERTIFICATE` block with a non-base64 body, legacy PEM
headers, or a missing `END` line, produces a **warning**.

### Blessing intentional fixtures: `expiry-radar.ignore`

Some expired artefacts are *supposed* to be expired: auth negative-test
fixtures, TLS expired-cert test data, VCR cassettes. Put an
`expiry-radar.ignore` file in the scan root — one glob or substring
pattern per line, `#` comments — and matching paths are listed as
unscanned instead of flagged:

```
# negative tests rely on an expired token
tests/fixtures/negative/
cassettes/
```

Paths containing `cassettes/` are deliberately **not** auto-suppressed:
a cassette directory can also hold a live token someone committed by
accident. The ignore file is the explicit, reviewable answer. This
repo ships one for its own test corpus.

## GitHub Action

```yaml
- uses: actions/checkout@v4
- uses: RakTikoo/expiry-radar@v1   # placeholder until published — see examples/
```

Or copy [`examples/expiry-radar.yml`](examples/expiry-radar.yml) into
`.github/workflows/`: it runs weekly, and opens/updates **one** tracking
issue titled **⏰ Expiry Radar** with the current report (checking for the
existing issue first with `gh issue list`), closing it when the repo is
clean again.

## MVP scope — what is NOT in v1

- **No live-endpoint probing.** Nothing connects to your servers; only
  artefacts *in the repo* are read.
- **No renewal.** It never mints, rotates, or replaces certificates or
  tokens. It tells you the date; fixing it is your job.
- **No SaaS / hosted anything.** No accounts, no dashboards, no telemetry.
- **No general secret scanning.** A JWT is reported for its `exp`, not as
  a leaked secret; API keys, passwords, etc. are other tools' job
  (gitleaks, SkillScan, …).
- **No signature verification** of certs or JWTs, no chain building, no
  revocation checks.
- **Date formats:** ISO `YYYY-MM-DD` only. Epoch timestamps, `MM/DD/YYYY`,
  and natural-language dates are out of scope for v1.
- **DER** is recognised only as a whole file (any extension, if the
  file starts with the DER SEQUENCE byte `0x30`), not embedded in other
  binary blobs; binary files are otherwise not text-scanned and are
  listed as unscanned (measured reasoning in ANALYSIS.md).

## Tests & fixtures

```bash
python3 make_fixtures.py   # regenerate the fixture corpus (needs openssl CLI)
python3 run_tests.py       # 61 tests, stdlib unittest, zero dependencies
```

The corpus comes first in this project: 22 cases under
[`fixtures/`](fixtures/) — clean cases that must produce zero findings,
one planted fault per case, and edge cases (binary blobs, malformed
PEM/JWT, a 6 MiB file, unicode + spaces in filenames, chained PEMs).
Each case's `case.json` states its expected findings, safe count and exit
code. Measured precision/recall and a hand-labelled real-world run are in
[ANALYSIS.md](ANALYSIS.md).

A note on the expired-cert fixture: `openssl` cannot mint a certificate
with a past `notAfter`, so that case ships a 30-day cert and its
`case.json` sets `--now` 60 days after generation — expired by the
scanner's clock, which is what the test exercises. Genuinely past
artefacts need no simulation and are included for real (a JWT with
`exp` in 2020, literal past fixture dates).

## Security

Static analysis only; see [SECURITY.md](SECURITY.md).

## License

MIT — see [LICENSE](LICENSE).
