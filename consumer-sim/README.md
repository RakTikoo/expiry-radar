# Consumer simulation — LOCAL EVIDENCE ONLY

**This is a simulation.** Nothing here ran on GitHub: no tag was cut, no
issue was opened, no workflow executed on a runner. It exists to prove,
locally, that a consumer repo can install and run Expiry Radar the way
the documentation describes, and to show exactly what the weekly
workflow's living issue would contain.

## What it contains

- `repo/` — a throwaway consumer repository:
  - `.github/workflows/expiry-radar.yml` — the example weekly workflow,
    copied verbatim from `examples/expiry-radar.yml`. Per that file's own
    instructions for the pre-publication form, the scanner is vendored:
    `repo/expiry_radar.py` is an unmodified copy of the v0.2 CLI. (After
    a release, consumers replace the vendored step with
    `uses: RakTikoo/expiry-radar@v0.2` — see RELEASE_NOTES.md.)
  - `certs/api.pem` — a certificate expiring ~30 days after the sim was
    built (planted: must be reported *expiring*).
  - `tests/auth_tokens.py` — a JWT with `exp` in 2020 (planted: must be
    reported *expired*).
- `run_simulation.sh` — rebuilds `repo/` and re-runs the simulation,
  writing fresh evidence. Safe to re-run; the cert is re-minted each
  time so "expiring" stays true.
- `evidence/` — the outputs of the run:
  - `expiry-radar.json` — the single scanner run (`--json`), exactly as
    the workflow produces it.
  - `expiry-radar-report.txt` — the text report rendered **from that
    JSON** by the same code the workflow embeds (the two formats cannot
    disagree, by construction).
  - `issue-body.md` — the body the workflow would create/update the
    single "⏰ Expiry Radar" issue with (label `expiry-radar`).
  - `simulation-log.txt` — the exit-code semantics, demonstrated:
    the scan's exit 2 is *findings* (issue updated), and a deliberately
    broken invocation (`--days banana`) exits 3, which the workflow
    treats as a broken invocation and fails on — never as findings.

## Result of the recorded run

See `evidence/simulation-log.txt`. Expected: exit code 2, exactly two
findings (1 expired JWT, 1 expiring certificate), issue body containing
the rendered report.
