# Security

## What Expiry Radar does with your code

Expiry Radar is a **static, read-only** scanner:

- It reads scanned files as bytes. It **never executes, imports, or
  evaluates** scanned code, and never follows symlinks (symlinked files are
  reported as unscanned).
- It makes **no network calls**, needs no account or token, and sends
  nothing anywhere. The CLI is a single stdlib-only Python file.
- **JWTs are never printed in full.** Evidence is redacted to the first
  8 characters plus an ellipsis, and the `iss` / `sub` / `aud` claims
  are never printed at all. Fixture-date evidence lines have JWT-shaped
  substrings and `key=value`-style secret values masked with `***`
  *before* the 80-char truncation. Certificate subjects/issuers are
  printed because they are the finding — do not commit real production
  certificates or tokens and expect them to stay private; rotate
  anything real that you find.
- **Report injection is blunted:** every attacker-controlled string in
  the text report (subjects, issuers, paths, evidence, warnings) has
  C0 control characters (including newline, carriage return and ESC)
  stripped, and detail/subject/issuer strings are capped at 120 chars,
  so a crafted certificate or filename cannot forge report lines or
  terminal escapes.
- **No hangs by construction:** non-regular files (FIFOs, devices,
  sockets) are never opened — they are listed as unscanned via `lstat`
  first — and regular files are read with a bounded read of the size
  cap + 1 byte. JWT scanning is a linear pass (no backtracking regex),
  decoded JWT segments are capped at 64 KB, and OID arcs are capped at
  16 encoded bytes, so crafted blobs cannot stall or crash the scanner
  (deeply nested JWT JSON yields a warning, not a RecursionError).
- Files larger than 5 MiB are **not silently passed**: they are listed
  under `unscanned` in both text and JSON output. The same goes for
  binary files that are not whole-file DER certificates, symlinks,
  submodule entries, and paths matched by `expiry-radar.ignore`.
- JWT signatures are **not** verified (documented in the README) — the
  tool reads the `exp` claim of tokens that are already committed, which
  is the expiry question; it does not authenticate them.

## Reporting a vulnerability

This is a local pre-release build. If you find a problem — e.g. a crafted
file that makes the scanner crash, hang, read outside the scanned tree, or
print an unredacted token — please open an issue in this repository with a
minimal reproducer file. There is no hosted service and no user data at
risk; the worst realistic impact is a wrong or missed expiry report.
