#!/usr/bin/env python3
"""Regenerate the fixture corpus under fixtures/ — deterministically in
*relative* terms: every case's ``case.json`` records the ``--now`` date its
expectations are stated against, derived from the generation date, so the
corpus stays correct whenever it is regenerated.

Certificates are minted with the ``openssl`` CLI (required for fixture
generation only — the scanner itself is stdlib-only and never shells out
to openssl). Private keys are generated in a temp dir and deleted; only
certificates are committed as fixtures.

Expired certificates: ``openssl req -x509`` cannot mint a cert with a past
``notAfter`` (``-days`` must be positive). Instead the "expired cert" case
ships a short-lived (30-day) cert and its ``case.json`` sets ``--now``
60 days after generation — by the scanner's clock, which is the clock
that matters for the test, the cert *is* expired. Genuinely-past artefacts
that need no simulation are covered for real: the expired JWT has
``exp`` in 2020 and the past fixture dates are literal past dates.

JWTs are hand-crafted (unsigned payloads with a dummy signature segment):
Expiry Radar decodes ``exp`` without checking signatures, by design.

Run:  python3 make_fixtures.py
"""

from __future__ import annotations

import base64
import json
import os
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timedelta, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
FIXTURES = os.path.join(HERE, "fixtures")
GEN_DATE = datetime.now(timezone.utc).date()


def b64url(obj) -> str:
    raw = json.dumps(obj, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def make_jwt(exp: datetime, extra=None) -> str:
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {"sub": "fixture-user", "iss": "expiry-radar-fixtures",
               "exp": int(exp.replace(tzinfo=timezone.utc).timestamp())}
    if extra:
        payload.update(extra)
    return f"{b64url(header)}.{b64url(payload)}.fixture-signature-not-real"


def make_cert(days: int, cn: str) -> tuple[bytes, bytes]:
    """Return (pem_bytes, der_bytes) for a self-signed cert valid `days`."""
    if shutil.which("openssl") is None:
        raise SystemExit("make_fixtures.py needs the openssl CLI "
                         "(fixture generation only, not the scanner)")
    with tempfile.TemporaryDirectory() as tmp:
        pem = os.path.join(tmp, "cert.pem")
        der = os.path.join(tmp, "cert.der")
        subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
             "-keyout", os.path.join(tmp, "key.pem"), "-out", pem,
             "-days", str(days), "-subj", f"/CN={cn}/O=Expiry Radar Fixtures",
             "-addext", "basicConstraints=critical,CA:FALSE"],
            check=True, capture_output=True)
        subprocess.run(
            ["openssl", "x509", "-in", pem, "-outform", "DER", "-out", der],
            check=True, capture_output=True)
        with open(pem, "rb") as fh:
            pem_bytes = fh.read()
        with open(der, "rb") as fh:
            der_bytes = fh.read()
    return pem_bytes, der_bytes


def write_case(dirname: str, files: dict, case: dict):
    path = os.path.join(FIXTURES, dirname)
    os.makedirs(path, exist_ok=True)
    for rel, content in files.items():
        full = os.path.join(path, rel)
        os.makedirs(os.path.dirname(full), exist_ok=True)
        mode = "wb" if isinstance(content, bytes) else "w"
        with open(full, mode) as fh:
            fh.write(content)
    case.setdefault("now", GEN_DATE.isoformat())
    case.setdefault("days", 90)
    with open(os.path.join(path, "case.json"), "w") as fh:
        json.dump(case, fh, indent=2)
        fh.write("\n")
    print(f"  {dirname}: {case['description']}")


def d(offset_days: int) -> str:
    return (GEN_DATE + timedelta(days=offset_days)).isoformat()


def epoch(offset_days: int) -> int:
    """Epoch-seconds for midnight UTC on GEN_DATE + offset_days."""
    return int(datetime.combine(
        GEN_DATE + timedelta(days=offset_days),
        datetime.min.time()).replace(tzinfo=timezone.utc).timestamp())


def openssl_stamp(offset_days: int) -> str:
    """An openssl-style timestamp (space-padded day) for GEN + offset."""
    when = GEN_DATE + timedelta(days=offset_days)
    return (f"{when.strftime('%b')} {when.day:2d} 00:00:00 "
            f"{when.year} GMT")


def main() -> int:
    readme_path = os.path.join(FIXTURES, "README.md")
    readme = None
    if os.path.exists(readme_path):
        with open(readme_path) as fh:
            readme = fh.read()
    if os.path.isdir(FIXTURES):
        shutil.rmtree(FIXTURES)
    os.makedirs(FIXTURES)
    if readme is not None:
        with open(readme_path, "w") as fh:
            fh.write(readme)
    print(f"Generating fixtures (generation date {GEN_DATE.isoformat()}):")

    far_pem, _ = make_cert(3650, "far-future.example.test")
    soon_pem, soon_der = make_cert(30, "expiring-soon.example.test")
    soon2_pem, _ = make_cert(45, "second-chain.example.test")
    far2_pem, _ = make_cert(3650, "chain-root.example.test")

    far_jwt = make_jwt(datetime(2036, 1, 1))
    expired_jwt = make_jwt(datetime(2020, 1, 1))
    soon_jwt = make_jwt(datetime.combine(
        GEN_DATE + timedelta(days=25), datetime.min.time()))

    # ---- clean cases: must produce ZERO findings -------------------------
    write_case("clean_no_artefacts", {
        "app.py": '"""A plain module."""\n\ndef add(a, b):\n    return a + b\n',
        "notes.txt": "Nothing date-bearing lives here.\n",
    }, {"description": "clean: no certs, JWTs or dates at all",
        "expected_findings": [], "expected_safe": 0, "expected_exit": 0})

    write_case("clean_cert_far_future", {
        "certs/server.pem": far_pem,
    }, {"description": "clean: cert expiring in ~10 years is safe",
        "expected_findings": [], "expected_safe": 1, "expected_exit": 0})

    write_case("clean_jwt_far_future", {
        "tokens.txt": f"fixture token: {far_jwt}\n",
    }, {"description": "clean: JWT with exp in 2036 is safe",
        "expected_findings": [], "expected_safe": 1, "expected_exit": 0})

    write_case("clean_fixture_date_far_future", {
        "testdata/token.json": '{\n  "valid_until": "2035-01-01",\n'
                               '  "user": "fixture-user"\n}\n',
    }, {"description": "clean: fixture valid-until date far in the future",
        "expected_findings": [], "expected_safe": 1, "expected_exit": 0})

    write_case("clean_changelog_historical_dates", {
        "CHANGELOG.md": "# Changelog\n\n## 2020-01-01\n- First release.\n\n"
                        "## 2019-05-17\n- Project started.\n",
        "docs/guide.md": "The format was introduced on 2018-03-04.\n",
    }, {"description": "clean: historical dates in changelog/docs are "
                        "history, not expiry fixtures",
        "expected_findings": [], "expected_safe": 0, "expected_exit": 0})

    write_case("clean_stamp_dates_in_samples", {
        "samples/good/led-board.kicad_sch":
            '(kicad_sch (version 20230121)\n'
            '  (title_block (title "LED Board") (date "2026-11-09")'
            ' (rev "A"))\n)\n',
        "samples/data.json": '{\n  "recorded_on": "2024-03-01",\n'
                             '  "subject_dob": "1990-06-15"\n}\n',
    }, {"description": "clean: stamp/record dates in sample paths — a "
                        "KiCad title-block drawing date and a recorded-on "
                        "date carry no validity cue (regression case from "
                        "the real-world KiCad run, see ANALYSIS.md)",
        "expected_findings": [], "expected_safe": 0, "expected_exit": 0})

    write_case("clean_chained_pem_far_future", {
        "certs/chain.pem": far_pem + far2_pem,
    }, {"description": "clean: chained PEM with two far-future certs",
        "expected_findings": [], "expected_safe": 2, "expected_exit": 0})

    write_case("clean_epoch_safe", {
        "config/settings.py":
            f"SESSION_EXPIRES_AT = {epoch(3000)}  # far future\n",
    }, {"description": "clean (v0.2): epoch expires_at far in the future "
                        "is safe",
        "expected_findings": [], "expected_safe": 1, "expected_exit": 0})

    write_case("clean_epoch_traps", {
        "config/limits.py":
            "CACHE_TTL = 3600\nSESSION_TTL_SECONDS = 86400\n"
            "EXPIRY_CHECK_INTERVAL = 300\n",
        "testdata/auth.json":
            '{\n  "expires_in": 7200,\n  "exp": 3600,\n'
            '  "created_at": 1577836800,\n  "updated_at": 1600000000,\n'
            '  "expires_at": 1767225600000,\n'
            '  "token_expires_at_ms": 1767225600000\n}\n',
    }, {"description": "clean (v0.2): epoch FP traps — ttl durations, "
                        "OAuth expires_in seconds, a sub-plausibility "
                        "exp value, created_at/updated_at timestamps and "
                        "millisecond epochs must NOT flag",
        "expected_findings": [], "expected_safe": 0, "expected_exit": 0})

    write_case("clean_jwk_without_exp", {
        "keys/jwks.json":
            '{\n  "keys": [\n'
            '    {"kty": "RSA", "kid": "sim-a", "use": "sig"},\n'
            '    {"kty": "EC", "kid": "sim-b", "use": "sig"}\n  ]\n}\n',
    }, {"description": "clean (v0.2): JWKS whose keys carry no exp field",
        "expected_findings": [], "expected_safe": 0, "expected_exit": 0})

    write_case("clean_openssl_dates", {
        "certs/openssl-dates.txt":
            "notBefore=Jan 15 00:00:00 2025 GMT\n"
            "notAfter=Jan 15 00:00:00 2049 GMT\n",
        "certs/inspect.txt":
            "Validity\n    Not Before: Jan 15 00:00:00 2025 GMT\n",
    }, {"description": "clean (v0.2): openssl output — a past notBefore "
                        "is a start date, not an expiry; a 2049 notAfter "
                        "is safe",
        "expected_findings": [], "expected_safe": 1, "expected_exit": 0})

    # ---- one planted fault per case --------------------------------------
    write_case("fault_cert_expired", {
        "certs/server.pem": soon_pem,
    }, {"description": "fault: cert expired (30d cert, --now is +60d — see "
                        "module docstring for why expiry is simulated "
                        "through --now)",
        "now": d(60),
        "expected_findings": [{"kind": "certificate", "status": "expired"}],
        "expected_safe": 0, "expected_exit": 2})

    write_case("fault_cert_expiring_30d", {
        "certs/server.pem": soon_pem,
    }, {"description": "fault: cert expiring within 30 days of generation",
        "expected_findings": [{"kind": "certificate", "status": "expiring"}],
        "expected_safe": 0, "expected_exit": 1})

    write_case("fault_cert_der_expiring", {
        "certs/server.der": soon_der,
    }, {"description": "fault: whole-file DER cert expiring within 30 days",
        "expected_findings": [{"kind": "certificate", "status": "expiring"}],
        "expected_safe": 0, "expected_exit": 1})

    write_case("fault_jwt_expired_2020", {
        "tests/fixtures/auth.py": f'TOKEN = "{expired_jwt}"\n',
    }, {"description": "fault: genuinely expired JWT (exp 2020-01-01)",
        "expected_findings": [{"kind": "jwt", "status": "expired"}],
        "expected_safe": 0, "expected_exit": 2})

    write_case("fault_jwt_expiring_soon", {
        "tokens.txt": f"session: {soon_jwt}\n",
    }, {"description": "fault: JWT expiring 25 days after generation",
        "expected_findings": [{"kind": "jwt", "status": "expiring"}],
        "expected_safe": 0, "expected_exit": 1})

    write_case("fault_fixture_date_past", {
        "tests/fixtures/token.json": '{\n  "valid_until": "2025-01-15",\n'
                                     '  "user": "fixture-user"\n}\n',
    }, {"description": "fault: fixture valid-until date in the past",
        "expected_findings": [{"kind": "fixture-date", "status": "expired"}],
        "expected_safe": 0, "expected_exit": 2})

    write_case("fault_fixture_date_expiring", {
        "testdata/session.json":
            '{\n  "note": "regenerate before ' + d(20) + '",\n'
            '  "expires": "' + d(20) + '"\n}\n',
    }, {"description": "fault: fixture dates 20 days after generation "
                        "(two dates on two lines = two findings)",
        "expected_findings": [{"kind": "fixture-date", "status": "expiring"},
                              {"kind": "fixture-date", "status": "expiring"}],
        "expected_safe": 0, "expected_exit": 1})

    write_case("fault_valid_until_key_in_code", {
        "src/config.py": 'LICENSE_VALID_UNTIL = "2020-06-01"  # checked at boot\n',
    }, {"description": "fault: expiry-key date outside a fixture path "
                        "(the date-like-key rule)",
        "expected_findings": [{"kind": "fixture-date", "status": "expired"}],
        "expected_safe": 0, "expected_exit": 2})

    write_case("fault_multiple_certs_one_file", {
        "certs/bundle.pem": far_pem + soon2_pem,
    }, {"description": "fault: chained PEM — one far-future (safe), one "
                        "expiring in 45 days (finding)",
        "expected_findings": [{"kind": "certificate", "status": "expiring"}],
        "expected_safe": 1, "expected_exit": 1})

    write_case("fault_expired_and_expiring_mix", {
        "tests/testdata.txt": f"old: {expired_jwt}\n",
        "certs/server.pem": soon_pem,
    }, {"description": "fault: expired JWT + expiring cert — exit 2 wins",
        "expected_findings": [{"kind": "jwt", "status": "expired"},
                              {"kind": "certificate", "status": "expiring"}],
        "expected_safe": 0, "expected_exit": 2})

    write_case("fault_epoch_expired", {
        "testdata/session.json":
            '{\n  "user": "fixture-user",\n'
            '  "expires_at": 1577836800\n}\n',
    }, {"description": "fault (v0.2): epoch expires_at in the past "
                        "(2020-01-01)",
        "expected_findings": [{"kind": "epoch-expiry",
                               "status": "expired"}],
        "expected_safe": 0, "expected_exit": 2})

    write_case("fault_epoch_expiring", {
        "config/app.env": f"TOKEN_EXPIRES_AT={epoch(20)}\n",
    }, {"description": "fault (v0.2): .env-style epoch expiry 20 days "
                        "after generation",
        "expected_findings": [{"kind": "epoch-expiry",
                               "status": "expiring"}],
        "expected_safe": 0, "expected_exit": 1})

    write_case("fault_jwk_expired", {
        "keys/jwks.json":
            '{\n  "keys": [\n'
            '    {"kty": "RSA", "kid": "sim-old", "use": "sig",\n'
            '     "n": "sXchDaQebHnPiGvyDOAT4saGEUetSyo9MKLOoWFsueri",\n'
            '     "exp": 1577836800},\n'
            '    {"kty": "EC", "kid": "sim-current", "use": "sig"}\n'
            '  ]\n}\n',
    }, {"description": "fault (v0.2): JWKS key with exp in 2020; the "
                        "second key has no exp and stays silent; reported "
                        "once as a JWK finding, not double-counted as an "
                        "epoch finding",
        "expected_findings": [{"kind": "jwk-expiry", "status": "expired"}],
        "expected_safe": 0, "expected_exit": 2})

    write_case("fault_jwk_expiring", {
        "keys/signing.json":
            '{\n  "kty": "RSA", "kid": "sim-next", "use": "sig",\n'
            f'  "exp": {epoch(15)}\n}}\n',
    }, {"description": "fault (v0.2): single JWK object with exp 15 days "
                        "after generation",
        "expected_findings": [{"kind": "jwk-expiry",
                               "status": "expiring"}],
        "expected_safe": 0, "expected_exit": 1})

    write_case("fault_openssl_expired", {
        "certs/openssl-dates.txt":
            "notBefore=Dec 10 00:00:00 2024 GMT\n"
            "notAfter=Jan 15 23:59:59 2025 GMT\n",
    }, {"description": "fault (v0.2): committed openssl -dates output "
                        "with a past notAfter (the notBefore line must "
                        "not flag)",
        "expected_findings": [{"kind": "openssl-expiry",
                               "status": "expired"}],
        "expected_safe": 0, "expected_exit": 2})

    write_case("fault_openssl_text_expiring", {
        "certs/inspect.txt":
            "Certificate:\n    Data:\n        Validity\n"
            "            Not Before: " + openssl_stamp(-300) + "\n"
            "            Not After : " + openssl_stamp(30) + "\n",
    }, {"description": "fault (v0.2): openssl -text Validity block with "
                        "notAfter 30 days after generation",
        "expected_findings": [{"kind": "openssl-expiry",
                               "status": "expiring"}],
        "expected_safe": 0, "expected_exit": 1})

    # ---- edge cases --------------------------------------------------------
    write_case("edge_binary_certlike_bytes", {
        "blob.bin": b"\x00\x01\x02-----BEGIN CERTIFICATE-----\n"
                    b"MIIBszCCARagAwIBAgIU\x00\xff\xfe random bytes\n"
                    b"-----END CERTIFICATE-----\x00\x03",
    }, {"description": "edge: binary blob with cert-like bytes — binary "
                        "files are only trusted as whole-file DER, so zero "
                        "findings and no crash; the blob is listed as "
                        "unscanned (binary — not searched)",
        "expected_findings": [], "expected_safe": 0, "expected_exit": 0,
        "expected_unscanned": ["blob.bin"]})

    write_case("edge_malformed_jwt", {
        "tokens.txt": "almost: eyJhbGciOiJIUzI1NiJ9.not-json-payload."
                      "siggy\nrandom: aaaaaaaaaa.bbbbbbbbbb.ccccc\n",
    }, {"description": "edge: JWT-shaped strings whose payload is not "
                        "JSON / whose header has no alg — not findings",
        "expected_findings": [], "expected_safe": 0, "expected_exit": 0})

    write_case("edge_malformed_pem", {
        "certs/broken.pem": "-----BEGIN CERTIFICATE-----\n"
                            "!!!not-base64!!!\n"
                            "-----END CERTIFICATE-----\n"
                            "-----BEGIN CERTIFICATE-----\n"
                            "AQIDBA==\n"
                            "-----END CERTIFICATE-----\n",
    }, {"description": "edge: malformed PEM blocks — warnings, no crash, "
                        "no findings",
        "expected_findings": [], "expected_safe": 0, "expected_exit": 0,
        "expected_warnings_min": 1})

    huge = b"A" * (6 * 1024 * 1024) + b"\n" + expired_jwt.encode() + b"\n"
    write_case("edge_huge_file", {
        "big.txt": huge,
        "small.txt": "nothing here\n",
    }, {"description": "edge: 6MiB file exceeds the 5MiB cap — listed as "
                        "unscanned (its expired JWT must NOT be silently "
                        "passed, nor found)",
        "expected_findings": [], "expected_safe": 0, "expected_exit": 0,
        "expected_unscanned": ["big.txt"]})

    write_case("edge_unicode_and_spaces_filename", {
        "my ünïcode file.txt": f"token: {expired_jwt}\n",
    }, {"description": "edge: filename with spaces and unicode, containing "
                        "an expired JWT",
        "expected_findings": [{"kind": "jwt", "status": "expired"}],
        "expected_safe": 0, "expected_exit": 2})

    write_case("edge_jwks_malformed", {
        "keys/jwks.json":
            '{"keys": [{"kty": "RSA", "kid": "sim-broken", '
            '"exp": "soon"},\n',
    }, {"description": "edge (v0.2): file named as JWKS but its JSON is "
                        "truncated — a warning (the name claims JWKS), "
                        "no findings, no crash",
        "expected_findings": [], "expected_safe": 0, "expected_exit": 0,
        "expected_warnings_min": 1})

    print("Done. Corpus expectations are in each case's case.json.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
