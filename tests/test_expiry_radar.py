#!/usr/bin/env python3
"""Expiry Radar tests: unit tests + an end-to-end corpus run.

The corpus test copies each fixtures/<case>/ directory to a temp dir
*without* its case.json (harness metadata, not fixture content), runs the
scanner with that case's --now/--days, and checks findings, safe counts,
exit code and unscanned files exactly against case.json.

Run:  python3 run_tests.py        (stdlib unittest, zero dependencies)
"""
import base64
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from datetime import datetime, timezone
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

import expiry_radar as er  # noqa: E402

NOW = datetime(2026, 11, 10, tzinfo=timezone.utc)


def jwt_with_exp(exp_ts):
    def b64(obj):
        raw = json.dumps(obj, separators=(",", ":")).encode()
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()
    return (f"{b64({'alg': 'HS256', 'typ': 'JWT'})}."
            f"{b64({'sub': 'x', 'exp': exp_ts})}.sig")


def load_cert_pem():
    path = os.path.join(ROOT, "fixtures", "fault_cert_expiring_30d",
                        "certs", "server.pem")
    with open(path, "rb") as fh:
        return fh.read()


class TestDerParser(unittest.TestCase):
    def test_parse_real_cert(self):
        pem = load_cert_pem()
        b64 = er.PEM_RE.search(pem).group(1)
        der = base64.b64decode(b"".join(b64.split()))
        info = er.parse_certificate_der(der)
        self.assertEqual(info.subject.split(",")[0],
                         "CN=expiring-soon.example.test")
        self.assertEqual(info.subject, info.issuer)  # self-signed fixture
        # 30-day cert minted 2026-11-10 -> notAfter in early Dec 2026
        self.assertEqual((info.not_after.year, info.not_after.month), (2026, 12))
        self.assertLess(info.not_before, info.not_after)

    def test_utc_and_generalized_time(self):
        self.assertEqual(er._parse_time(0x17, b"260101000000Z"),
                         datetime(2026, 1, 1, tzinfo=timezone.utc))
        self.assertEqual(er._parse_time(0x17, b"991231235959Z"),
                         datetime(1999, 12, 31, 23, 59, 59, tzinfo=timezone.utc))
        self.assertEqual(er._parse_time(0x18, b"20360101000000Z"),
                         datetime(2036, 1, 1, tzinfo=timezone.utc))

    def test_garbage_der_rejected(self):
        for bad in (b"", b"not a cert", b"\x30\x03\x02\x01\x05", b"\x30\x82"):
            with self.assertRaises((er.DerError, ValueError)):
                er.parse_certificate_der(bad)


class TestClassify(unittest.TestCase):
    def test_boundaries(self):
        self.assertEqual(er.classify(datetime(2026, 11, 9, tzinfo=timezone.utc), NOW, 90)[0], "expired")
        self.assertEqual(er.classify(datetime(2026, 11, 10, 12, tzinfo=timezone.utc), NOW, 90)[0], "expiring")
        self.assertEqual(er.classify(datetime(2027, 2, 7, tzinfo=timezone.utc), NOW, 90)[0], "expiring")
        self.assertEqual(er.classify(datetime(2027, 2, 8, tzinfo=timezone.utc), NOW, 90)[0], "safe")
        self.assertEqual(er.classify(datetime(2027, 2, 8, tzinfo=timezone.utc), NOW, 30)[0], "safe")
        self.assertEqual(er.classify(datetime(2026, 12, 1, tzinfo=timezone.utc), NOW, 30)[0], "expiring")


class TestJwt(unittest.TestCase):
    def test_expired_and_far_future(self):
        expired = er.scan_jwts(jwt_with_exp(1577836800).encode(), "t.txt", NOW, 90, [])
        self.assertEqual([(f.status, f.days_left) for f in expired], [("expired", -2505)])
        self.assertEqual(expired[0].evidence, "eyJhbGci…")  # redacted, 8 chars
        self.assertNotIn("eyJhbGciOi", expired[0].evidence.replace("…", ""))
        far = er.scan_jwts(jwt_with_exp(2082758400).encode(), "t.txt", NOW, 90, [])
        self.assertEqual(far[0].status, "safe")

    def test_malformed_and_no_exp_are_not_findings(self):
        junk = b"eyJhbGciOiJIUzI1NiJ9.not-json.sig aaaaaaaaaa.bbbbbbbbbb.ccccc"
        self.assertEqual(er.scan_jwts(junk, "t.txt", NOW, 90, []), [])
        # A well-formed JWT with no exp claim at all is not an expiry finding.
        def b64u(obj):
            raw = json.dumps(obj, separators=(",", ":")).encode()
            return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()
        no_exp = (f"{b64u({'alg': 'HS256'})}.{b64u({'sub': 'x'})}.sig")
        self.assertEqual(er.scan_jwts(no_exp.encode(), "t.txt", NOW, 90, []), [])
        # Header without alg is not treated as a JWT.
        def b64(obj):
            raw = json.dumps(obj, separators=(",", ":")).encode()
            return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()
        token = f"{b64({'typ': 'JWT'})}.{b64({'exp': 1577836800})}.sig"
        self.assertEqual(er.scan_jwts(token.encode(), "t.txt", NOW, 90, []), [])


class TestDates(unittest.TestCase):
    def test_fixture_path_flagged(self):
        found = er.scan_dates('{"valid_until": "2020-01-01"}\n',
                              "tests/fixtures/x.json", NOW, 90)
        self.assertEqual([(f.status, f.kind) for f in found],
                         [("expired", "fixture-date")])

    def test_doc_files_exempt(self):
        self.assertEqual(er.scan_dates("## 2020-01-01\n- release\n",
                                       "CHANGELOG.md", NOW, 90), [])
        self.assertEqual(er.scan_dates("Introduced on 2019-05-17.\n",
                                       "docs/guide.md", NOW, 90), [])

    def test_expiry_key_outside_fixture_path(self):
        found = er.scan_dates('LICENSE_VALID_UNTIL = "2020-06-01"\n',
                              "src/config.py", NOW, 90)
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].status, "expired")

    def test_prose_word_and_plain_dates_not_flagged(self):
        # A sentence mentioning expiry + a date is narration, not a field.
        self.assertEqual(er.scan_dates("This token expired in 2020-01-01.\n",
                                       "src/main.py", NOW, 90), [])
        self.assertEqual(er.scan_dates("x = 2020-01-01  # release date\n",
                                       "src/main.py", NOW, 90), [])
        # A date today is expiring, not expired; a far date is safe.
        found = er.scan_dates('expires: "2026-11-10"\n', "src/main.py", NOW, 90)
        self.assertEqual(found[0].status, "expiring")
        self.assertEqual(found[0].days_left, 0)
        found = er.scan_dates('expires: "2030-01-01"\n', "src/main.py", NOW, 90)
        self.assertEqual(found[0].status, "safe")

    def test_invalid_dates_ignored(self):
        self.assertEqual(er.scan_dates('expires: "2026-02-30"\n',
                                       "tests/f.json", NOW, 90), [])


class TestCorpus(unittest.TestCase):
    """Every fixtures/<case> must match its case.json exactly."""

    @staticmethod
    def cases():
        fixtures = os.path.join(ROOT, "fixtures")
        for name in sorted(os.listdir(fixtures)):
            path = os.path.join(fixtures, name)
            manifest = os.path.join(path, "case.json")
            if os.path.isdir(path) and os.path.exists(manifest):
                with open(manifest) as fh:
                    yield name, path, json.load(fh)

    def test_corpus(self):
        failures = []
        for name, path, case in self.cases():
            with self.subTest(case=name):
                with tempfile.TemporaryDirectory() as tmp:
                    dest = os.path.join(tmp, name)
                    shutil.copytree(path, dest,
                                    ignore=shutil.ignore_patterns("case.json"))
                    now = datetime.strptime(case["now"], "%Y-%m-%d").replace(
                        tzinfo=timezone.utc)
                    result = er.scan(dest, now=now, days=case.get("days", 90))
                    got = sorted(
                        (f.kind, f.status)
                        for f in result.expired + result.expiring)
                    want = sorted((f["kind"], f["status"])
                                  for f in case["expected_findings"])
                    if got != want:
                        failures.append(
                            f"{name}: findings {got} != expected {want}")
                    if len(result.safe) != case.get("expected_safe", 0):
                        failures.append(
                            f"{name}: safe {len(result.safe)} != "
                            f"expected {case.get('expected_safe', 0)}")
                    if result.exit_code() != case["expected_exit"]:
                        failures.append(
                            f"{name}: exit {result.exit_code()} != "
                            f"expected {case['expected_exit']}")
                    if sorted(u["path"] for u in result.unscanned) != sorted(
                            case.get("expected_unscanned", [])):
                        failures.append(
                            f"{name}: unscanned "
                            f"{[u['path'] for u in result.unscanned]} != "
                            f"expected {case.get('expected_unscanned', [])}")
                    if len(result.warnings) < case.get("expected_warnings_min", 0):
                        failures.append(
                            f"{name}: warnings {len(result.warnings)} < "
                            f"expected minimum {case['expected_warnings_min']}")
        self.assertEqual(failures, [], "\n".join(failures))


class TestCli(unittest.TestCase):
    def run_cli(self, *args):
        return subprocess.run([sys.executable,
                               os.path.join(ROOT, "expiry_radar.py"), *args],
                              capture_output=True, text=True, timeout=60)

    def test_exit_codes_and_json(self):
        base = os.path.join(ROOT, "fixtures")
        proc = self.run_cli(f"{base}/fault_jwt_expired_2020", "--now", "2026-11-10", "--json")
        self.assertEqual(proc.returncode, 2)
        data = json.loads(proc.stdout)
        self.assertEqual(data["summary"]["expired"], 1)
        self.assertEqual(data["exit_code"], 2)
        self.assertTrue(all("eyJ" not in json.dumps(f) or len(f.get("evidence", "")) <= 10
                            for f in data["findings"]))
        proc = self.run_cli(f"{base}/fault_cert_expiring_30d", "--now", "2026-11-10")
        self.assertEqual(proc.returncode, 1)
        proc = self.run_cli(f"{base}/clean_no_artefacts", "--now", "2026-11-10")
        self.assertEqual(proc.returncode, 0)
        self.assertIn("No expired or expiring", proc.stdout)

    def test_days_threshold_and_show_safe(self):
        base = os.path.join(ROOT, "fixtures")
        proc = self.run_cli(f"{base}/fault_cert_expiring_30d", "--now",
                            "2026-11-10", "--days", "10")
        self.assertEqual(proc.returncode, 0)  # 30d out is safe under a 10d window
        proc = self.run_cli(f"{base}/clean_cert_far_future", "--now",
                            "2026-11-10", "--show-safe")
        self.assertEqual(proc.returncode, 0)
        self.assertIn("SAFE", proc.stdout)

    def test_now_override_changes_classification(self):
        base = os.path.join(ROOT, "fixtures")
        # Same cert: expiring at generation date, expired 60 days later.
        self.assertEqual(
            self.run_cli(f"{base}/fault_cert_expired", "--now", "2026-11-10").returncode, 1)
        self.assertEqual(
            self.run_cli(f"{base}/fault_cert_expired", "--now", "2027-01-09").returncode, 2)

    def test_symlink_is_unscanned_not_followed(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = os.path.join(tmp, "real.txt")
            with open(target, "w") as fh:
                fh.write(jwt_with_exp(1577836800))
            os.symlink(target, os.path.join(tmp, "link.txt"))
            proc = self.run_cli(tmp, "--now", "2026-11-10", "--json")
            data = json.loads(proc.stdout)
            self.assertEqual(data["summary"]["expired"], 1)  # real file found
            self.assertEqual([u["path"] for u in data["unscanned"]], ["link.txt"])

    def test_git_repo_scans_tracked_files_only(self):
        if shutil.which("git") is None:
            self.skipTest("git not available")
        with tempfile.TemporaryDirectory() as tmp:
            def git(*a):
                subprocess.run(["git", "-C", tmp, *a], check=True,
                               capture_output=True)
            git("init", "-q")
            git("config", "user.email", "fixture@example.test")
            git("config", "user.name", "Fixture")
            with open(os.path.join(tmp, "tracked.txt"), "w") as fh:
                fh.write(jwt_with_exp(1577836800))
            git("add", "tracked.txt")
            git("commit", "-qm", "fixture")
            with open(os.path.join(tmp, "untracked.txt"), "w") as fh:
                fh.write(jwt_with_exp(1577836800))
            proc = self.run_cli(tmp, "--now", "2026-11-10", "--json")
            data = json.loads(proc.stdout)
            self.assertEqual(data["file_source"], "git")
            self.assertEqual(data["summary"]["expired"], 1)
            self.assertEqual(data["findings"][0]["path"], "tracked.txt")

    def test_non_directory_is_error(self):
        proc = self.run_cli("/does/not/exist")
        # T2: usage errors pin EXACTLY 3 — never 2 (2 means "expired").
        self.assertEqual(proc.returncode, 3)


# ----------------------------------------------------------------------
# Adversarial-review fix pass (regression tests, one group per finding)
# ----------------------------------------------------------------------

def b64u_of(obj_or_raw):
    raw = obj_or_raw if isinstance(obj_or_raw, bytes) else json.dumps(
        obj_or_raw, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def make_token(payload, header=None, sig="sig"):
    header = header if header is not None else {"alg": "HS256", "typ": "JWT"}
    return f"{b64u_of(header)}.{b64u_of(payload)}.{sig}"


EXPIRED_TOKEN = make_token({"sub": "x", "exp": 1577836800})


class TestUsageExitCodes(unittest.TestCase):
    """Fix 6/12: usage errors exit exactly 3, findings keep 0/1/2."""

    def run_cli(self, *args):
        return subprocess.run(
            [sys.executable, os.path.join(ROOT, "expiry_radar.py"), *args],
            capture_output=True, text=True, timeout=60)

    def test_usage_errors_are_3(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(self.run_cli(tmp, "--days", "-1").returncode, 3)
            self.assertEqual(self.run_cli(tmp, "--days", "abc").returncode, 3)
            self.assertEqual(
                self.run_cli(tmp, "--now", "not-a-date").returncode, 3)
            self.assertEqual(
                self.run_cli(tmp, "--max-file-size", "-1").returncode, 3)
            self.assertEqual(
                self.run_cli(tmp, "--bogus-flag").returncode, 3)
            self.assertEqual(self.run_cli(tmp).returncode, 0)  # clean dir

    def test_negative_max_file_size_api(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(ValueError):
                er.scan(tmp, now=NOW, max_file_size=-1)


class TestNonRegularFiles(unittest.TestCase):
    """Fix 1: FIFOs are never opened (they block forever); bounded read."""

    def test_fifo_is_unscanned_not_hung(self):
        if not hasattr(os, "mkfifo"):
            self.skipTest("no mkfifo")
        with tempfile.TemporaryDirectory() as tmp:
            with open(os.path.join(tmp, "real.txt"), "w") as fh:
                fh.write("nothing here\n")
            try:
                os.mkfifo(os.path.join(tmp, "pipe"))
            except OSError:
                self.skipTest("mkfifo not permitted")
            proc = subprocess.run(
                [sys.executable, os.path.join(ROOT, "expiry_radar.py"),
                 tmp, "--now", "2026-11-10", "--json"],
                capture_output=True, text=True, timeout=30)
            data = json.loads(proc.stdout)
            self.assertEqual(proc.returncode, 0)
            self.assertEqual([u["path"] for u in data["unscanned"]], ["pipe"])
            self.assertIn("not a regular file",
                          data["unscanned"][0]["reason"])

    def test_oversize_still_unscanned_with_small_cap(self):
        with tempfile.TemporaryDirectory() as tmp:
            with open(os.path.join(tmp, "f.txt"), "w") as fh:
                fh.write("x" * 100)
            result = er.scan(tmp, now=NOW, max_file_size=10)
            self.assertEqual(result.files_scanned, 0)
            self.assertEqual([u["path"] for u in result.unscanned], ["f.txt"])


class TestJwtPerformance(unittest.TestCase):
    """Fix 2/5: linear JWT scan; line numbers via precomputed bisect."""

    def test_dotless_base64_blob_is_fast(self):
        start = time.time()
        self.assertEqual(er.scan_jwts(b"A" * 100_000, "t.txt", NOW, 90, []),
                         [])
        self.assertLess(time.time() - start, 1.0)

    def test_many_copies_of_one_token_complete(self):
        data = ((EXPIRED_TOKEN + "\n") * 20_000).encode()
        start = time.time()
        found = er.scan_jwts(data, "t.txt", NOW, 90, [])
        elapsed = time.time() - start
        self.assertEqual(len(found), 20_000)
        self.assertEqual(found[-1].line, 20_000)  # bisect line index
        self.assertLess(elapsed, 10.0)

    def test_line_number_matches_naive_count(self):
        data = b"a\nbb\nccc\ndddd"
        offsets = er._newline_offsets(data)
        for off in range(len(data)):
            self.assertEqual(er._line_number(offsets, off),
                             er._line_of(data, off))


class TestJwtRobustness(unittest.TestCase):
    """Fixes 3 + 11: RecursionError, oversized segments, alg=none."""

    def test_deeply_nested_payload_warns_and_scan_continues(self):
        depth = 20000  # ~40 KB raw: under the 64 KB cap, past json's limit
        raw = b'{"exp":1577836800,"x":' + b"[" * depth + b"]" * depth + b"}"
        token = f"{b64u_of({'alg': 'HS256'})}.{b64u_of(raw)}.sig"
        warnings = []
        data = (token + "\n" + EXPIRED_TOKEN + "\n").encode()
        found = er.scan_jwts(data, "t.txt", NOW, 90, warnings)
        self.assertEqual(len(found), 1)  # the valid token after it
        self.assertTrue(any("deeply nested" in w for w in warnings))

    def test_oversized_payload_segment_warns(self):
        token = make_token({"exp": 1577836800, "blob": "A" * 70_000})
        warnings = []
        self.assertEqual(er.scan_jwts(token.encode(), "t.txt", NOW, 90,
                                      warnings), [])
        self.assertTrue(any("oversized" in w for w in warnings))

    def test_unsigned_alg_none_token(self):
        token = make_token({"exp": 1577836800}, header={"alg": "none"},
                           sig="")
        self.assertTrue(token.endswith("."))
        found = er.scan_jwts(token.encode(), "t.txt", NOW, 90, [])
        self.assertEqual([(f.kind, f.status) for f in found],
                         [("jwt", "expired")])

    def test_token_followed_by_sentence_period(self):
        data = f"Use {EXPIRED_TOKEN}. Then rotate it.\n".encode()
        self.assertEqual(len(er.scan_jwts(data, "t.txt", NOW, 90, [])), 1)


class TestOidAndTimes(unittest.TestCase):
    """Fixes 4 + 18: OID first-sub-identifier decoding, caps, UTCTime pivot."""

    def test_multi_byte_first_subidentifier(self):
        self.assertEqual(er._parse_oid(bytes([0x88, 0x37, 0x03])), "2.999.3")
        self.assertEqual(er._parse_oid(bytes([0x55, 0x04, 0x03])), "2.5.4.3")
        self.assertEqual(er._parse_oid(bytes([0x2A])), "1.2")

    def test_oid_caps(self):
        with self.assertRaises(er.DerError):  # one arc > 16 encoded bytes
            er._parse_oid(bytes([0x2A] + [0xFF] * 17 + [0x7F]))
        with self.assertRaises(er.DerError):  # whole OID > 64 bytes
            er._parse_oid(bytes([0x2A] * 65))
        with self.assertRaises(er.DerError):  # truncated arc
            er._parse_oid(bytes([0x88]))

    def test_utctime_pivot_boundaries(self):
        self.assertEqual(er._parse_time(0x17, b"491231235959Z"),
                         datetime(2049, 12, 31, 23, 59, 59,
                                  tzinfo=timezone.utc))
        self.assertEqual(er._parse_time(0x17, b"500101000000Z"),
                         datetime(1950, 1, 1, tzinfo=timezone.utc))


class TestDerAndPemWarnings(unittest.TestCase):
    """Fix 7: cert-extension DER failures and loose PEM problems warn."""

    def scan_tmp(self, files):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        for rel, content in files.items():
            full = os.path.join(tmp.name, rel)
            os.makedirs(os.path.dirname(full), exist_ok=True)
            mode = "wb" if isinstance(content, bytes) else "w"
            with open(full, mode) as fh:
                fh.write(content)
        return er.scan(tmp.name, now=NOW)

    def test_garbage_der_extension_warns(self):
        result = self.scan_tmp({"cert.der": "this is not a certificate"})
        self.assertEqual(result.findings, [])
        self.assertTrue(any("DER parse" in w for w in result.warnings))

    def test_binary_garbage_der_extension_warns(self):
        result = self.scan_tmp({"cert.der": b"\x30\x82\xff\xff\x00junk"})
        self.assertEqual(result.findings, [])
        self.assertTrue(any("DER parse" in w for w in result.warnings))

    def test_pem_text_crt_does_not_der_warn(self):
        result = self.scan_tmp({"cert.crt": load_cert_pem()})
        self.assertFalse(any("DER parse" in w for w in result.warnings))
        self.assertEqual(len([f for f in result.findings
                              if f.kind == "certificate"]), 1)

    def test_bad_pem_body_warns(self):
        result = self.scan_tmp({
            "broken.pem": "-----BEGIN CERTIFICATE-----\n"
                          "!!!not-base64!!!\n"
                          "-----END CERTIFICATE-----\n"})
        self.assertEqual(result.findings, [])
        self.assertTrue(any("non-base64" in w for w in result.warnings))

    def test_unterminated_pem_warns(self):
        result = self.scan_tmp({
            "broken.pem": "-----BEGIN CERTIFICATE-----\nAAAA\n"})
        self.assertTrue(any("unterminated" in w for w in result.warnings))

    def test_legacy_pem_headers_warn(self):
        result = self.scan_tmp({
            "old.pem": "-----BEGIN CERTIFICATE-----\n"
                       "Proc-Type: 4,ENCRYPTED\n\nAAAA\n"
                       "-----END CERTIFICATE-----\n"})
        self.assertTrue(any("legacy headers" in w for w in result.warnings))


class TestRedaction(unittest.TestCase):
    """Fix 8: claims never printed; evidence masked; T3 full-token check."""

    def test_jwt_claims_not_in_detail(self):
        token = make_token({
            "exp": 1577836800,
            "iss": "https://issuer.example.com/a/very/long/issuer",
            "sub": "user-secret-subject-1234567890",
            "aud": "my-private-audience-name",
        })
        found = er.scan_jwts(token.encode(), "t.txt", NOW, 90, [])
        self.assertEqual(len(found), 1)
        for secret in ("issuer.example.com", "user-secret-subject",
                       "private-audience"):
            self.assertNotIn(secret, found[0].detail)
            self.assertNotIn(secret, found[0].evidence)

    def test_fixture_evidence_masks_secrets(self):
        line = ('{"valid_until": "2020-01-01", '
                '"api_key": "supersecretvalue123456"}\n')
        found = er.scan_dates(line, "tests/fixtures/x.json", NOW, 90)
        self.assertEqual(len(found), 1)
        self.assertNotIn("supersecretvalue123456", found[0].evidence)
        self.assertIn("***", found[0].evidence)
        self.assertLessEqual(len(found[0].evidence), 80)

    def test_fixture_evidence_masks_embedded_jwt(self):
        line = f'{{"expires": "2020-01-01", "note": "{EXPIRED_TOKEN}"}}\n'
        found = er.scan_dates(line, "tests/fixtures/x.json", NOW, 90)
        self.assertEqual(len(found), 1)
        self.assertNotIn(EXPIRED_TOKEN, found[0].evidence)
        self.assertNotIn(EXPIRED_TOKEN[10:40], found[0].evidence)

    def test_full_token_nowhere_in_cli_output(self):  # T3
        with tempfile.TemporaryDirectory() as tmp:
            os.makedirs(os.path.join(tmp, "tests", "fixtures"))
            with open(os.path.join(tmp, "auth.txt"), "w") as fh:
                fh.write(EXPIRED_TOKEN + "\n")
            with open(os.path.join(tmp, "tests", "fixtures", "leak.json"),
                      "w") as fh:
                fh.write('{"expires": "2020-01-01", "note": "'
                         + EXPIRED_TOKEN + '"}\n')
            # A claims-bearing token too: iss/sub/aud must not leak either.
            claims_token = make_token({
                "exp": 1577836800, "iss": "https://issuer.example.com/x",
                "sub": "user-secret-subject-1234567890",
                "aud": "my-private-audience-name"})
            with open(os.path.join(tmp, "claims.txt"), "w") as fh:
                fh.write(claims_token + "\n")
            for extra in (["--json"], []):
                proc = subprocess.run(
                    [sys.executable, os.path.join(ROOT, "expiry_radar.py"),
                     tmp, "--now", "2026-11-10", *extra],
                    capture_output=True, text=True, timeout=60)
                out = proc.stdout + proc.stderr
                self.assertNotIn(EXPIRED_TOKEN, out)
                self.assertNotIn(EXPIRED_TOKEN[10:40], out)
                self.assertNotIn(claims_token, out)
                self.assertNotIn("user-secret-subject", out)
                self.assertNotIn("private-audience", out)
                self.assertNotIn("issuer.example.com", out)


class TestTextSanitisation(unittest.TestCase):
    """Fix 9: no control chars / injected lines / oversized details."""

    def test_render_text_sanitises_attacker_strings(self):
        result = er.ScanResult(root="/tmp/x", now=NOW, days=90)
        result.findings.append(er.Finding(
            kind="certificate", status="expired", path="evil\npath.pem",
            line=1, expires="2020-01-01", days_left=-100,
            detail="subject: CN=evil\n[EXPIRED] fake\x1b[31m " + "A" * 300,
            evidence="ev\x1bid"))
        result.warnings.append("warn\ninjected warning line")
        result.unscanned.append({"path": "a\rb", "reason": "x\x1by"})
        text = er.render_text(result)
        self.assertNotIn("\x1b", text)
        self.assertNotIn("\r", text)
        self.assertFalse(any(ln.startswith("[EXPIRED] fake")
                             for ln in text.splitlines()))
        self.assertFalse(any(ln == "injected warning line"
                             for ln in text.splitlines()))
        self.assertNotIn("A" * 200, text)  # detail capped at 120 chars


class TestBinaryHandling(unittest.TestCase):
    """Fix 10: binaries unscanned (not counted); 0x30 DER any extension."""

    def test_binary_with_embedded_jwt_is_unscanned(self):
        with tempfile.TemporaryDirectory() as tmp:
            with open(os.path.join(tmp, "blob.bin"), "wb") as fh:
                fh.write(b"\x00\x01" + EXPIRED_TOKEN.encode())
            result = er.scan(tmp, now=NOW)
            self.assertEqual(result.findings, [])
            self.assertEqual(result.files_scanned, 0)
            self.assertEqual(len(result.unscanned), 1)
            self.assertEqual(result.unscanned[0]["reason"],
                             "binary — not searched")

    def test_der_cert_with_bin_extension_is_found(self):
        src = os.path.join(ROOT, "fixtures", "fault_cert_der_expiring",
                           "certs", "server.der")
        with open(src, "rb") as fh:
            der = fh.read()
        self.assertEqual(der[:1], b"\x30")
        with tempfile.TemporaryDirectory() as tmp:
            with open(os.path.join(tmp, "cert.bin"), "wb") as fh:
                fh.write(der)
            result = er.scan(tmp, now=NOW)
            self.assertEqual([(f.kind, f.status) for f in result.findings],
                             [("certificate", "expiring")])
            self.assertEqual(result.files_scanned, 1)


class TestCueAndKeyPrecision(unittest.TestCase):
    """Fixes 13/14/15: cue word boundaries, expiry-only keys, attribution."""

    FIX = "tests/fixtures/x.json"

    def dates(self, line, rel="src/main.py"):
        return er.scan_dates(line + "\n", rel, NOW, 90)

    def test_cue_lookalikes_do_not_trigger(self):
        for line in ("invalid since 2020-01-01",
                     "validation completed 2020-01-01",
                     "renewable energy reading 2020-01-01",
                     "use before 2020-01-01",
                     "created before 2020-01-01"):
            self.assertEqual(self.dates(line, self.FIX), [], line)

    def test_real_cues_still_trigger(self):
        for line in ("valid until 2020-01-01",
                     "renewal scheduled 2020-01-01",
                     "please regenerate the fixture by 2020-01-01",
                     "deadline 2020-01-01"):
            self.assertEqual(len(self.dates(line, self.FIX)), 1, line)

    def test_generic_domain_keys_removed(self):
        self.assertEqual(self.dates('due_date = "2020-01-01"'), [])
        self.assertEqual(self.dates('{"end_date": "2020-01-01"}'), [])
        self.assertEqual(self.dates('{"due_date": "2020-01-01", "x": 1}'), [])

    def test_expiry_keys_still_flag(self):
        for line in ('expires = "2020-01-01"',
                     '{"exp": "2020-01-01"}',
                     'not_after: "2020-01-01"',
                     'expiration_date = "2020-01-01"',
                     '"valid_until": "2020-01-01"'):
            self.assertEqual(len(self.dates(line)), 1, line)

    def test_per_key_attribution_multi_date_line(self):
        line = ('{"valid_until": "2020-01-01", "created": "2019-05-05", '
                '"dob": "1990-01-01"}')
        found = self.dates(line)
        self.assertEqual([f.expires for f in found], ["2020-01-01"])
        line = '{"created": "2019-05-05", "expires": "2020-01-01"}'
        found = self.dates(line, self.FIX)
        self.assertEqual([f.expires for f in found], ["2020-01-01"])

    def test_cue_with_multiple_dates_flags_none(self):
        self.assertEqual(
            self.dates("regenerate 2019-01-01 and 2020-06-01", self.FIX), [])


class TestDocExemption(unittest.TestCase):
    """Fix 16: doc detection, consistent exemption, counted suppression."""

    def test_is_doc_file(self):
        for rel in ("CHANGELOG", "LICENSE", "README", "CHANGELOG.md",
                    "docs/guide.md", "notes/release_notes.txt",
                    "release-notes.md", "CHANGELOG.adoc", "HISTORY.txt"):
            self.assertTrue(er._is_doc_file(rel), rel)
        for rel in ("src/readme.py", "tokens.txt", "certs/server.pem",
                    "src/config.py", "CHANGELOG.py"):
            self.assertFalse(er._is_doc_file(rel), rel)

    def test_jwt_in_readme_suppressed_and_counted(self):
        with tempfile.TemporaryDirectory() as tmp:
            with open(os.path.join(tmp, "README.md"), "w") as fh:
                fh.write(f"Example token: {EXPIRED_TOKEN}\n")
            result = er.scan(tmp, now=NOW)
            self.assertEqual(result.findings, [])
            self.assertEqual(result.suppressed_in_docs, 1)
            self.assertEqual(er.to_json_dict(result)["suppressed_in_docs"], 1)

    def test_cert_in_changelog_suppressed(self):
        with tempfile.TemporaryDirectory() as tmp:
            with open(os.path.join(tmp, "CHANGELOG"), "wb") as fh:
                fh.write(load_cert_pem())
            result = er.scan(tmp, now=NOW)
            self.assertEqual(result.findings, [])
            self.assertEqual(result.suppressed_in_docs, 1)

    def test_jwt_in_readme_py_not_suppressed(self):
        with tempfile.TemporaryDirectory() as tmp:
            os.makedirs(os.path.join(tmp, "src"))
            with open(os.path.join(tmp, "src", "readme.py"), "w") as fh:
                fh.write(f'TOKEN = "{EXPIRED_TOKEN}"\n')
            result = er.scan(tmp, now=NOW)
            self.assertEqual(len(result.expired), 1)
            self.assertEqual(result.suppressed_in_docs, 0)


class TestIgnoreFile(unittest.TestCase):
    """Fix 17: expiry-radar.ignore blesses fixtures; cassettes NOT
    auto-suppressed."""

    def _repo(self, tmp, with_cassette=True):
        os.makedirs(os.path.join(tmp, "tests", "fixtures"))
        with open(os.path.join(tmp, "tests", "fixtures", "auth.py"),
                  "w") as fh:
            fh.write(f'TOKEN = "{EXPIRED_TOKEN}"\n')
        if with_cassette:
            os.makedirs(os.path.join(tmp, "cassettes"))
            with open(os.path.join(tmp, "cassettes", "resp.txt"), "w") as fh:
                fh.write(EXPIRED_TOKEN + "\n")

    def test_cassettes_not_auto_suppressed(self):
        with tempfile.TemporaryDirectory() as tmp:
            self._repo(tmp)
            result = er.scan(tmp, now=NOW)
            self.assertEqual(len(result.expired), 2)  # fixture + cassette

    def test_ignore_file_suppresses(self):
        with tempfile.TemporaryDirectory() as tmp:
            self._repo(tmp)
            with open(os.path.join(tmp, "expiry-radar.ignore"), "w") as fh:
                fh.write("# bless intentional fixtures\n"
                         "tests/fixtures/\ncassettes/\n")
            result = er.scan(tmp, now=NOW)
            self.assertEqual(result.findings, [])
            ignored = [u["path"] for u in result.unscanned
                       if "ignored" in u["reason"]]
            self.assertEqual(sorted(ignored),
                             ["cassettes/resp.txt",
                              "tests/fixtures/auth.py"])


class TestCollectionEdgeCases(unittest.TestCase):
    """Fix 12: walk onerror, git fallback warning, submodule gitlinks."""

    def test_walk_onerror_becomes_unscanned(self):
        def fake_walk(top, topdown=True, onerror=None, followlinks=False):
            if onerror is not None:
                onerror(PermissionError(
                    13, "Permission denied", os.path.join(top, "secret")))
            return iter([(top, [], [])])

        with tempfile.TemporaryDirectory() as tmp:
            with open(os.path.join(tmp, "a.txt"), "w") as fh:
                fh.write("hi\n")
            with mock.patch.object(er.os, "walk", fake_walk):
                result = er.scan(tmp, now=NOW)
            self.assertIn("secret", [u["path"] for u in result.unscanned])

    def test_git_failure_fallback_warns(self):
        with tempfile.TemporaryDirectory() as tmp:
            os.mkdir(os.path.join(tmp, ".git"))  # present but not a repo
            with open(os.path.join(tmp, "a.txt"), "w") as fh:
                fh.write("hi\n")
            result = er.scan(tmp, now=NOW)
            self.assertEqual(result.source, "walk")
            self.assertTrue(any("fell back to directory walk" in w
                                for w in result.warnings))

    def test_plain_non_git_dir_has_no_fallback_warning(self):
        with tempfile.TemporaryDirectory() as tmp:
            with open(os.path.join(tmp, "a.txt"), "w") as fh:
                fh.write("hi\n")
            result = er.scan(tmp, now=NOW)
            self.assertEqual(result.source, "walk")
            self.assertEqual(result.warnings, [])

    def test_submodule_is_unscanned(self):
        if shutil.which("git") is None:
            self.skipTest("git not available")
        with tempfile.TemporaryDirectory() as tmp:
            inner = os.path.join(tmp, "inner")
            outer = os.path.join(tmp, "outer")
            os.makedirs(inner)
            os.makedirs(outer)

            def git(cwd, *a, check=True):
                return subprocess.run(["git", "-C", cwd, *a], check=check,
                                      capture_output=True, text=True)

            try:
                git(inner, "init", "-q")
                git(inner, "config", "user.email", "f@example.test")
                git(inner, "config", "user.name", "Fixture")
                with open(os.path.join(inner, "x.txt"), "w") as fh:
                    fh.write(EXPIRED_TOKEN + "\n")
                git(inner, "add", ".")
                git(inner, "commit", "-qm", "inner")
                git(outer, "init", "-q")
                git(outer, "config", "user.email", "f@example.test")
                git(outer, "config", "user.name", "Fixture")
                subprocess.run(
                    ["git", "-C", outer, "-c", "protocol.file.allow=always",
                     "submodule", "add", "-q", inner, "sub"],
                    check=True, capture_output=True, text=True)
                git(outer, "add", ".")
                git(outer, "commit", "-qm", "outer")
            except subprocess.CalledProcessError:
                self.skipTest("git submodule not permitted in this env")
            result = er.scan(outer, now=NOW)
            self.assertEqual(result.source, "git")
            subs = [u for u in result.unscanned
                    if u["reason"] == "submodule (not scanned)"]
            self.assertEqual([u["path"] for u in subs], ["sub"])
            self.assertEqual(result.findings, [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
