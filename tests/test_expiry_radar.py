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


class TestEpochExpiry(unittest.TestCase):
    """v0.2: epoch-seconds values of expiry-semantic keys only."""

    def scan_text(self, text, rel="config/app.py"):
        return er.scan_epochs(text, rel, NOW, 90)

    def test_expired_env_style(self):
        got = self.scan_text("TOKEN_EXPIRES_AT=1577836800\n",
                             rel="config/app.env")
        self.assertEqual([(f.kind, f.status) for f in got],
                         [("epoch-expiry", "expired")])

    def test_expiring_json_key(self):
        got = self.scan_text('{"expires_at": 1796000000}\n')
        self.assertEqual([f.status for f in got], ["expiring"])

    def test_safe_far_future(self):
        got = self.scan_text("SESSION_EXPIRES_AT = 4102444800\n")
        self.assertEqual([f.status for f in got], ["safe"])

    def test_jwt_style_exp_key(self):
        got = self.scan_text('{"exp": 1577836800, "sub": "x"}\n')
        self.assertEqual(len(got), 1)

    def test_traps_do_not_flag(self):
        text = (
            "CACHE_TTL = 3600\n"
            "SESSION_TTL_SECONDS = 86400\n"
            '"expires_in": 7200,\n'
            '"exp": 3600,\n'
            '"created_at": 1577836800,\n'
            '"updated_at": 1600000000,\n'
            '"iat": 1577836800,\n'
            '"expires_at": 1767225600000,\n'      # millisecond epoch
            '"token_expires_at_ms": 1767225600000,\n'
            "EXPIRY_CHECK_INTERVAL = 300\n"
            '"valid_until": "2020-01-01",\n'       # ISO form, not epoch
            '"expires_at": 9999999999999999999,\n'  # absurd future
            '"expires_at": -5,\n'
            '"expires_at": 1577836800.5,\n'        # fractional — not an epoch
        )
        self.assertEqual(self.scan_text(text), [])

    def test_float_point_zero_spelling_flags(self):
        got = self.scan_text('"expires_at": 1577836800.0\n')
        self.assertEqual([f.status for f in got], ["expired"])

    def test_claimed_occurrences_skipped(self):
        # occurrence-level dedupe: the JWK scanner's claimed
        # (line, value) is skipped; a different value on the same
        # line is still reported (fix pass — whole-line exclusion
        # silently dropped it)
        from collections import Counter
        text = ('{"exp": 1893456000, "expires_at": 1577836800, '
                '"iat": 1}\n')
        got = er.scan_epochs(text, "keys/jwks.json", NOW, 90,
                             claims=Counter({(1, 1893456000): 1}))
        self.assertEqual(len(got), 1)
        self.assertEqual(got[0].expires, "2020-01-01T00:00:00Z")
        unclaimed = er.scan_epochs(text, "keys/jwks.json", NOW, 90)
        self.assertEqual(len(unclaimed), 2)

    def test_window_boundary(self):
        # exactly at the window edge is expiring, one day beyond is safe
        edge = int((NOW.timestamp()) + 89 * 86400)
        got = self.scan_text(f'"expires_at": {edge}\n')
        self.assertEqual([f.status for f in got], ["expiring"])


class TestJwkExpiry(unittest.TestCase):
    """v0.2: exp inside JWK/JWKS-shaped JSON."""

    def scan_text(self, text, rel="keys/jwks.json"):
        warnings = []
        got, _claims = er.scan_jwks(text, rel, NOW, 90, warnings)
        return got, warnings

    def test_jwks_array_expired(self):
        text = json.dumps({"keys": [
            {"kty": "RSA", "kid": "a", "exp": 1577836800},
            {"kty": "EC", "kid": "b"}]})
        got, _ = self.scan_text(text)
        self.assertEqual([(f.kind, f.status) for f in got],
                         [("jwk-expiry", "expired")])

    def test_single_jwk_expiring(self):
        exp = int(NOW.timestamp()) + 10 * 86400
        got, _ = self.scan_text(json.dumps({"kty": "RSA", "exp": exp}))
        self.assertEqual([f.status for f in got], ["expiring"])

    def test_no_exp_no_finding(self):
        got, warnings = self.scan_text(
            json.dumps({"keys": [{"kty": "RSA", "kid": "a"}]}))
        self.assertEqual(got, [])
        self.assertEqual(warnings, [])

    def test_shape_must_validate(self):
        # exp in plain JSON without kty/keys shape is the epoch rule's
        # job, not the JWK rule's
        got, _ = self.scan_text(json.dumps({"exp": 1577836800}),
                                rel="data.json")
        self.assertEqual(got, [])

    def test_non_numeric_exp_warns_once(self):
        text = json.dumps({"keys": [
            {"kty": "RSA", "exp": "soon"}, {"kty": "EC", "exp": "later"}]})
        got, warnings = self.scan_text(text)
        self.assertEqual(got, [])
        self.assertEqual(len(warnings), 1)
        self.assertIn("non-numeric", warnings[0])

    def test_implausible_exp_values_silent(self):
        # Fix pass (FP hunt): the JWK scanner now applies the epoch
        # plausibility window. 10**30, the RSA public exponent 65537,
        # and the no-expiry sentinels 0 / -1 are silently not
        # expiries — the first version flagged them as 1970 dates.
        for value in (10 ** 30, 65537, 0, -1):
            got, warnings = self.scan_text(
                json.dumps({"kty": "RSA", "exp": value}))
            self.assertEqual(got, [], f"exp={value}")
            self.assertEqual(warnings, [], f"exp={value}")

    def test_infinite_exp_warns(self):
        got, warnings = self.scan_text('{"kty": "RSA", "exp": 1e999}')
        self.assertEqual(got, [])
        self.assertTrue(any("non-integer" in w for w in warnings))

    def test_deeply_nested_warns_not_crashes(self):
        text = '{"keys": ' + "[" * 500 + "]" * 500 + "}"
        got, warnings = self.scan_text(text)
        self.assertEqual(got, [])
        self.assertTrue(any("deeply nested" in w for w in warnings))

    def test_malformed_named_jwks_warns(self):
        got, warnings = self.scan_text('{"keys": [{"kty": "RSA", "exp": 1')
        self.assertEqual(got, [])
        self.assertTrue(any("does not parse" in w for w in warnings))

    def test_malformed_unnamed_is_silent(self):
        got, warnings = self.scan_text('{"keys": [{"kty": "RSA", "exp": 1',
                                       rel="data/blob.json")
        self.assertEqual(got, [])
        self.assertEqual(warnings, [])

    def test_no_key_material_in_finding(self):
        text = json.dumps({"keys": [{"kty": "RSA", "kid": "secret-kid",
                                     "n": "BIGMODULUSVALUE",
                                     "exp": 1577836800}]})
        got, _ = self.scan_text(text)
        blob = json.dumps([f.to_dict() for f in got])
        self.assertNotIn("BIGMODULUSVALUE", blob)
        self.assertNotIn("secret-kid", blob)


class TestOpensslExpiry(unittest.TestCase):
    """v0.2: notAfter lines in committed openssl output."""

    def scan_text(self, text):
        return er.scan_openssl_text(text, "certs/out.txt", NOW, 90)

    def test_dates_form_expired(self):
        got = self.scan_text(
            "notBefore=Dec 10 00:00:00 2024 GMT\n"
            "notAfter=Jan 15 23:59:59 2025 GMT\n")
        self.assertEqual([(f.kind, f.status) for f in got],
                         [("openssl-expiry", "expired")])

    def test_text_form_expiring(self):
        got = self.scan_text("    Not After : Dec 25 00:00:00 2026 GMT\n")
        self.assertEqual([f.status for f in got], ["expiring"])

    def test_not_before_never_flags(self):
        got = self.scan_text(
            "notBefore=Jan 15 00:00:00 2020 GMT\n"
            "    Not Before: Jan 15 00:00:00 2020 GMT\n")
        self.assertEqual(got, [])

    def test_space_padded_day(self):
        got = self.scan_text("notAfter=Jan  5 00:00:00 2025 GMT\n")
        self.assertEqual([f.status for f in got], ["expired"])

    def test_invalid_calendar_date_skipped(self):
        self.assertEqual(
            self.scan_text("notAfter=Feb 30 00:00:00 2025 GMT\n"), [])

    def test_unknown_month_skipped(self):
        self.assertEqual(
            self.scan_text("notAfter=Xyz 10 00:00:00 2025 GMT\n"), [])


class TestSarif(unittest.TestCase):
    """v0.2: --sarif output is valid SARIF 2.1.0 and cross-checks
    against the JSON report result-for-result."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, True)
        with open(os.path.join(self.tmp, "session.json"), "w") as fh:
            fh.write('{"expires_at": 1577836800}\n')
        with open(os.path.join(self.tmp, "jwks.json"), "w") as fh:
            fh.write(json.dumps(
                {"keys": [{"kty": "RSA", "exp": 1577836800}]}))
        # an oversize file -> unscanned, must surface in SARIF honestly
        with open(os.path.join(self.tmp, "big.bin"), "wb") as fh:
            fh.write(b"A" * (er.MAX_FILE_SIZE + 1))
        self.result = er.scan(self.tmp, now=NOW, days=90)

    def test_sarif_shape(self):
        doc = er.render_sarif(self.result)
        self.assertEqual(doc["version"], "2.1.0")
        self.assertIn("sarif-2.1.0", doc["$schema"])
        run = doc["runs"][0]
        self.assertEqual(run["tool"]["driver"]["name"], "Expiry Radar")
        self.assertEqual(run["tool"]["driver"]["version"], "0.2.0")
        json.dumps(doc)  # serialisable

    def test_results_crosscheck_json(self):
        doc = er.render_sarif(self.result)
        run = doc["runs"][0]
        report = er.to_json_dict(self.result)
        self.assertEqual(len(run["results"]),
                         len(report["findings"]))
        rule_ids = {r["id"] for r in run["tool"]["driver"]["rules"]}
        for res, finding in zip(run["results"], report["findings"]):
            self.assertEqual(res["ruleId"], finding["kind"])
            self.assertIn(res["ruleId"], rule_ids)
            loc = res["locations"][0]["physicalLocation"]
            self.assertEqual(loc["artifactLocation"]["uri"],
                             finding["path"])
            self.assertEqual(loc["region"]["startLine"], finding["line"])
            self.assertEqual(res["properties"]["status"],
                             finding["status"])
        levels = {r["properties"]["status"]: r["level"]
                  for r in run["results"]}
        self.assertEqual(levels["expired"], "error")

    def test_unscanned_is_honest(self):
        doc = er.render_sarif(self.result)
        run = doc["runs"][0]
        invocation = run["invocations"][0]
        self.assertFalse(invocation["executionSuccessful"])
        notes = invocation["toolExecutionNotifications"]
        self.assertTrue(any(
            n["associatedRule"]["id"] == "unscanned-file"
            and "big.bin" in n["message"]["text"] for n in notes))
        rule_ids = {r["id"] for r in run["tool"]["driver"]["rules"]}
        self.assertIn("unscanned-file", rule_ids)

    def test_clean_scan_execution_successful(self):
        clean = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, clean, True)
        with open(os.path.join(clean, "a.txt"), "w") as fh:
            fh.write("nothing here\n")
        doc = er.render_sarif(er.scan(clean, now=NOW, days=90))
        run = doc["runs"][0]
        self.assertEqual(run["results"], [])
        self.assertTrue(run["invocations"][0]["executionSuccessful"])

    def test_no_token_material_leaks(self):
        blob = json.dumps(er.render_sarif(self.result))
        self.assertNotIn("1577836800", blob)  # epoch values stay out too

    def run_cli(self, *args):
        return subprocess.run(
            [sys.executable, os.path.join(ROOT, "expiry_radar.py"), *args],
            capture_output=True, text=True, timeout=60)

    def test_cli_sarif_exit_code_and_parse(self):
        proc = self.run_cli(self.tmp, "--sarif", "--now", "2026-11-10")
        self.assertEqual(proc.returncode, 2)  # expired findings
        doc = json.loads(proc.stdout)
        self.assertEqual(doc["version"], "2.1.0")
        self.assertTrue(doc["runs"][0]["results"])

    def test_cli_json_and_sarif_mutually_exclusive(self):
        proc = self.run_cli(self.tmp, "--json", "--sarif")
        self.assertEqual(proc.returncode, 3)  # usage error


class TestV02FixPass(unittest.TestCase):
    """Regression tests for the v0.2 adversarial fix pass (red team,
    FP hunter, code auditor). One test per closed finding."""

    # --- red team #1/#2/#3: quadratic paths are now linear -------------
    def test_epoch_long_token_linear(self):
        start = time.time()
        got = er.scan_epochs("a" * 16000 + "\n", "x.txt", NOW, 90)
        self.assertEqual(got, [])
        self.assertLess(time.time() - start, 2.0)

    def test_epoch_many_matches_one_line_linear(self):
        line = "exp = 1577836800, " * 2000 + '"iat": 1\n'
        start = time.time()
        got = er.scan_epochs(line, "x.txt", NOW, 90)
        self.assertEqual(len(got), 2000)
        self.assertLess(time.time() - start, 3.0)

    def test_jwk_many_keys_linear(self):
        keys = [{"kty": "RSA", "exp": 1577836800 + i} for i in range(2000)]
        text = json.dumps({"keys": keys}, indent=1)
        warnings = []
        start = time.time()
        got, _ = er.scan_jwks(text, "keys/jwks.json", NOW, 90, warnings)
        self.assertEqual(len(got), 2000)
        self.assertLess(time.time() - start, 3.0)

    # --- auditor #1 / red team #6: JWK line attribution ----------------
    def test_jwk_line_attribution_with_kid_collision(self):
        text = (
            '{\n'
            '  "keys": [\n'
            '    {"kty": "RSA", "kid": "1577836800", "exp": 1893456000},\n'
            '    {"kty": "EC", "exp": 1577836800}\n'
            '  ]\n'
            '}\n'
        )
        got, _ = er.scan_jwks(text, "keys/jwks.json", NOW, 90, [])
        by_status = {f.status: f for f in got}
        self.assertEqual(by_status["safe"].line, 3)
        self.assertEqual(by_status["expired"].line, 4)

    def test_jwk_duplicate_values_get_own_lines(self):
        text = (
            '{\n  "keys": [\n'
            '    {"kty": "RSA", "exp": 1577836800},\n'
            '    {"kty": "EC", "exp": 1577836800}\n'
            '  ]\n}\n'
        )
        got, _ = er.scan_jwks(text, "keys/jwks.json", NOW, 90, [])
        self.assertEqual([f.line for f in got], [3, 4])

    # --- auditor #2 / red team #4: occurrence-level dedupe -------------
    def test_compact_mixed_file_reports_both(self):
        with tempfile.TemporaryDirectory() as tmp:
            with open(os.path.join(tmp, "mixed.json"), "w") as fh:
                fh.write('{"expires_at": 1577836800, "keys": '
                         '[{"kty": "RSA", "exp": 1893456000}]}')
            result = er.scan(tmp, now=NOW, days=90)
            kinds = sorted((f.kind, f.status) for f in result.findings)
            self.assertEqual(kinds, [("epoch-expiry", "expired"),
                                     ("jwk-expiry", "safe")])
            self.assertEqual(result.exit_code(), 2)

    # --- red team #5: unicode-escaped JWKS ------------------------------
    def test_jwk_unicode_escaped_exp_found(self):
        text = '{"keys": [{"kty": "RSA", "\\u0065xp": 1577836800}]}'
        got, _ = er.scan_jwks(text, "keys/jwks.json", NOW, 90, [])
        self.assertEqual([(f.kind, f.status) for f in got],
                         [("jwk-expiry", "expired")])

    # --- red team #9: string exp in JWKS is a JWK finding, once ---------
    def test_jwk_string_exp_accepted_once(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "jwks.json")
            with open(path, "w") as fh:
                fh.write('{"kty": "RSA", "exp": "1577836800"}')
            result = er.scan(tmp, now=NOW, days=90)
            self.assertEqual(
                [(f.kind, f.status) for f in result.findings],
                [("jwk-expiry", "expired")])
            self.assertEqual(result.warnings, [])

    # --- auditor #3: epoch terminator -----------------------------------
    def test_epoch_trailing_junk_rejected(self):
        for text in ('"expires_at": 1577836800abc\n',
                     '"expires_at": 1577836800seconds\n',
                     '"expires_at": 1577836800_000\n',
                     '"expires_at": 1577836800.0e3\n'):
            self.assertEqual(er.scan_epochs(text, "x.json", NOW, 90),
                             [], text)

    # --- FP hunt #1/#2/#11: bare exp needs token context -----------------
    def test_bare_exp_without_context_ignored(self):
        self.assertEqual(
            er.scan_epochs('{"exp": 1577836800}\n', "x.json", NOW, 90),
            [])
        self.assertEqual(
            er.scan_epochs(
                '{"players": [{"name": "x", "exp": 200000000}]}\n',
                "hiscores.json", NOW, 90),
            [])

    def test_bare_exp_with_claim_context_flags(self):
        got = er.scan_epochs('{"iat": 1577800000, "exp": 1577836800}\n',
                             "x.json", NOW, 90)
        self.assertEqual([f.status for f in got], ["expired"])

    # --- FP hunt #6/#7/#10: doc containers --------------------------------
    def test_doc_containers_suppress_new_kinds(self):
        cases = {
            "app.log": "TOKEN_EXPIRES_AT=1577836800\n",
            "docs/payload.json": '{"expires_at": 1577836800}\n',
            "CHANGELOG.json": '{"expires_at": 1577836800}\n',
            ".env.example": "TOKEN_EXPIRES_AT=1577836800\n",
        }
        with tempfile.TemporaryDirectory() as tmp:
            for rel, content in cases.items():
                full = os.path.join(tmp, rel)
                os.makedirs(os.path.dirname(full), exist_ok=True)
                with open(full, "w") as fh:
                    fh.write(content)
            result = er.scan(tmp, now=NOW, days=90)
            self.assertEqual(result.findings, [])
            self.assertEqual(result.suppressed_in_docs, 4)

    # --- auditor #4: evidence masking with adjacent secrets --------------
    def test_epoch_evidence_masks_quoted_secret(self):
        line = ('{"expires_at": 1577836800, "note": '
                '"password is correcthorsebatterystaple ok"}\n')
        got = er.scan_epochs(line, "x.json", NOW, 90)
        self.assertEqual(len(got), 1)
        self.assertNotIn("correcthorsebatterystaple", got[0].evidence)

    # --- auditor #5: epoch is an instant (documented divergence) ----------
    def test_midnight_epoch_is_expired_by_midday(self):
        midday = datetime(2026, 11, 10, 12, 0, tzinfo=timezone.utc)
        epoch = int(datetime(2026, 11, 10,
                             tzinfo=timezone.utc).timestamp())
        got = er.scan_epochs(f'"expires_at": {epoch}\n', "x.json",
                             midday, 90)
        self.assertEqual([f.status for f in got], ["expired"])

    # --- auditor #7: kty whitelist ---------------------------------------
    def test_jwk_kty_whitelist(self):
        got, _ = er.scan_jwks(
            json.dumps({"kty": "WEIRD\nVALUE", "exp": 1577836800}),
            "keys/jwks.json", NOW, 90, [])
        self.assertEqual(got[0].evidence, "JWK (kty=unknown)")

    # --- auditor #9 gap: SARIF with warnings resolves its rule ------------
    def test_sarif_warning_rule_resolves(self):
        with tempfile.TemporaryDirectory() as tmp:
            with open(os.path.join(tmp, "broken.pem"), "w") as fh:
                fh.write("-----BEGIN CERTIFICATE-----\n!!!\n"
                         "-----END CERTIFICATE-----\n")
            result = er.scan(tmp, now=NOW, days=90)
            self.assertTrue(result.warnings)
            doc = er.render_sarif(result)
            run = doc["runs"][0]
            rule_ids = {r["id"] for r in run["tool"]["driver"]["rules"]}
            self.assertIn("scan-warning", rule_ids)
            for note in run["invocations"][0][
                    "toolExecutionNotifications"]:
                self.assertIn(note["associatedRule"]["id"], rule_ids)


class IsoDatetimeExpiryTests(unittest.TestCase):
    def test_offsets_are_instants_not_end_of_day(self):
        now = datetime(2026, 11, 11, tzinfo=timezone.utc)
        for value, status in [
                ("2026-11-11T00:30:00+01:00", "expired"),
                ("2026-11-10T23:30:00-01:00", "expiring"),
                ("2026-11-11T00:00:00Z", "expiring")]:
            with self.subTest(value=value):
                findings = er.scan_dates('expires="' + value + '"', "config.py", now, 90)
                self.assertEqual(len(findings), 1)
                self.assertEqual(findings[0].status, status)

    def test_invalid_or_unzoned_datetime_is_not_truncated_to_date(self):
        for value in ["2020-01-01T25:00:00Z", "2020-01-01T00:00:00+01:99",
                      "2020-01-01T00:00:00", "2020-02-30T00:00:00Z"]:
            with self.subTest(value=value):
                self.assertEqual(er.scan_dates('expires="' + value + '"',
                                               "config.py", NOW, 90), [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
