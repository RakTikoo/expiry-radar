#!/usr/bin/env python3
"""Expiry Radar — find repo artefacts that break on a known future date.

Scans git-tracked files (fallback: a plain directory walk) for:
  1. X.509 certificates in PEM form (and whole-file DER) — parses ``notAfter``
     with a minimal stdlib-only ASN.1/DER parser.
  2. Committed JWTs — decodes the payload ``exp`` claim (no signature check).
     Tokens are NEVER printed in full; evidence is redacted to 8 characters,
     and the iss/sub/aud claims are never printed at all.
  3. Hardcoded ISO dates in test / fixture / snapshot / testdata paths, and
     dates sitting as the value of an expiry-like key anywhere — flagging
     dates that are past or within the warning window.

Static analysis only: scanned files are read as bytes and never executed,
imported, or evaluated. Python standard library only. No network, no
account, no token.

Exit codes: 0 = clean, 1 = something expiring within the window,
2 = something already expired, 3 = usage error (bad arguments, bad
--now, non-directory path — EX_USAGE-style, never a finding).
"""

from __future__ import annotations

import argparse
import base64
import bisect
import binascii
import fnmatch
import json
import os
import re
import stat
import subprocess
import sys
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

__version__ = "0.1.0"

MAX_FILE_SIZE = 5 * 1024 * 1024  # 5 MiB — larger files are listed as unscanned
DEFAULT_DAYS = 90
IGNORE_FILENAME = "expiry-radar.ignore"
MAX_JWT_DECODED_SEGMENT = 64 * 1024  # decoded JWT header/payload cap

SKIP_DIRS = {
    ".git", ".hg", ".svn", "__pycache__", "node_modules", ".venv", "venv",
    ".tox", ".mypy_cache", ".pytest_cache",
}
DER_EXTENSIONS = {".der", ".crt", ".cer"}
# Document / history files: their dates are historical by nature, not expiry
# fixtures. The exemption applies to certs and JWTs in them too (a cert or
# token quoted in documentation is documentation), but suppressed findings
# are *counted* (suppressed_in_docs in JSON) — never silently dropped.
# A file is a doc file when it has a documentation extension (.md/.rst/
# .adoc), or when it has NO extension (or a .txt extension) and a doc-like
# stem: an extensionless CHANGELOG/LICENSE/README is exempt, but
# src/readme.py is NOT — a code extension defeats the stem.
DOC_FILENAMES = {"changelog", "history", "news", "readme", "license",
                 "licence", "authors", "changes", "releasenotes",
                 "release_notes", "release-notes"}
DOC_EXTENSIONS_ANY_STEM = {".md", ".rst", ".adoc"}

FIXTURE_PATH_PARTS = {
    "test", "tests", "testing", "fixture", "fixtures", "testdata",
    "snapshot", "snapshots", "__fixtures__", "__snapshots__", "sample",
    "samples", "mock", "mocks", "seed", "seeds", "golden", "goldens",
    "expected", "test_data", "test-data",
}
# A file is also fixture-ish if its *name* says so (e.g. tests live next to
# code as foo_test.go / test_foo.py / foo.spec.ts).
FIXTURE_NAME_RE = re.compile(
    r"(^test[_.-]|_test\.|\.test\.|\.spec\.|fixture|snapshot|testdata)",
    re.IGNORECASE,
)
# Expiry-like *keys* only, and only in key syntax — `expires:`,
# `valid_until =`, `"notAfter":` — never as a bare prose word. The key set
# is deliberately expiry-semantic only: generic scheduling keys such as
# `due_date` / `end_date` (invoices, events) were removed after the
# false-positive review — they are not expiry bounds. `ttl` is likewise
# excluded by decision: TTL values are overwhelmingly durations in
# seconds, not ISO dates (see ANALYSIS.md, adversarial review #14).
EXPIRY_KEY_RE = re.compile(
    r"(expir\w*|valid[_-]?(?:until|to|thru)|validuntil|not[_-]?after|"
    r"\bexp\b)"
    r"\s*[\"']?\s*[:=]",
    re.IGNORECASE,
)
# A key *occurrence* whose value position we can locate: after the match,
# the scanner is sitting exactly where the key's value starts, so a date
# is flagged only if it IS that key's value (per-key attribution).
KEY_VALUE_RE = re.compile(
    r"[A-Za-z0-9_\-]*?(?:expir\w+|valid[_-]?(?:until|to|thru)|validuntil|"
    r"not[_-]?after|exp)"
    r"\s*[\"']?\s*[:=]\s*[\"']?",
    re.IGNORECASE,
)
ISO_DATE_RE = re.compile(r"\b(\d{4})-(\d{2})-(\d{2})\b")
PEM_RE = re.compile(
    rb"-----BEGIN CERTIFICATE-----([A-Za-z0-9+/=\s]+?)-----END CERTIFICATE-----"
)
PEM_BEGIN = b"-----BEGIN CERTIFICATE-----"
PEM_END = b"-----END CERTIFICATE-----"
# Legacy constant, kept for API compatibility. The scanner no longer uses
# this regex: its nested quantifiers were super-quadratic on long dotless
# base64 runs (100 KB of 'A' took ~25 s). Scanning is now a linear pass
# over maximal token-character runs, validated in code (scan_jwts).
JWT_RE = re.compile(
    rb"[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{3,}"
)
# Maximal runs of JWT-alphabet characters (including the '.' separator).
# A single character class with one quantifier cannot backtrack
# quadratically; each run is then split and validated in code.
JWT_RUN_RE = re.compile(rb"[A-Za-z0-9_.\-]+")


# --------------------------------------------------------------------------
# Output sanitisation (text report injection defence)
# --------------------------------------------------------------------------

def _sanitize(text) -> str:
    """Replace C0 control characters (incl. \\n, \\r, ESC) and DEL with a
    space. Attacker-controlled strings (cert subjects, paths, evidence,
    warning text) must never inject lines or terminal escapes into the
    text report."""
    if text is None:
        return ""
    return "".join(
        ch if (ord(ch) >= 0x20 and ord(ch) != 0x7F) else " "
        for ch in str(text))


def _cap(text, limit: int = 120) -> str:
    """Sanitise, then cap at `limit` characters (with an ellipsis)."""
    text = _sanitize(text)
    return text if len(text) <= limit else text[:limit - 1] + "…"


# --------------------------------------------------------------------------
# Minimal ASN.1 / DER parsing (stdlib only)
# --------------------------------------------------------------------------

class DerError(ValueError):
    pass


def _read_tlv(data: bytes, offset: int):
    """Return (tag, value_bytes, next_offset) for one DER TLV at offset."""
    if offset + 2 > len(data):
        raise DerError("truncated TLV")
    tag = data[offset]
    offset += 1
    if tag & 0x1F == 0x1F:
        raise DerError("multi-byte tags not supported (not valid in X.509 core)")
    if offset >= len(data):
        raise DerError("missing length")
    first = data[offset]
    offset += 1
    if first & 0x80:
        n = first & 0x7F
        if n == 0 or n > 4 or offset + n > len(data):
            raise DerError("bad long-form length")
        length = int.from_bytes(data[offset:offset + n], "big")
        offset += n
    else:
        length = first
    if offset + length > len(data):
        raise DerError("value overruns buffer")
    return tag, data[offset:offset + length], offset + length


def _tlvs(value: bytes):
    """Split a constructed value into TLV children: [(tag, value, raw)]."""
    out = []
    offset = 0
    while offset < len(value):
        start = offset
        tag, val, offset = _read_tlv(value, offset)
        out.append((tag, val, value[start:offset]))
    return out


def _parse_oid(value: bytes) -> str:
    """Decode an OID. The first sub-identifier is a base-128 arc like any
    other (it packs arcs 0/1 as 40*a+b and may span several bytes —
    2.999.… needs two); decoding it byte-wise rendered 2.999.3 as
    2.56.55.3. Arcs are capped at 16 encoded bytes and the whole OID at
    64 bytes: an unbounded arc builds a quadratic-cost bigint."""
    if not value:
        raise DerError("empty OID")
    if len(value) > 64:
        raise DerError("OID too long (>64 bytes)")
    arcs = []
    i = 0
    while i < len(value):
        acc = 0
        count = 0
        while True:
            if i >= len(value):
                raise DerError("truncated OID arc")
            byte = value[i]
            i += 1
            count += 1
            if count > 16:
                raise DerError("OID arc too long (>16 bytes)")
            acc = (acc << 7) | (byte & 0x7F)
            if not byte & 0x80:
                break
        arcs.append(acc)
    first = arcs[0]
    if first < 40:
        parts = [0, first]
    elif first < 80:
        parts = [1, first - 40]
    else:
        parts = [2, first - 80]
    parts.extend(arcs[1:])
    return ".".join(str(p) for p in parts)


_STRING_TAGS = {
    0x0C: "utf-8",       # UTF8String
    0x13: "ascii",       # PrintableString
    0x16: "ascii",       # IA5String
    0x14: "latin-1",     # TeletexString (approximation; fine for names)
    0x19: "latin-1",     # VisibleString (approx)
    0x1A: "latin-1",
}


def _decode_dir_string(tag: int, value: bytes) -> str:
    if tag == 0x1E:  # BMPString
        try:
            return value.decode("utf-16-be")
        except UnicodeDecodeError:
            return ""
    enc = _STRING_TAGS.get(tag, "utf-8")
    return value.decode(enc, errors="replace")


_SHORT_NAMES = {"2.5.4.3": "CN", "2.5.4.10": "O", "2.5.4.11": "OU",
                "2.5.4.6": "C", "2.5.4.7": "L", "2.5.4.8": "ST"}


def _parse_name(name_value: bytes) -> str:
    """Render an X.501 Name (SEQUENCE OF SET OF SEQUENCE{OID, value})."""
    pieces = []
    for set_tag, set_value, _ in _tlvs(name_value):
        if set_tag != 0x31:
            continue
        for ava_tag, ava_value, _ in _tlvs(set_value):
            if ava_tag != 0x30:
                continue
            parts = _tlvs(ava_value)
            if len(parts) != 2:
                continue
            oid = _parse_oid(parts[0][1])
            text = _decode_dir_string(parts[1][0], parts[1][1])
            label = _SHORT_NAMES.get(oid, oid)
            if text:
                pieces.append(f"{label}={text}")
    return ", ".join(pieces) if pieces else "(no name)"


def _parse_time(tag: int, value: bytes) -> datetime:
    text = value.decode("ascii")
    if not text.endswith("Z"):
        # X.509 times in DER are UTC ('Z') or occasionally +hhmm offsets.
        # Handle a trailing offset crudely; anything else is rejected.
        m = re.match(r"^(.*)([+-]\d{4})$", text)
        if not m:
            raise DerError(f"unsupported time format: {text!r}")
        text, offset = m.group(1), m.group(2)
        base = _parse_time_body(tag, text)
        sign = 1 if offset[0] == "+" else -1
        delta = timedelta(hours=int(offset[1:3]), minutes=int(offset[3:5]))
        return base - sign * delta
    return _parse_time_body(tag, text)


def _parse_time_body(tag: int, text: str) -> datetime:
    text = text.rstrip("Z")
    if "." in text:  # fractional seconds (GeneralizedTime only)
        text = text.split(".", 1)[0]
    if tag == 0x17:  # UTCTime YYMMDDHHMMSS — RFC 5280 pivot: <50 → 20xx
        if len(text) != 12 or not text.isdigit():
            raise DerError(f"bad UTCTime: {text!r}")
        year = int(text[0:2])
        year += 2000 if year < 50 else 1900
        rest = text[2:]
    elif tag == 0x18:  # GeneralizedTime YYYYMMDDHHMMSS
        if len(text) != 14 or not text.isdigit():
            raise DerError(f"bad GeneralizedTime: {text!r}")
        year = int(text[0:4])
        rest = text[4:]
    else:
        raise DerError(f"unexpected time tag {tag:#x}")
    month, day, hour, minute, second = (
        int(rest[0:2]), int(rest[2:4]), int(rest[4:6]),
        int(rest[6:8]), int(rest[8:10]),
    )
    return datetime(year, month, day, hour, minute, second,
                    tzinfo=timezone.utc)


@dataclass
class CertInfo:
    subject: str
    issuer: str
    not_before: datetime
    not_after: datetime


def parse_certificate_der(der: bytes) -> CertInfo:
    """Parse one DER X.509 certificate. Raises DerError on any problem.

    Only the fields Expiry Radar needs are decoded: subject, issuer and the
    validity window. Signature is never checked (irrelevant to expiry and
    checking it would need trust roots we deliberately do not have).
    """
    tag, cert_value, end = _read_tlv(der, 0)
    if tag != 0x30:
        raise DerError("certificate is not a SEQUENCE")
    if end != len(der):
        raise DerError("trailing bytes after certificate")
    top = _tlvs(cert_value)
    if len(top) < 1 or top[0][0] != 0x30:
        raise DerError("missing tbsCertificate")
    tbs = _tlvs(top[0][1])
    idx = 0
    if idx < len(tbs) and tbs[idx][0] == 0xA0:  # [0] EXPLICIT version
        idx += 1
    # serialNumber, signature AlgorithmIdentifier
    idx += 2
    if idx + 2 >= len(tbs):
        raise DerError("tbsCertificate too short")
    issuer = _parse_name(tbs[idx][1]); idx += 1
    validity = _tlvs(tbs[idx][1]); idx += 1
    if len(validity) != 2:
        raise DerError("validity must hold notBefore and notAfter")
    not_before = _parse_time(validity[0][0], validity[0][1])
    not_after = _parse_time(validity[1][0], validity[1][1])
    subject = _parse_name(tbs[idx][1]); idx += 1
    return CertInfo(subject=subject, issuer=issuer,
                    not_before=not_before, not_after=not_after)


# --------------------------------------------------------------------------
# Findings & classification
# --------------------------------------------------------------------------

@dataclass
class Finding:
    kind: str            # certificate | jwt | fixture-date
    status: str          # expired | expiring | safe
    path: str            # repo-relative, forward slashes
    line: int            # 1-based; 1 for whole-file artefacts
    expires: str         # ISO-8601 UTC
    days_left: int
    detail: str          # human summary — never a full token
    evidence: str = ""   # redacted evidence, safe to print

    def to_dict(self):
        return {
            "kind": self.kind, "status": self.status, "path": self.path,
            "line": self.line, "expires": self.expires,
            "days_left": self.days_left, "detail": self.detail,
            "evidence": self.evidence,
        }


def classify(expiry: datetime, now: datetime, days: int):
    """Return (status, days_left)."""
    seconds = (expiry - now).total_seconds()
    days_left = int(seconds // 86400)  # floor: -1s already counts as -1d
    if seconds < 0:
        return "expired", days_left
    if seconds < days * 86400:
        return "expiring", days_left
    return "safe", days_left


def _newline_offsets(data: bytes):
    """Sorted offsets of every b'\\n' in data, computed once per file
    (C-speed finditer) so line lookups are a bisect, not a rescan —
    the old per-finding data.count() was O(file × findings)."""
    return [m.start() for m in re.finditer(b"\n", data)]


def _line_number(newline_offsets, offset: int) -> int:
    return bisect.bisect_left(newline_offsets, offset) + 1


def _line_of(data: bytes, offset: int) -> int:
    """Legacy single-lookup helper (O(n)); scanners use _line_number."""
    return data.count(b"\n", 0, offset) + 1


# --------------------------------------------------------------------------
# Scanners (one per artefact kind). Each returns findings; problems that
# are not findings go to the shared `warnings` list.
# --------------------------------------------------------------------------

def scan_certs_pem(data: bytes, rel: str, now, days, warnings,
                   newline_offsets=None):
    """PEM blocks, found *loosely*: every BEGIN CERTIFICATE marker is
    accounted for. A block with non-base64 body bytes, legacy PEM headers
    (Proc-Type: / DEK-Info: style lines), or no END marker produces a
    warning — never silence (the old strict regex simply did not match
    such blocks, so a broken committed cert looked like no cert)."""
    findings = []
    offsets = (newline_offsets if newline_offsets is not None
               else _newline_offsets(data))
    pos = 0
    while True:
        start = data.find(PEM_BEGIN, pos)
        if start == -1:
            break
        line = _line_number(offsets, start)
        end = data.find(PEM_END, start + len(PEM_BEGIN))
        if end == -1:
            warnings.append(f"{rel}: unterminated PEM certificate block "
                            f"(line {line}): missing END CERTIFICATE")
            break
        body = data[start + len(PEM_BEGIN):end]
        pos = end + len(PEM_END)
        if any(b":" in ln for ln in body.splitlines()):
            # Base64 never contains ':'; a colon means legacy PEM headers
            # (or prose). We do not strip headers and guess — warn.
            warnings.append(f"{rel}: PEM certificate block with legacy "
                            f"headers (line {line}) — not parsed")
            continue
        raw_b64 = re.sub(rb"\s+", b"", body)
        if not raw_b64 or re.search(rb"[^A-Za-z0-9+/=]", raw_b64):
            warnings.append(f"{rel}: unparseable PEM certificate block "
                            f"(line {line}): non-base64 data in body")
            continue
        try:
            der = base64.b64decode(raw_b64, validate=True)
            info = parse_certificate_der(der)
        except (binascii.Error, DerError, ValueError,
                UnicodeDecodeError) as exc:
            warnings.append(f"{rel}: unparseable PEM certificate block "
                            f"(line {line}): {_cap(exc)}")
            continue
        status, days_left = classify(info.not_after, now, days)
        findings.append(Finding(
            kind="certificate", status=status, path=rel, line=line,
            expires=info.not_after.strftime("%Y-%m-%dT%H:%M:%SZ"),
            days_left=days_left,
            detail=f"subject: {_cap(info.subject)}; "
                   f"issuer: {_cap(info.issuer)}",
            evidence="PEM certificate",
        ))
    return findings


def scan_cert_der(data: bytes, rel: str, now, days, warnings,
                  warn_on_fail: bool = True):
    """Whole-file DER. A file carrying a certificate extension that fails
    to parse is a warning, not a silent pass (warn_on_fail); callers set
    warn_on_fail=False when the bytes are explained another way (e.g.
    the file is a PEM text file, already handled by scan_certs_pem)."""
    try:
        info = parse_certificate_der(data)
    except (DerError, ValueError, UnicodeDecodeError) as exc:
        if warn_on_fail and warnings is not None:
            warnings.append(f"{rel}: file with certificate extension "
                            f"failed DER parse: {_cap(exc)}")
        return []
    status, days_left = classify(info.not_after, now, days)
    return [Finding(
        kind="certificate", status=status, path=rel, line=1,
        expires=info.not_after.strftime("%Y-%m-%dT%H:%M:%SZ"),
        days_left=days_left,
        detail=f"subject: {_cap(info.subject)}; issuer: {_cap(info.issuer)}",
        evidence="DER certificate",
    )]


def _b64url_decode(segment: bytes) -> bytes:
    pad = b"=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(segment + pad)


_MISS = object()


def scan_jwts(data: bytes, rel: str, now, days, warnings,
              newline_offsets=None):
    """Committed JWTs, found linearly: iterate maximal runs of the JWT
    alphabet, split each run on '.', and validate the first three
    segments in code (length caps here, not in regex quantifiers, so
    there is nothing to backtrack). Decoded segments are capped at
    64 KB; a deeply nested payload raises RecursionError in json.loads,
    which is caught and turned into a warning — the scan continues.
    The empty-signature form `header.payload.` (alg=none) is accepted.
    Identical tokens are decoded once per file (cache), so a file with
    20k copies of one token costs one decode plus 20k bisects."""
    findings = []
    offsets = (newline_offsets if newline_offsets is not None
               else _newline_offsets(data))
    cache = {}
    for match in JWT_RUN_RE.finditer(data):
        run = match.group(0)
        if b"." not in run:
            continue
        start = match.start()
        stripped = run.lstrip(b".")
        start += len(run) - len(stripped)
        run = stripped
        if len(run) > 262144:
            continue  # implausible token blob; not worth splitting
        parts = run.split(b".")
        if len(parts) < 3:
            continue
        header_b, payload_b, sig_b = parts[0], parts[1], parts[2]
        if len(header_b) < 8 or len(payload_b) < 8:
            continue
        if 0 < len(sig_b) < 3:
            continue  # signature segment present but implausibly short
        # No silent length pre-filter: oversized segments go through
        # _decode_jwt_expiry, whose decoded-size cap produces a warning.
        # (The 256 KB run cap above bounds the decode cost, and the
        # per-file token cache bounds how often it is paid.)
        token = b".".join((header_b, payload_b, sig_b))
        expiry = cache.get(token, _MISS)
        if expiry is _MISS:
            expiry, warn = _decode_jwt_expiry(header_b, payload_b)
            cache[token] = expiry
            if warn:
                warnings.append(
                    f"{rel}: {warn} "
                    f"(line {_line_number(offsets, start)})")
        if expiry is None:
            continue
        status, days_left = classify(expiry, now, days)
        findings.append(Finding(
            kind="jwt", status=status, path=rel,
            line=_line_number(offsets, start),
            expires=expiry.strftime("%Y-%m-%dT%H:%M:%SZ"),
            days_left=days_left,
            # iss/sub/aud are deliberately NOT printed: they are claims
            # about a (possibly real) identity/audience and leaked in
            # full before the fix pass. The exp date is the finding.
            detail="JWT exp claim",
            evidence=token[:8].decode("ascii", errors="replace") + "…",
        ))
    return findings


def _decode_jwt_expiry(header_b: bytes, payload_b: bytes):
    """Return (expiry_datetime_or_None, warning_or_None) for one token.
    (None, None) means 'not a JWT / no usable exp — stay silent';
    (None, msg) means 'looked like a JWT but is broken — warn once'."""
    try:
        header_raw = _b64url_decode(header_b)
        if len(header_raw) > MAX_JWT_DECODED_SEGMENT:
            return None, "JWT with oversized header segment — skipped"
        header = json.loads(header_raw)
    except RecursionError:
        return None, "JWT with deeply nested header JSON — skipped"
    except (ValueError, binascii.Error, UnicodeDecodeError):
        return None, None  # JWT-shaped random string — not a token
    if not isinstance(header, dict) or "alg" not in header:
        return None, None
    try:
        payload_raw = _b64url_decode(payload_b)
        if len(payload_raw) > MAX_JWT_DECODED_SEGMENT:
            return None, "JWT with oversized payload segment — skipped"
        payload = json.loads(payload_raw)
    except RecursionError:
        return None, "JWT with deeply nested payload JSON — skipped"
    except (ValueError, binascii.Error, UnicodeDecodeError):
        return None, None
    if not isinstance(payload, dict) or "exp" not in payload:
        return None, None
    exp = payload["exp"]
    if isinstance(exp, bool) or not isinstance(exp, (int, float)):
        return None, "JWT with non-numeric exp"
    try:
        return datetime.fromtimestamp(exp, tz=timezone.utc), None
    except (OverflowError, OSError, ValueError):
        return None, "JWT with out-of-range exp"


def _is_fixture_path(rel: str) -> bool:
    parts = [p.lower() for p in rel.split("/")]
    if any(p in FIXTURE_PATH_PARTS for p in parts[:-1]):
        return True
    return bool(FIXTURE_NAME_RE.search(parts[-1]))


def _is_doc_file(rel: str) -> bool:
    name = rel.rsplit("/", 1)[-1].lower()
    stem, dot, ext = name.rpartition(".")
    if not dot:
        return name in DOC_FILENAMES
    if "." + ext in DOC_EXTENSIONS_ANY_STEM:
        return True
    if "." + ext == ".txt":
        return stem in DOC_FILENAMES
    return False


# In a fixture-ish path a bare date is still not enough: KiCad sample boards
# carry a title-block *drawing* date, JSON fixtures carry birthdays and
# snapshot stamps. The line itself must carry expiry context — a cue word
# saying this date bounds validity — before we call it a date-bomb.
# Cues are whole words (\b): "invalid", "validation" and "renewable" must
# NOT trip \bvalid / \brenew. Plain-English "before" is NOT a cue (it
# appears in every "best before / use before / created before" stamp).
# Note what else is NOT a cue: bare "expired" / "notAfter". Their field
# forms are caught by the key rule; as prose they only narrate.
FIXTURE_CUE_RE = re.compile(
    r"(\bvalid\b|\buntil\b|\bdeadline\b|\bcut[_-]?off\b|"
    r"\bregenerat\w*\b|\brenew(?:s|ed|al|ing)?\b|"
    r"\bexpir(?:e|es|ing|y|ation)\b)",
    re.IGNORECASE,
)

_JWT_MASK_RE = re.compile(
    r"[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]*")
_KV_MASK_RE = re.compile(
    r"([A-Za-z0-9_\-.\"']+\s*[=:]\s*[\"']?)([^\s\"',\}\]]{9,})")


def _mask_evidence(line: str) -> str:
    """Fixture-date evidence is a raw source line and may carry secrets:
    mask JWT-shaped substrings and key=value / key: value values longer
    than 8 chars with ***, then sanitise and cap at 80 chars. Masking
    happens BEFORE truncation so a long secret is never half-printed."""
    masked = _JWT_MASK_RE.sub("***", line)
    masked = _KV_MASK_RE.sub(lambda m: m.group(1) + "***", masked)
    return _cap(masked, 80)


def scan_dates(text: str, rel: str, now, days, include_doc: bool = False):
    """ISO dates. Conservative by construction — a date is flagged only if

    * it IS the value of an expiry key on its line (per-key attribution:
      ``valid_until = "DATE"``, ``"expires": "DATE"`` — other dates on
      the same line, however many, are not flagged), or
    * its path is fixture-ish *and* its line carries an expiry cue word
      *and* it is the ONLY date on the line.

    Changelog/docs are exempt (unless include_doc, used by scan() to
    count suppressed findings). One finding per (line, date)."""
    findings = []
    if not include_doc and _is_doc_file(rel):
        return findings
    fixture = _is_fixture_path(rel)
    today = now.date()
    for lineno, line in enumerate(text.splitlines(), start=1):
        dates = list(ISO_DATE_RE.finditer(line))
        if not dates:
            continue
        flagged = set()
        for key_match in KEY_VALUE_RE.finditer(line):
            date_match = ISO_DATE_RE.match(line, key_match.end())
            if date_match:
                flagged.add(date_match.start())
        if (fixture and len(dates) == 1
                and FIXTURE_CUE_RE.search(line)):
            flagged.add(dates[0].start())
        if not flagged:
            continue
        evidence = _mask_evidence(line.strip())
        for match in dates:
            if match.start() not in flagged:
                continue
            year, month, day = (int(match.group(i)) for i in (1, 2, 3))
            if not (1900 <= year <= 2200 and 1 <= month <= 12
                    and 1 <= day <= 31):
                continue
            try:
                when = datetime(year, month, day, tzinfo=timezone.utc)
            except ValueError:
                continue  # e.g. 2026-02-30 — not a real date
            # A bare date is valid *through* that day, so its expiry
            # moment is the end of the day; days_left is date-to-date.
            status, _ = classify(
                when + timedelta(days=1) - timedelta(seconds=1), now, days)
            days_left = (when.date() - today).days
            findings.append(Finding(
                kind="fixture-date", status=status, path=rel, line=lineno,
                expires=when.strftime("%Y-%m-%d"), days_left=days_left,
                detail=f"hardcoded date {match.group(0)} in fixture-like "
                       f"context",
                evidence=evidence,
            ))
    return findings


# --------------------------------------------------------------------------
# File collection & scanning
# --------------------------------------------------------------------------

@dataclass
class ScanResult:
    root: str
    now: datetime
    days: int
    findings: list = field(default_factory=list)
    unscanned: list = field(default_factory=list)
    warnings: list = field(default_factory=list)
    files_scanned: int = 0
    source: str = "walk"  # git | walk
    suppressed_in_docs: int = 0

    @property
    def expired(self):
        return [f for f in self.findings if f.status == "expired"]

    @property
    def expiring(self):
        return [f for f in self.findings if f.status == "expiring"]

    @property
    def safe(self):
        return [f for f in self.findings if f.status == "safe"]

    def exit_code(self) -> int:
        if self.expired:
            return 2
        if self.expiring:
            return 1
        return 0


def _git_tracked_files(root: str):
    """(regular_paths, gitlink_paths) via `git ls-files -s`, or None if
    git is unavailable / root is not a repo / the command failed.
    Gitlinks (mode 160000) are submodule entries, not files."""
    try:
        proc = subprocess.run(
            ["git", "-C", root, "ls-files", "-s", "-z"],
            capture_output=True, timeout=30,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if proc.returncode != 0:
        return None
    regular, gitlinks = [], []
    raw = proc.stdout.decode("utf-8", errors="surrogateescape")
    for record in raw.split("\0"):
        if not record:
            continue
        meta, _, path = record.partition("\t")
        if not path:
            continue
        mode = meta.split(" ", 1)[0]
        if mode == "160000":
            gitlinks.append(path)
        else:
            regular.append(path)
    return regular, gitlinks


def _walk_files(root: str):
    """Return (paths, unscanned, gitlinks). Directory read errors are
    reported through os.walk's onerror into `unscanned` instead of being
    swallowed (os.walk's default). Submodule roots (a directory holding
    a `.git` *file*) are not descended into."""
    paths, unscanned, gitlinks = [], [], []

    def _onerror(exc):
        bad = getattr(exc, "filename", None) or root
        rel = os.path.relpath(bad, root).replace(os.sep, "/")
        unscanned.append({"path": rel, "reason": f"unreadable: {exc}"})

    for dirpath, dirnames, filenames in os.walk(
            root, onerror=_onerror, followlinks=False):
        keep = []
        for name in sorted(dirnames):
            full_dir = os.path.join(dirpath, name)
            if name in SKIP_DIRS or os.path.islink(full_dir):
                continue
            if os.path.isfile(os.path.join(full_dir, ".git")):
                gitlinks.append(
                    os.path.relpath(full_dir, root).replace(os.sep, "/"))
                continue
            keep.append(name)
        dirnames[:] = keep
        for name in sorted(filenames):
            paths.append(os.path.relpath(os.path.join(dirpath, name), root))
    return paths, unscanned, gitlinks


def collect_files(root: str):
    """Return (paths, source, extra_unscanned, extra_warnings)."""
    tracked = _git_tracked_files(root)
    if tracked is not None:
        regular, gitlinks = tracked
        extra = [{"path": g.replace(os.sep, "/"),
                  "reason": "submodule (not scanned)"} for g in gitlinks]
        return regular, "git", extra, []
    paths, walk_unscanned, walk_gitlinks = _walk_files(root)
    extra = walk_unscanned + [
        {"path": g, "reason": "submodule (not scanned)"}
        for g in walk_gitlinks]
    warnings = []
    if os.path.exists(os.path.join(root, ".git")):
        # A .git entry exists but ls-files failed: the fallback changes
        # the scan's scope (untracked files are now in), so say so.
        warnings.append(
            "git ls-files failed — fell back to directory walk; "
            "scan scope changed (untracked files are now included)")
    return paths, "walk", extra, warnings


def _load_ignore_patterns(root: str):
    """Patterns from <root>/expiry-radar.ignore: one glob or substring
    per line, '#' comments. This is the supported way to bless
    intentional expired fixtures (auth negative tests, TLS
    expired-cert fixtures, VCR cassettes) — cassettes/ and friends are
    deliberately NOT auto-suppressed; see ANALYSIS.md #17."""
    path = os.path.join(root, IGNORE_FILENAME)
    patterns = []
    try:
        if not os.path.isfile(path):
            return patterns
        with open(path, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if line and not line.startswith("#"):
                    patterns.append(line)
    except OSError:
        return patterns
    return patterns


def _is_ignored(rel: str, patterns) -> bool:
    for pattern in patterns:
        if pattern in rel or fnmatch.fnmatchcase(rel, pattern):
            return True
    return False


def _is_binary(data: bytes) -> bool:
    return b"\x00" in data[:8192]


def scan(root: str, now: datetime, days: int = DEFAULT_DAYS,
         max_file_size: int = MAX_FILE_SIZE) -> ScanResult:
    if max_file_size < 0:
        raise ValueError("max_file_size must be >= 0")
    root = os.path.abspath(root)
    result = ScanResult(root=root, now=now, days=days)
    rel_paths, source, extra_unscanned, extra_warnings = collect_files(root)
    result.source = source
    result.unscanned.extend(extra_unscanned)
    result.warnings.extend(extra_warnings)
    ignore_patterns = _load_ignore_patterns(root)
    for rel_os in sorted(rel_paths):
        rel = rel_os.replace(os.sep, "/")
        full = os.path.join(root, rel_os)
        if _is_ignored(rel, ignore_patterns):
            result.unscanned.append(
                {"path": rel, "reason": "ignored by expiry-radar.ignore"})
            continue
        if os.path.islink(full):
            result.unscanned.append(
                {"path": rel, "reason": "symlink not followed"})
            continue
        try:
            st = os.lstat(full)
        except OSError as exc:
            result.unscanned.append(
                {"path": rel, "reason": f"unreadable: {exc}"})
            continue
        if not stat.S_ISREG(st.st_mode):
            # FIFOs, devices, sockets, stray directories: never opened
            # (opening a FIFO blocks forever — that was the hang).
            result.unscanned.append(
                {"path": rel, "reason": "not a regular file (not scanned)"})
            continue
        if st.st_size > max_file_size:
            result.unscanned.append({
                "path": rel,
                "reason": f"too large ({st.st_size} bytes > {max_file_size})",
                "size": st.st_size,
            })
            continue
        try:
            with open(full, "rb") as fh:
                # Bounded read: even if the file grows after lstat, we
                # never read more than the cap + 1 byte.
                data = fh.read(max_file_size + 1)
        except OSError as exc:
            result.unscanned.append(
                {"path": rel, "reason": f"unreadable: {exc}"})
            continue
        if len(data) > max_file_size:
            result.unscanned.append({
                "path": rel,
                "reason": f"too large (> {max_file_size} bytes)",
                "size": st.st_size,
            })
            continue
        ext = os.path.splitext(rel)[1].lower()
        if _is_binary(data):
            # Binary: the only artefact we trust here is a whole-file
            # DER certificate — attempted for cert extensions, and for
            # ANY binary starting with 0x30 (DER SEQUENCE) whatever its
            # extension. Everything else binary is listed as unscanned
            # ("binary — not searched") and does NOT count as scanned:
            # embedded text patterns in binary blobs are too FP-prone.
            if ext in DER_EXTENSIONS or data[:1] == b"\x30":
                der_findings = scan_cert_der(
                    data, rel, now, days, result.warnings,
                    warn_on_fail=(ext in DER_EXTENSIONS))
                if der_findings:
                    result.files_scanned += 1
                    result.findings.extend(der_findings)
                    continue
                if ext in DER_EXTENSIONS:
                    result.files_scanned += 1  # attempted; warning stands
                    continue
            result.unscanned.append(
                {"path": rel, "reason": "binary — not searched"})
            continue
        result.files_scanned += 1
        offsets = _newline_offsets(data)
        file_findings = []
        file_findings.extend(scan_certs_pem(
            data, rel, now, days, result.warnings,
            newline_offsets=offsets))
        if ext in DER_EXTENSIONS and PEM_BEGIN not in data:
            file_findings.extend(scan_cert_der(
                data, rel, now, days, result.warnings, warn_on_fail=True))
        file_findings.extend(scan_jwts(
            data, rel, now, days, result.warnings,
            newline_offsets=offsets))
        text = data.decode("utf-8", errors="replace")
        file_findings.extend(scan_dates(text, rel, now, days,
                                        include_doc=True))
        if _is_doc_file(rel):
            # Doc exemption applies to certs/JWTs/dates alike — but the
            # suppression is counted, never silent.
            result.suppressed_in_docs += len(file_findings)
        else:
            result.findings.extend(file_findings)
    result.findings.sort(key=lambda f: (f.status != "expired",
                                        f.status != "expiring",
                                        f.days_left, f.path, f.line))
    return result


# --------------------------------------------------------------------------
# Reporting
# --------------------------------------------------------------------------

def render_text(result: ScanResult, show_safe: bool = False) -> str:
    lines = []
    lines.append(f"Expiry Radar {__version__} — {_sanitize(result.root)}")
    lines.append(f"as of {result.now.strftime('%Y-%m-%d')} UTC, "
                 f"warning window {result.days}d, "
                 f"files scanned: {result.files_scanned} "
                 f"(source: {result.source})")
    lines.append("")
    shown = result.expired + result.expiring + (result.safe if show_safe else [])
    if not shown:
        lines.append("No expired or expiring artefacts found.")
    for finding in shown:
        lines.append(
            f"[{finding.status.upper():8}] {finding.kind:12} "
            f"{_sanitize(finding.path)}:{finding.line}  "
            f"expires {_sanitize(finding.expires)} "
            f"({finding.days_left:+d}d)  {_cap(finding.detail)}"
            + (f"  [{_sanitize(finding.evidence)}]"
               if finding.evidence else "")
        )
    lines.append("")
    lines.append(
        f"Summary: {len(result.expired)} expired, "
        f"{len(result.expiring)} expiring (<{result.days}d), "
        f"{len(result.safe)} safe (counted, not listed unless --show-safe)"
    )
    if result.suppressed_in_docs:
        lines.append(
            f"Suppressed in documentation files: "
            f"{result.suppressed_in_docs} (counted as suppressed_in_docs "
            f"in JSON, not listed)")
    if result.unscanned:
        lines.append(f"Unscanned files ({len(result.unscanned)}):")
        for item in result.unscanned:
            lines.append(f"  - {_sanitize(item['path'])}: "
                         f"{_sanitize(item['reason'])}")
    if result.warnings:
        lines.append(f"Warnings ({len(result.warnings)}):")
        for warning in result.warnings:
            lines.append(f"  - {_sanitize(warning)}")
    lines.append(f"Exit code: {result.exit_code()} "
                 f"(0 clean, 1 expiring, 2 expired, 3 usage error)")
    return "\n".join(lines) + "\n"


def to_json_dict(result: ScanResult, show_safe: bool = False) -> dict:
    return {
        "tool": "expiry-radar",
        "version": __version__,
        "root": result.root,
        "now": result.now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "days": result.days,
        "file_source": result.source,
        "files_scanned": result.files_scanned,
        "suppressed_in_docs": result.suppressed_in_docs,
        "summary": {
            "expired": len(result.expired),
            "expiring": len(result.expiring),
            "safe": len(result.safe),
            "findings": len(result.expired) + len(result.expiring),
            "unscanned": len(result.unscanned),
            "warnings": len(result.warnings),
            "suppressed_in_docs": result.suppressed_in_docs,
        },
        "findings": [f.to_dict() for f in result.expired + result.expiring],
        "safe": [f.to_dict() for f in result.safe] if show_safe else [],
        "unscanned": result.unscanned,
        "warnings": result.warnings,
        "exit_code": result.exit_code(),
    }


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

class _ArgumentParser(argparse.ArgumentParser):
    """Usage errors exit 3, never 2: exit 2 means 'expired finding'
    for this tool, and CI must not confuse the two."""

    def error(self, message):
        self.print_usage(sys.stderr)
        self.exit(3, f"{self.prog}: error: {message}\n")


def _parse_now(value: str) -> datetime:
    try:
        parsed = datetime.strptime(value, "%Y-%m-%d")
    except ValueError:
        raise argparse.ArgumentTypeError(
            f"--now must be YYYY-MM-DD, got {value!r}")
    return parsed.replace(tzinfo=timezone.utc)


def main(argv=None) -> int:
    parser = _ArgumentParser(
        prog="expiry-radar",
        description="Find repo artefacts that break on a known future date: "
                    "expiring X.509 certs, committed JWTs past their exp, and "
                    "hardcoded valid-until dates in fixtures.")
    parser.add_argument("path", nargs="?", default=".",
                        help="repo / directory to scan (default: .)")
    parser.add_argument("--json", action="store_true",
                        help="emit a JSON report instead of text")
    parser.add_argument("--show-safe", action="store_true",
                        help="also list safe (>window) artefacts")
    parser.add_argument("--days", type=int, default=DEFAULT_DAYS,
                        help=f"warning window in days (default: {DEFAULT_DAYS})")
    parser.add_argument("--now", type=_parse_now, default=None,
                        help="override 'today' (YYYY-MM-DD, UTC) — for "
                             "deterministic tests and what-if runs")
    parser.add_argument("--max-file-size", type=int, default=MAX_FILE_SIZE,
                        help="skip files larger than this many bytes "
                             "(they are reported as unscanned)")
    args = parser.parse_args(argv)
    if args.days < 0:
        parser.error("--days must be >= 0")
    if args.max_file_size < 0:
        parser.error("--max-file-size must be >= 0")
    if not os.path.isdir(args.path):
        print(f"expiry-radar: not a directory: {args.path}", file=sys.stderr)
        return 3
    now = args.now or datetime.now(timezone.utc)
    result = scan(args.path, now=now, days=args.days,
                  max_file_size=args.max_file_size)
    if args.json:
        print(json.dumps(to_json_dict(result, show_safe=args.show_safe),
                         indent=2, ensure_ascii=False))
    else:
        sys.stdout.write(render_text(result, show_safe=args.show_safe))
    return result.exit_code()


if __name__ == "__main__":
    raise SystemExit(main())
