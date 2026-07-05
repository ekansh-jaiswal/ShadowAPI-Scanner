"""
scanner/log_parser.py
=====================
Parses Nginx combined-format access.log + companion access_headers.log (JSONL)
into EndpointRecord dataclasses, normalising concrete path segments into
parameterised templates (e.g. /api/v1/patients/104 → /api/v1/patients/{id}).

Join strategy between the two log files
----------------------------------------
The generator writes access.log and access_headers.log in lockstep — line N
in access.log corresponds exactly to line N in access_headers.log.  We exploit
this by doing a *positional join* (zip) when both files are present.

In a real deployment the paired JSONL file would come from an enhanced Nginx
log format (``$http_authorization``) or an APM/WAF system that already
embeds the auth header alongside each request record, so positional alignment
is guaranteed.  If you ever move to a system where ordering is not guaranteed,
inject a ``$request_id`` (Nginx variable, or UUID added by an API gateway) into
both log streams and join on that instead.

Path normalisation rules (applied in order)
--------------------------------------------
1. UUID v4 segment               → {id}
2. Pure-numeric segment          → {id}
3. Hex-only segment (≥8 chars)   → {id}
4. Base64url-ish token (≥16 chars, mixed alnum + - / _) → {id}
   (catches short-lived JWTs and opaque tokens in path position)
5. Query string is stripped from the template; query params are stored raw.

Public API
----------
    parse_logs(access_log, headers_log=None) -> ParseResult
    ParseResult.endpoint_records  : list[EndpointRecord]
    ParseResult.by_template       : dict[str, EndpointRecord]   (deduplicated)
"""

from __future__ import annotations

import json
import re
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

# ─────────────────────────────────────────────────────────────────────────────
# Nginx combined log regex
# Format: $remote_addr - $remote_user [$time_local] "$request"
#          $status $body_bytes_sent "$http_referer" "$http_user_agent"
# ─────────────────────────────────────────────────────────────────────────────
_NGINX_RE = re.compile(
    r'^(?P<remote_addr>\S+)'          # source IP
    r' - '
    r'(?P<remote_user>\S+)'           # remote user (usually '-')
    r' \[(?P<time_local>[^\]]+)\] '   # [timestamp]
    r'"(?P<method>[A-Z]+) '           # HTTP method
    r'(?P<full_path>\S+) '            # path (may include query string)
    r'HTTP/\d\.\d" '
    r'(?P<status>\d{3}) '             # status code
    r'(?P<bytes>\d+) '                # bytes sent
    r'"(?P<referer>[^"]*)" '          # referer
    r'"(?P<user_agent>[^"]*)"'        # user agent
)

# ─────────────────────────────────────────────────────────────────────────────
# Path normalisation patterns (applied in order)
# ─────────────────────────────────────────────────────────────────────────────
_UUID_RE = re.compile(
    r'(?<=/)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}(?=/|$)',
    re.IGNORECASE,
)
_NUMERIC_RE    = re.compile(r'(?<=/)\d+(?=/|$)')
_HEX_TOKEN_RE  = re.compile(r'(?<=/)[0-9a-f]{8,}(?=/|$)', re.IGNORECASE)
# Opaque token: long alnum-only run (no hyphens — those indicate human-readable
# slugs like 'insurance-claims', not tokens).  Underscore allowed (base64url).
_B64_TOKEN_RE  = re.compile(r'(?<=/)[A-Za-z0-9_]{16,}(?=/|$)')

_MAX_SAMPLE_PATHS  = 5    # raw path samples kept per template (for report evidence)
_MAX_SAMPLE_TOKENS = 10   # unique token values kept per template


# ─────────────────────────────────────────────────────────────────────────────
# Data classes
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class RawEntry:
    """One parsed line from the two log files, before aggregation."""
    line_no:      int
    source_ip:    str
    time_local:   str
    method:       str
    raw_path:     str           # full path with query string
    path_only:    str           # path without query string
    query_string: str           # everything after '?' (empty string if none)
    status:       int
    bytes_sent:   int
    user_agent:   str
    # From access_headers.log (None if file not available)
    has_auth:     Optional[bool]    = None
    token:        Optional[str]     = None
    token_owner:  Optional[str]     = None


@dataclass
class EndpointRecord:
    """
    Aggregated statistics for one normalised path template
    (e.g. /api/v1/patients/{id}).
    """
    path_template:      str
    methods_seen:       set[str]               = field(default_factory=set)
    hit_count:          int                    = 0
    status_codes:       Counter                = field(default_factory=Counter)
    source_ips:         set[str]               = field(default_factory=set)
    # Evidence for the report
    sample_raw_paths:   list[str]              = field(default_factory=list)
    sample_tokens:      list[str]              = field(default_factory=list)
    # Auth-presence stats (populated only when headers log is available)
    auth_present_count: int                    = 0
    auth_absent_count:  int                    = 0
    # All raw entries (risk engine reads these for per-request analysis)
    raw_entries:        list[RawEntry]         = field(default_factory=list)

    # Convenience properties
    @property
    def auth_coverage(self) -> str:
        """Human-readable auth coverage string, e.g. '108/124 had auth'."""
        total = self.auth_present_count + self.auth_absent_count
        if total == 0:
            return "unknown (no header log)"
        return f"{self.auth_present_count}/{total} requests had Authorization header"

    @property
    def never_authenticated(self) -> bool:
        """True if zero requests to this template ever included an auth header."""
        total = self.auth_present_count + self.auth_absent_count
        return total > 0 and self.auth_present_count == 0

    @property
    def sometimes_unauthenticated(self) -> bool:
        """True if some (but not all) requests lacked an auth header."""
        return self.auth_absent_count > 0 and self.auth_present_count > 0


@dataclass
class ParseResult:
    """Top-level result returned by parse_logs()."""
    endpoint_records:  list[EndpointRecord]         # sorted by hit_count desc
    by_template:       dict[str, EndpointRecord]    # keyed by path_template
    total_lines:       int
    parse_errors:      int
    header_log_joined: bool                         # True if JSONL file was merged


# ─────────────────────────────────────────────────────────────────────────────
# Core normalisation
# ─────────────────────────────────────────────────────────────────────────────

def normalise_path(path: str) -> str:
    """
    Convert a concrete path into a parameterised template.

    /api/v1/patients/104                 → /api/v1/patients/{id}
    /api/v1/patient-records/115          → /api/v1/patient-records/{id}
    /api/v1/internal/debug/patient/108   → /api/v1/internal/debug/patient/{id}
    /api/v1/appointments/1003            → /api/v1/appointments/{id}
    /api/v1/doctors/3                    → /api/v1/doctors/{id}
    /api/v1/patients/104/insurance-claims→ /api/v1/patients/{id}/insurance-claims
    /api/v1/otp/verify                   → /api/v1/otp/verify   (no segments to replace)
    /api/v1/health                       → /api/v1/health
    /api/v1/report/8f14e45f              → /api/v1/report/{id}
    """
    p = path.split("?")[0]          # strip query string
    p = _UUID_RE.sub("{id}", p)
    p = _NUMERIC_RE.sub("{id}", p)
    p = _HEX_TOKEN_RE.sub("{id}", p)
    p = _B64_TOKEN_RE.sub("{id}", p)
    return p


# ─────────────────────────────────────────────────────────────────────────────
# Parsing helpers
# ─────────────────────────────────────────────────────────────────────────────

def _parse_access_log(path: Path) -> tuple[list[RawEntry], int]:
    """
    Parse Nginx combined-format access.log.
    Returns (entries, error_count).
    """
    entries: list[RawEntry] = []
    errors = 0

    with path.open("r", encoding="utf-8", errors="replace") as fh:
        for lineno, line in enumerate(fh, start=1):
            line = line.rstrip("\n")
            m = _NGINX_RE.match(line)
            if not m:
                errors += 1
                continue

            full_path = m.group("full_path")
            if "?" in full_path:
                path_only, qs = full_path.split("?", 1)
            else:
                path_only, qs = full_path, ""

            entries.append(RawEntry(
                line_no      = lineno,
                source_ip    = m.group("remote_addr"),
                time_local   = m.group("time_local"),
                method       = m.group("method"),
                raw_path     = full_path,
                path_only    = path_only,
                query_string = qs,
                status       = int(m.group("status")),
                bytes_sent   = int(m.group("bytes")),
                user_agent   = m.group("user_agent"),
            ))

    return entries, errors


def _parse_headers_log(path: Path) -> list[dict]:
    """
    Parse access_headers.log (JSONL).
    Returns one dict per line; malformed lines are skipped.
    """
    records: list[dict] = []
    with path.open("r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                pass
    return records


class LogMismatchError(ValueError):
    """
    Raised when access.log and access_headers.log have different line counts.

    Both files are written in lockstep by generate_logs.py; a count drift means
    one file was truncated, partially overwritten, or the generator crashed mid-
    run.  We refuse to continue rather than silently misattribute auth data to
    the wrong requests.

    Recovery options:
      1. Re-run generate_logs.py to regenerate both files from scratch.
      2. Pass headers_log_path=None to parse_logs() to skip auth merging.
      3. If you move to a system without guaranteed lockstep ordering, inject a
         shared request-id into both log streams (e.g. Nginx $request_id + the
         same UUID written to the JSONL) and join on that key instead.
    """


def _merge_headers(entries: list[RawEntry], header_records: list[dict]) -> None:
    """
    Positional join: entry[i] ↔ header_records[i].

    Both files MUST have the same line count.  If they diverge this function
    raises ``LogMismatchError`` immediately — we fail loudly rather than
    silently producing wrong auth statistics.

    Why positional and not key-based?
    ----------------------------------
    The generator writes both files inside the same loop iteration, so they are
    guaranteed to be in sync.  Key-based joining would require either (a) a
    shared request-id written to both streams, or (b) a composite key of
    (timestamp + IP + method + path) which is only unique-enough when timestamps
    have sub-second resolution — Nginx's ``$time_local`` is second-granular, so
    multiple requests in the same second would collide.  The positional approach
    is more robust *given the lockstep guarantee*, and the count assertion below
    enforces that guarantee at parse time.
    """
    n_access  = len(entries)
    n_headers = len(header_records)

    if n_access != n_headers:
        # Find first divergence point for actionable diagnostics
        diverge_at = min(n_access, n_headers)  # both agree up to this index
        shorter    = "access.log" if n_access < n_headers else "access_headers.log"
        longer     = "access_headers.log" if n_access < n_headers else "access.log"
        raise LogMismatchError(
            f"\n"
            f"  access.log has {n_access} lines, "
            f"access_headers.log has {n_headers} lines — they MUST match.\n"
            f"  {shorter} is {abs(n_access - n_headers)} line(s) shorter than {longer}.\n"
            f"  Both files agree up to line {diverge_at}; divergence starts at "
            f"line {diverge_at + 1}.\n"
            f"  Fix: re-run  python mock_env/generate_logs.py  to regenerate both files,\n"
            f"       or call parse_logs(..., headers_log_path=None) to skip auth merging."
        )

    # Fast path — guaranteed positional alignment
    for entry, hrec in zip(entries, header_records):
        entry.has_auth    = hrec.get("has_authorization", False)
        entry.token       = hrec.get("token")
        entry.token_owner = hrec.get("token_owner")





# ─────────────────────────────────────────────────────────────────────────────
# Aggregation
# ─────────────────────────────────────────────────────────────────────────────

def _aggregate(entries: list[RawEntry]) -> dict[str, EndpointRecord]:
    """Group RawEntry objects by path template, building EndpointRecord for each."""
    agg: dict[str, EndpointRecord] = {}
    seen_raw_paths: dict[str, set[str]]   = defaultdict(set)
    seen_tokens:    dict[str, set[str]]   = defaultdict(set)

    for entry in entries:
        tmpl = normalise_path(entry.path_only)

        if tmpl not in agg:
            agg[tmpl] = EndpointRecord(path_template=tmpl)

        rec = agg[tmpl]
        rec.hit_count       += 1
        rec.methods_seen.add(entry.method)
        rec.status_codes[entry.status] += 1
        rec.source_ips.add(entry.source_ip)
        rec.raw_entries.append(entry)

        # Sample raw paths (store query string too for OTP/search endpoints)
        raw = entry.raw_path
        if raw not in seen_raw_paths[tmpl] and len(rec.sample_raw_paths) < _MAX_SAMPLE_PATHS:
            seen_raw_paths[tmpl].add(raw)
            rec.sample_raw_paths.append(raw)

        # Auth stats
        if entry.has_auth is not None:
            if entry.has_auth:
                rec.auth_present_count += 1
                # Sample tokens
                if entry.token and entry.token not in seen_tokens[tmpl] \
                        and len(rec.sample_tokens) < _MAX_SAMPLE_TOKENS:
                    seen_tokens[tmpl].add(entry.token)
                    rec.sample_tokens.append(entry.token)
            else:
                rec.auth_absent_count += 1

    return agg


# ─────────────────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────────────────

def parse_logs(
    access_log_path: str | Path,
    headers_log_path: Optional[str | Path] = None,
) -> ParseResult:
    """
    Parse access.log (+ optional access_headers.log) and return a ParseResult.

    Parameters
    ----------
    access_log_path  : path to Nginx combined-format access log
    headers_log_path : path to companion JSONL headers log; pass None to skip
                       (auth-presence stats will be unavailable)

    Returns
    -------
    ParseResult with fully populated EndpointRecord objects.
    """
    access_log_path = Path(access_log_path)
    if not access_log_path.exists():
        raise FileNotFoundError(f"access.log not found: {access_log_path}")

    entries, errors = _parse_access_log(access_log_path)

    joined = False
    if headers_log_path is not None:
        headers_log_path = Path(headers_log_path)
        if headers_log_path.exists():
            header_records = _parse_headers_log(headers_log_path)
            _merge_headers(entries, header_records)
            joined = True

    by_template = _aggregate(entries)

    # Sort by hit count descending for report ordering
    sorted_records = sorted(by_template.values(), key=lambda r: r.hit_count, reverse=True)

    return ParseResult(
        endpoint_records  = sorted_records,
        by_template       = by_template,
        total_lines       = len(entries),
        parse_errors      = errors,
        header_log_joined = joined,
    )


# ─────────────────────────────────────────────────────────────────────────────
# __main__ — sanity-check against the generated logs
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse as ap

    cli = ap.ArgumentParser(description="Run log_parser against generated log files")
    cli.add_argument("--log",     default="mock_env/access.log",
                     help="Path to Nginx access.log")
    cli.add_argument("--headers", default="mock_env/access_headers.log",
                     help="Path to companion JSONL headers log")
    args = cli.parse_args()

    print(f"Parsing: {args.log}")
    print(f"Headers: {args.headers}")
    print()

    result = parse_logs(args.log, args.headers)

    print(f"Total lines parsed : {result.total_lines}")
    print(f"Parse errors       : {result.parse_errors}")
    print(f"Header log joined  : {result.header_log_joined}")
    print(f"Unique templates   : {len(result.endpoint_records)}")
    print()

    # ── Normalisation spot-check ───────────────────────────────────────────
    test_cases = [
        ("/api/v1/patients/104",                    "/api/v1/patients/{id}"),
        ("/api/v1/patient-records/115",             "/api/v1/patient-records/{id}"),
        ("/api/v1/internal/debug/patient/108",      "/api/v1/internal/debug/patient/{id}"),
        ("/api/v1/appointments/1003",               "/api/v1/appointments/{id}"),
        ("/api/v1/doctors/3",                       "/api/v1/doctors/{id}"),
        ("/api/v1/patients/104/insurance-claims",   "/api/v1/patients/{id}/insurance-claims"),
        ("/api/v1/otp/verify",                      "/api/v1/otp/verify"),
        ("/api/v1/health",                          "/api/v1/health"),
        ("/api/v1/report/8f14e45f",                 "/api/v1/report/{id}"),
    ]
    print("Path normalisation spot-check:")
    all_ok = True
    for raw, expected in test_cases:
        got = normalise_path(raw)
        status = "✅" if got == expected else "❌"
        if got != expected:
            all_ok = False
        print(f"  {status}  {raw:<50}  →  {got}")
    print(f"  {'All pass ✅' if all_ok else 'FAILURES ABOVE ❌'}")
    print()

    # ── Summary table ──────────────────────────────────────────────────────
    COL_W = 50
    H1 = f"{'PATH TEMPLATE':<{COL_W}} {'HITS':>5}  {'METHODS':<20}  {'STATUS CODES':<30}  AUTH"
    print("=" * (len(H1) + 2))
    print(H1)
    print("=" * (len(H1) + 2))

    for rec in result.endpoint_records:
        methods   = ",".join(sorted(rec.methods_seen))
        statuses  = "  ".join(f"{k}×{v}" for k, v in sorted(rec.status_codes.items()))
        auth_info = rec.auth_coverage

        # First line: template + counts
        print(f"{rec.path_template:<{COL_W}} {rec.hit_count:>5}  {methods:<20}  {statuses:<30}  {auth_info}")

        # Second line: sample raw paths (indented)
        for sp in rec.sample_raw_paths[:2]:
            print(f"  {'':>{COL_W-2}}  sample: {sp}")

        # Third line: source IPs (abbreviated)
        ips = ", ".join(sorted(rec.source_ips)[:4])
        if len(rec.source_ips) > 4:
            ips += f" … (+{len(rec.source_ips)-4} more)"
        print(f"  {'':>{COL_W-2}}  IPs: {ips}")
        print()

    # ── Auth-absent highlights ─────────────────────────────────────────────
    print("=" * (len(H1) + 2))
    print("ENDPOINTS WITH MISSING AUTH (any requests lacking Authorization header):")
    print("=" * (len(H1) + 2))
    for rec in result.endpoint_records:
        if rec.auth_absent_count > 0:
            pct = 100 * rec.auth_absent_count / (rec.auth_present_count + rec.auth_absent_count)
            flag = "⚠ NEVER AUTHENTICATED" if rec.never_authenticated else "⚠ SOMETIMES UNAUTHENTICATED"
            print(f"  {flag}: {rec.path_template}")
            print(f"           {rec.auth_absent_count} unauthenticated / {rec.hit_count} total  ({pct:.0f}%)")
    print()
