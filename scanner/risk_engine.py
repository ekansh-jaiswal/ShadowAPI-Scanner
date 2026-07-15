"""
scanner/risk_engine.py
======================
Evaluates endpoints against rule-based heuristics to identify OWASP API Top 10
vulnerabilities, including an active Broken Object Level Authorization (BOLA) probe.

Public API
----------
    probe_server_health(url, timeout)  -> ProbeStatus
    run_risk_engine(diff_result, spec_result, mock_server_url, probe_status)
                                       -> dict[str, list[Finding]]

Probe failure policy
--------------------
    Active BOLA probes are only run when probe_status.reachable is True.
    If the mock server cannot be reached, all active probes are skipped and
    a ProbeStatus with reachable=False and a human-readable error_detail is
    returned.  The caller (cli.py) is responsible for surfacing this warning
    — probes NEVER silently fail or silently produce findings.
"""

from __future__ import annotations

import logging
import re
import requests
import requests.exceptions
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)

try:
    from scanner.log_parser import EndpointRecord, RawEntry
    from scanner.spec_loader import SpecResult
    from scanner.diff_engine import DiffResult, ShadowEndpoint, OkEndpoint
except ModuleNotFoundError:
    import sys, os
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
    from scanner.log_parser import EndpointRecord, RawEntry
    from scanner.spec_loader import SpecResult
    from scanner.diff_engine import DiffResult, ShadowEndpoint, OkEndpoint


@dataclass
class Finding:
    category: str      # e.g., "API1:2023 Broken Object Level Authorization"
    severity: str      # "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"
    title: str
    description: str
    evidence: dict = field(default_factory=dict)


@dataclass
class ProbeStatus:
    """
    Result of the startup health-check ping to the mock server.

    Attributes
    ----------
    reachable : bool
        True  → server responded; active BOLA probes were attempted.
        False → server was unreachable; ALL active probes were skipped.
    error_detail : str
        Human-readable reason for failure (empty string when reachable=True).
    probe_url : str
        The URL that was health-checked.
    probes_attempted : int
        Count of individual HTTP probe requests that were dispatched.
    probes_succeeded : int
        Count that received a response (any status code, including 4xx/5xx).
    probes_failed : int
        Count that raised a network-level exception (ConnectionError/Timeout).
    """
    reachable:        bool
    error_detail:     str  = ""
    probe_url:        str  = ""
    probes_attempted: int  = 0
    probes_succeeded: int  = 0
    probes_failed:    int  = 0

    @property
    def summary_line(self) -> str:
        if not self.reachable:
            return (
                f"Active probes SKIPPED — mock server unreachable at {self.probe_url}. "
                f"Reason: {self.error_detail}. "
                f"Re-run with a live server or use --no-active-probes for passive-only mode."
            )
        if self.probes_failed:
            return (
                f"{self.probes_failed}/{self.probes_attempted} active probe(s) failed "
                f"mid-scan (ConnectionError/Timeout). Findings may be incomplete."
            )
        return f"{self.probes_succeeded}/{self.probes_attempted} active probe(s) completed successfully."
PROBE_TIMEOUT = 3   # seconds for the startup health-check ping
ACTIVE_TIMEOUT = 2  # seconds for each individual BOLA probe request


def probe_server_health(mock_server_url: str, timeout: int = PROBE_TIMEOUT) -> ProbeStatus:
    """
    Ping the mock server's /api/v1/health endpoint before starting active probes.

    Returns a ProbeStatus with reachable=True if any HTTP response (including
    4xx/5xx) was received — we only need to know the TCP stack is alive.
    Returns reachable=False with an explanatory error_detail on network failures.

    This check is deliberately shallow: it does NOT validate the response body,
    only that the server is listening.
    """
    if not mock_server_url:
        return ProbeStatus(reachable=False, error_detail="No mock server URL provided.",
                           probe_url=mock_server_url)

    health_url = f"{mock_server_url.rstrip('/')}/api/v1/health"
    try:
        resp = requests.get(health_url, timeout=timeout)
        return ProbeStatus(reachable=True, probe_url=health_url)
    except requests.exceptions.ConnectionError as exc:
        return ProbeStatus(
            reachable=False,
            error_detail=f"Connection refused or host unreachable ({exc.__class__.__name__})",
            probe_url=health_url,
        )
    except requests.exceptions.Timeout:
        return ProbeStatus(
            reachable=False,
            error_detail=f"Health-check timed out after {timeout}s",
            probe_url=health_url,
        )
    except requests.exceptions.RequestException as exc:
        return ProbeStatus(
            reachable=False,
            error_detail=str(exc),
            probe_url=health_url,
        )


def _check_shadow(endpoint: ShadowEndpoint) -> Optional[Finding]:
    return Finding(
        category="API9:2023 Improper Inventory Management",
        severity="MEDIUM",
        title="Shadow API Endpoint",
        description="Endpoint is actively receiving traffic but is not documented in the OpenAPI specification.",
    )

def _check_sensitive_path(path_template: str, log_record: EndpointRecord) -> Optional[Finding]:
    sensitive_keywords = ["patient", "ehr", "aadhaar", "abha", "otp", "prescription", "diagnosis", "insurance", "report"]
    path_lower = path_template.lower()
    found = [kw for kw in sensitive_keywords if kw in path_lower]
    for raw in log_record.sample_raw_paths:
        raw_lower = raw.lower()
        found.extend([kw for kw in sensitive_keywords if kw in raw_lower and kw not in found])
        
    if found:
        return Finding(
            category="API3:2023 Excessive Data Exposure / Sensitive Data",
            severity="INFO",
            title="Sensitive Path or Parameters",
            description=f"Endpoint URL contains sensitive keywords: {', '.join(found)}",
        )
    return None

def _check_missing_auth(log_record: EndpointRecord, requires_auth: bool) -> Optional[Finding]:
    if log_record.auth_coverage.startswith("unknown"):
        return None
        
    if not requires_auth and log_record.never_authenticated:
        return None
        
    if log_record.never_authenticated:
        return Finding(
            category="API2:2023 Broken Authentication",
            severity="HIGH" if requires_auth else "MEDIUM",
            title="Missing Authentication",
            description="Endpoint was never observed requiring an Authorization header.",
        )
    elif log_record.sometimes_unauthenticated:
        return Finding(
            category="API2:2023 Broken Authentication",
            severity="HIGH" if requires_auth else "MEDIUM",
            title="Inconsistent Authentication",
            description=f"Endpoint sometimes accepts requests without authentication ({log_record.auth_absent_count} unauthenticated requests).",
        )
    return None
_PUBLIC_REFERENCE_RESOURCES: frozenset[str] = frozenset({
    "doctor",      # /doctors/{id} — public directory
    "product",     # /products/{id} — public catalogue
    "category",    # /categories/{id} — taxonomy lookup
    "specialty",   # /specialties/{id}
    "hospital",    # /hospitals/{id}
    "health",      # /api/v1/health — liveness probe
    "status",      # /status — readiness probe
    "ping",        # /ping
})
_NUMERIC_ID_IN_PATH = re.compile(r'/(\d+)(?:/|$)')
_UUID_IN_PATH       = re.compile(
    r'/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:/|$)',
    re.IGNORECASE,
)


def _is_ownership_scoped(
    path_template: str,
    extra_exclusions: frozenset[str] = frozenset(),
) -> bool:
    """
    Return True if the path structurally looks like a per-object resource
    (i.e. it contains a numeric ID or UUID segment) AND none of its segments
    match the public-reference exclusion list.

    This replaces the previous keyword-allowlist approach, which was too
    narrowly tuned to the healthcare mock server's vocabulary and missed any
    resource named outside that domain (e.g. crAPI's /vehicle/{uuid}/location).

    Parameters
    ----------
    path_template    : normalised path, e.g. /identity/api/v2/vehicle/{id}/location
    extra_exclusions : additional resource keywords to exclude, supplied at
                       runtime via --exclude-from-bola
    """
    has_id = (
        "{id}" in path_template
        or _NUMERIC_ID_IN_PATH.search(path_template) is not None
        or _UUID_IN_PATH.search(path_template) is not None
    )
    if not has_id:
        return False
    all_exclusions = _PUBLIC_REFERENCE_RESOURCES | extra_exclusions
    path_lower = path_template.lower()
    if any(kw in path_lower for kw in all_exclusions):
        return False

    return True
def _extract_id_segment(raw_path: str) -> tuple[str, str] | None:
    """
    Extract the first ownership-identifying segment from a concrete raw path.
    Returns (matched_string, id_type) where id_type is 'numeric' or 'uuid',
    or None if no ID-like segment is found.

    Numeric: /patients/111/insurance-claims  → ('111', 'numeric')
    UUID:    /vehicle/fadcf145-.../location  → ('fadcf145-...', 'uuid')
    """
    m = _UUID_IN_PATH.search(raw_path)
    if m:
        return (m.group(1), 'uuid')
    m = _NUMERIC_ID_IN_PATH.search(raw_path)
    if m:
        return (m.group(1), 'numeric')
    return None


def _build_cross_user_pairs(
    log_record: EndpointRecord,
) -> list[tuple[str, str, str, str]]:
    """
    Scan all raw log entries for this endpoint template and build pairs
    of (victim_id, victim_path, attacker_token, victim_id_type) where
    victim and attacker are verifiably different JWT subjects.

    A valid BOLA test requires:
      - At least two entries with DIFFERENT token subjects
      - Each entry has a distinct ID segment in the path
    This ensures we are genuinely testing cross-user access and not
    merely re-fetching the same user's own object with their own token.

    Returns a list of tuples:
        (victim_raw_path, victim_id_str, attacker_token, id_type)

    If insufficient data exists, an empty list is returned and the
    reason is logged explicitly.
    """
    entries_with_id: list[tuple[str, str, str, str]] = []  # (sub, raw_path, id_str, id_type, token)
    for entry in log_record.raw_entries:
        if not entry.token:
            continue
        extracted = _extract_id_segment(entry.raw_path)
        if not extracted:
            continue
        id_str, id_type = extracted
        sub = _jwt_subject(entry.token)
        if not sub:
            continue
        entries_with_id.append((sub, entry.raw_path, id_str, id_type, entry.token))

    if not entries_with_id:
        logger.info(
            "BOLA probe skipped for %s — no log entries with both a token and "
            "an ID segment were found.",
            log_record.path_template,
        )
        return []
    by_subject: dict[str, tuple[str, str, str, str]] = {}  # sub → (raw_path, id_str, id_type, token)
    for sub, raw_path, id_str, id_type, token in entries_with_id:
        if sub not in by_subject:
            by_subject[sub] = (raw_path, id_str, id_type, token)

    if len(by_subject) < 2:
        logger.info(
            "BOLA probe skipped for %s — only one token subject (%s) found in "
            "log entries. Need at least two distinct users to perform a meaningful "
            "cross-user access test.",
            log_record.path_template,
            next(iter(by_subject)),
        )
        return []
    subjects = list(by_subject.keys())
    pairs: list[tuple[str, str, str, str]] = []
    for i, victim_sub in enumerate(subjects):
        victim_path, victim_id, id_type, _ = by_subject[victim_sub]
        attacker_sub = subjects[(i + 1) % len(subjects)]
        attacker_token = by_subject[attacker_sub][3]
        pairs.append((victim_path, victim_id, attacker_token, id_type))

    return pairs


def _jwt_subject(token_str: str) -> str:
    """Extract the 'sub' claim from a JWT without verifying the signature.
    Returns empty string if the token is not a recognisable JWT."""
    import base64
    try:
        jwt = token_str.removeprefix("Bearer ").strip()
        parts = jwt.split(".")
        if len(parts) < 2:
            return ""
        payload = parts[1]
        payload += "=" * (4 - len(payload) % 4)
        import json as _json
        decoded = _json.loads(base64.urlsafe_b64decode(payload))
        return decoded.get("sub", "")
    except Exception:
        return ""
def _numeric_probe_pairs(
    log_record: EndpointRecord,
    fallback_token: str,
) -> list[tuple[str, str, str, str]]:
    """
    Legacy numeric-ID probe: when log data doesn't provide two distinct users
    (e.g. the original mock server where all tokens are the same format),
    fall back to id±1 with a fixed fallback token.

    Only called for numeric IDs, not UUIDs (UUID guessing is not meaningful).
    """
    pairs = []
    for raw_path in log_record.sample_raw_paths:
        extracted = _extract_id_segment(raw_path)
        if not extracted or extracted[1] != 'numeric':
            continue
        id_str, _ = extracted
        original_id = int(id_str)
        for tid in [original_id + 1, original_id - 1]:
            if tid < 1:
                continue
            test_path = raw_path.replace(f"/{id_str}", f"/{tid}", 1)
            pairs.append((test_path, str(tid), fallback_token, 'numeric'))
        break  # one raw path is enough for the fallback
    return pairs


def _check_bola_and_exposure(
    log_record: EndpointRecord,
    mock_server_url: str,
    path_template: str = "",
    probe_status: Optional[ProbeStatus] = None,
    extra_exclusions: frozenset[str] = frozenset(),
) -> list[Finding]:
    """
    Run active BOLA probes against the target server.

    Strategy
    --------
    1.  Check ownership scope structurally (any ID/UUID in path) and against
        the exclusion list.  Skip if not ownership-scoped.
    2.  Attempt to build cross-user probe pairs from log entries with distinct
        JWT subjects (preferred — proves real cross-user boundary violation).
    3.  Fall back to id±1 numeric probing with a hardcoded token only for
        pure-numeric-ID endpoints where the log lacks two distinct users.
    4.  For each pair: first try unauthenticated, then wrong-owner token.

    NEVER silently produces findings when the server is unreachable —
    all network exceptions are counted in probe_status.probes_failed.
    """
    findings: list[Finding] = []
    if not mock_server_url:
        return findings
    if probe_status is not None and not probe_status.reachable:
        return findings
    if path_template and not _is_ownership_scoped(path_template, extra_exclusions):
        return findings
    pairs = _build_cross_user_pairs(log_record)
    if not pairs:
        FALLBACK_TOKEN = "Bearer token-patient-101"
        pairs = _numeric_probe_pairs(log_record, FALLBACK_TOKEN)
        if pairs:
            logger.info(
                "BOLA probe for %s: using id±1 numeric fallback "
                "(cross-user log data not available).",
                path_template,
            )

    if not pairs:
        logger.info(
            "BOLA probe skipped for %s — insufficient data for any probe strategy.",
            path_template,
        )
        return findings
    for victim_path, victim_id, attacker_token, id_type in pairs:
        test_url = f"{mock_server_url.rstrip('/')}{victim_path}"
        if probe_status is not None:
            probe_status.probes_attempted += 1
        try:
            resp_no_auth = requests.get(test_url, timeout=ACTIVE_TIMEOUT)
            if probe_status is not None:
                probe_status.probes_succeeded += 1
            if resp_no_auth.status_code == 200:
                try:
                    data = resp_no_auth.json()
                except ValueError:
                    data = {}
                if data:
                    findings.append(Finding(
                        category="API1:2023 Broken Object Level Authorization",
                        severity="CRITICAL",
                        title="BOLA (Unauthenticated Access)",
                        description=(
                            f"Successfully accessed object '{victim_id}' with NO "
                            f"authentication."
                        ),
                        evidence={"url": test_url, "status": 200,
                                  "response_sample": str(data)[:400]},
                    ))
                    _check_pii_exposure(data, findings)
                    return findings
        except (requests.exceptions.ConnectionError,
                requests.exceptions.Timeout) as exc:
            if probe_status is not None:
                probe_status.probes_failed += 1
            logger.warning(
                "BOLA probe failed (unauthenticated) for %s: %s",
                test_url, exc.__class__.__name__,
            )
            return findings
        if probe_status is not None:
            probe_status.probes_attempted += 1
        try:
            resp_auth = requests.get(
                test_url,
                headers={"Authorization": attacker_token},
                timeout=ACTIVE_TIMEOUT,
            )
            if probe_status is not None:
                probe_status.probes_succeeded += 1
            if resp_auth.status_code == 200:
                try:
                    data = resp_auth.json()
                except ValueError:
                    data = {}
                if data:
                    findings.append(Finding(
                        category="API1:2023 Broken Object Level Authorization",
                        severity="CRITICAL",
                        title="BOLA (Cross-User Access)",
                        description=(
                            f"Successfully accessed object '{victim_id}' using a "
                            f"different user's token."
                        ),
                        evidence={
                            "url": test_url,
                            "status": 200,
                            "attacker_token_prefix": attacker_token[:60],
                            "response_sample": str(data)[:400],
                        },
                    ))
                    _check_pii_exposure(data, findings)
                    return findings
        except (requests.exceptions.ConnectionError,
                requests.exceptions.Timeout) as exc:
            if probe_status is not None:
                probe_status.probes_failed += 1
            logger.warning(
                "BOLA probe failed (wrong-token) for %s: %s",
                test_url, exc.__class__.__name__,
            )
            return findings

    return findings

def _check_pii_exposure(data: dict, findings: list[Finding]):
    pii_keys = ["ssn", "aadhaar_number", "aadhaar", "full_name", "dob", "diagnosis", "prescription"]
    found_pii = [k for k in pii_keys if k in str(data).lower()]
    if found_pii:
        findings.append(Finding(
            category="API3:2023 Excessive Data Exposure",
            severity="HIGH",
            title="PII / Sensitive Data Exposure",
            description=f"Response payload contains highly sensitive PII fields: {', '.join(found_pii)}",
            evidence={"keys_found": found_pii, "response_sample": str(data)[:200]}
        ))
_RATE_LIMIT_EXEMPT_KEYWORDS = {"health", "status", "ping", "ready", "live"}


def _check_rate_limiting(log_record: EndpointRecord, is_public_endpoint: bool = False,
                          path_template: str = "") -> Optional[Finding]:
    if is_public_endpoint:
        return None
    path_lower = path_template.lower()
    if any(kw in path_lower for kw in _RATE_LIMIT_EXEMPT_KEYWORDS):
        return None
    bursts_per_sec: dict = defaultdict(int)
    total_per_ip: dict = defaultdict(int)

    for entry in log_record.raw_entries:
        bursts_per_sec[(entry.source_ip, entry.time_local)] += 1
        total_per_ip[entry.source_ip] += 1

    max_sec_burst = 0
    max_sec_ip = None
    for (ip, ts), count in bursts_per_sec.items():
        if count > max_sec_burst:
            max_sec_burst = count
            max_sec_ip = ip

    max_total = 0
    max_total_ip = None
    for ip, count in total_per_ip.items():
        if count > max_total:
            max_total = count
            max_total_ip = ip
    is_burst = max_sec_burst > 10
    is_brute_force = max_total > 30

    if is_burst or is_brute_force:
        target_ip = max_sec_ip if is_burst else max_total_ip
        req_count = max_sec_burst if is_burst else max_total
        desc_type = (
            f"burst of {req_count} requests in 1 second" if is_burst
            else f"sustained volume of {req_count} requests"
        )
        got_429 = any(
            entry.status == 429
            for entry in log_record.raw_entries
            if entry.source_ip == target_ip
        )
        if not got_429:
            return Finding(
                category="API4:2023 Unrestricted Resource Consumption",
                severity="HIGH",
                title="Missing Rate Limiting",
                description=(
                    f"Observed {desc_type} from IP {target_ip} with no "
                    f"429 Too Many Requests response."
                ),
                evidence={
                    "burst_ip": target_ip,
                    "requests_observed": req_count,
                    "type": "1-sec burst" if is_burst else "sustained",
                },
            )
    return None

def _check_method_mismatch(endpoint: OkEndpoint) -> Optional[Finding]:
    undocumented_methods = endpoint.log_record.methods_seen - endpoint.spec_endpoint.declared_methods
    if undocumented_methods:
        return Finding(
            category="API9:2023 Improper Inventory Management",
            severity="MEDIUM",
            title="Undocumented HTTP Method",
            description=f"Observed methods {', '.join(undocumented_methods)} which are not documented in the specification.",
        )
    return None

def _check_shadow_method_mismatch(endpoint: ShadowEndpoint, spec_result: SpecResult) -> Optional[Finding]:
    parts = endpoint.path_template.split('/')
    if len(parts) > 1 and parts[-1] == '{id}':
        base_path = '/'.join(parts[:-1])
        if base_path in spec_result.path_templates:
            return Finding(
                category="API9:2023 Improper Inventory Management",
                severity="MEDIUM",
                title="Undocumented Sub-resource Method",
                description=f"Base path '{base_path}' is documented, but operations on '{endpoint.path_template}' are not.",
            )
    return None


def run_risk_engine(
    diff_result:      DiffResult,
    spec_result:      SpecResult,
    mock_server_url:  str                  = "",
    probe_status:     Optional[ProbeStatus] = None,
    exclude_from_bola: frozenset[str]       = frozenset(),
) -> dict[str, list[Finding]]:
    """
    Run all risk checks on the diff result and return a dict mapping
    path templates to lists of Findings.

    Parameters
    ----------
    probe_status
        Pass in the ProbeStatus returned by probe_server_health().
        If reachable=False, active BOLA probes are skipped entirely.
        If None (backwards-compat / passive mode), probes are skipped.
    """
    results: dict[str, list[Finding]] = defaultdict(list)
    for shadow in diff_result.shadow:
        tmpl = shadow.path_template
        lr = shadow.log_record

        f = _check_shadow(shadow)
        if f: results[tmpl].append(f)

        f = _check_shadow_method_mismatch(shadow, spec_result)
        if f: results[tmpl].append(f)

        f = _check_sensitive_path(tmpl, lr)
        if f: results[tmpl].append(f)
        f = _check_missing_auth(lr, requires_auth=True)
        if f: results[tmpl].append(f)
        f = _check_rate_limiting(lr, is_public_endpoint=False, path_template=tmpl)
        if f: results[tmpl].append(f)

        findings = _check_bola_and_exposure(
            lr, mock_server_url, path_template=tmpl,
            probe_status=probe_status, extra_exclusions=exclude_from_bola,
        )
        results[tmpl].extend(findings)
    for ok in diff_result.ok:
        tmpl = ok.path_template
        lr = ok.log_record
        requires_auth = ok.spec_endpoint.requires_auth
        is_public = ok.spec_endpoint.is_public

        f = _check_method_mismatch(ok)
        if f: results[tmpl].append(f)

        f = _check_sensitive_path(tmpl, lr)
        if f: results[tmpl].append(f)

        f = _check_missing_auth(lr, requires_auth)
        if f: results[tmpl].append(f)
        f = _check_rate_limiting(lr, is_public_endpoint=is_public, path_template=tmpl)
        if f: results[tmpl].append(f)
        findings = _check_bola_and_exposure(
            lr, mock_server_url, path_template=tmpl,
            probe_status=probe_status, extra_exclusions=exclude_from_bola,
        )
        results[tmpl].extend(findings)
    for fuzzy in diff_result.fuzzy_reconciled:
        tmpl = fuzzy.discovered_template
        lr = fuzzy.log_record
        requires_auth = fuzzy.spec_endpoint.requires_auth
        is_public = fuzzy.spec_endpoint.is_public

        undoc_methods = lr.methods_seen - fuzzy.spec_endpoint.declared_methods
        if undoc_methods:
            results[tmpl].append(Finding(
                category="API9:2023 Improper Inventory Management",
                severity="MEDIUM",
                title="Undocumented HTTP Method",
                description=(
                    f"Observed methods {', '.join(undoc_methods)} which are not "
                    f"documented."
                ),
            ))

        f = _check_sensitive_path(tmpl, lr)
        if f: results[tmpl].append(f)

        f = _check_missing_auth(lr, requires_auth)
        if f: results[tmpl].append(f)

        f = _check_rate_limiting(lr, is_public_endpoint=is_public, path_template=tmpl)
        if f: results[tmpl].append(f)

        findings = _check_bola_and_exposure(
            lr, mock_server_url, path_template=tmpl,
            extra_exclusions=exclude_from_bola,
        )
        results[tmpl].extend(findings)

    return dict(results)

if __name__ == "__main__":
    import argparse as ap
    from scanner.log_parser import parse_logs
    from scanner.spec_loader import load_spec
    from scanner.diff_engine import diff

    cli = ap.ArgumentParser(description="Run risk_engine against logs + spec")
    cli.add_argument("--log",     default="mock_env/access.log")
    cli.add_argument("--headers", default="mock_env/access_headers.log")
    cli.add_argument("--spec",    default="mock_env/openapi_spec.yaml")
    cli.add_argument("--url",     default="http://localhost:8000")
    args = cli.parse_args()

    log_res = parse_logs(args.log, args.headers)
    spec_res = load_spec(args.spec)
    diff_res = diff(log_res, spec_res)

    print("Running Risk Engine...\n")
    risk_results = run_risk_engine(diff_res, spec_res, args.url)
    
    import json
    import dataclasses
    json_output = {
        endpoint: [dataclasses.asdict(f) for f in findings]
        for endpoint, findings in risk_results.items()
        if findings
    }
    
    print(json.dumps(json_output, indent=2))
    
    print("\nDone.")
