"""
scanner/cli.py
==============
Entry point for the Shadow API Discovery & Vulnerability Scanner.

Usage
-----
    python scanner/cli.py \\
        --log-file   mock_env/access.log \\
        --spec       mock_env/openapi_spec.yaml \\
        --mock-server-url http://localhost:8000 \\
        --output     report.html \\
        --fail-on    critical,high

Exit codes
----------
    0  — scan completed; no findings at or above --fail-on threshold
    1  — scan completed; at least one finding at or above --fail-on threshold
    2  — usage error (bad arguments, files not found)
    3  — unexpected runtime error during scan

The --fail-on flag makes the scanner suitable for CI/CD gating (mirrors
the industry practice described in HCIC Problem 14).
"""

from __future__ import annotations

import argparse
import sys
import traceback
from pathlib import Path
try:
    from scanner.log_parser       import parse_logs
    from scanner.spec_loader      import load_spec
    from scanner.diff_engine      import diff
    from scanner.risk_engine      import run_risk_engine, probe_server_health, ProbeStatus
    from scanner.scorer           import score_endpoints
    from scanner.report_generator import generate_report
except ModuleNotFoundError:
    import os
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
    from scanner.log_parser       import parse_logs
    from scanner.spec_loader      import load_spec
    from scanner.diff_engine      import diff
    from scanner.risk_engine      import run_risk_engine, probe_server_health, ProbeStatus
    from scanner.scorer           import score_endpoints
    from scanner.report_generator import generate_report
_SEVERITY_RANK: dict[str, int] = {
    "CRITICAL": 4,
    "HIGH":     3,
    "MEDIUM":   2,
    "LOW":      1,
    "INFO":     0,
    "NONE":     -1,
}

_EXIT_OK       = 0
_EXIT_FINDINGS = 1
_EXIT_USAGE    = 2
_EXIT_ERROR    = 3
_NO_COLOR = not sys.stdout.isatty()

def _c(text: str, code: str) -> str:
    """Wrap text in ANSI colour if stdout is a tty."""
    if _NO_COLOR:
        return text
    return f"\033[{code}m{text}\033[0m"

def _bold(t: str)    -> str: return _c(t, "1")
def _red(t: str)     -> str: return _c(t, "31")
def _orange(t: str)  -> str: return _c(t, "33")
def _green(t: str)   -> str: return _c(t, "32")
def _cyan(t: str)    -> str: return _c(t, "36")
def _dim(t: str)     -> str: return _c(t, "2")

_SEV_COLOR = {
    "CRITICAL": _red,
    "HIGH":     _orange,
    "MEDIUM":   _orange,
    "LOW":      _cyan,
    "INFO":     _dim,
    "NONE":     _dim,
}

def _sev(s: str) -> str:
    return _SEV_COLOR.get(s, str)(s)


def _step(n: int, total: int, msg: str) -> None:
    print(f"  {_dim(f'[{n}/{total}]')} {msg}", flush=True)

def _ok(msg: str)   -> None: print(f"  {_green('✔')} {msg}", flush=True)
def _warn(msg: str) -> None: print(f"  {_orange('⚠')} {msg}", flush=True)
def _err(msg: str)  -> None: print(f"  {_red('✖')} {msg}", file=sys.stderr, flush=True)
def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="shadow-scan",
        description=(
            "Shadow API Discovery & Vulnerability Scanner\n"
            "Compares web server logs against an OpenAPI spec to discover\n"
            "undocumented endpoints, then runs OWASP API Top 10 checks.\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  # Full scan with CI exit-code gating:\n"
            "  python scanner/cli.py \\\n"
            "      --log-file mock_env/access.log \\\n"
            "      --spec mock_env/openapi_spec.yaml \\\n"
            "      --mock-server-url http://localhost:8000 \\\n"
            "      --output report.html \\\n"
            "      --fail-on critical,high\n\n"
            "  # Passive scan only (no active BOLA probes):\n"
            "  python scanner/cli.py \\\n"
            "      --log-file access.log --spec api.yaml --no-active-probes\n"
        ),
    )

    p.add_argument(
        "--log-file", required=True, metavar="PATH",
        help="Path to Nginx combined-format access log",
    )
    p.add_argument(
        "--headers-log", metavar="PATH", default=None,
        help=(
            "Path to companion JSONL auth-headers log "
            "(default: same directory as --log-file, filename access_headers.log)"
        ),
    )
    p.add_argument(
        "--spec", required=True, metavar="PATH",
        help="Path to OpenAPI 3.0 YAML/JSON spec file",
    )
    p.add_argument(
        "--mock-server-url", metavar="URL", default="",
        help=(
            "Base URL of the mock/test server for active BOLA probes "
            "(e.g. http://localhost:8000). Omit or pass empty string to "
            "skip active probing."
        ),
    )
    p.add_argument(
        "--no-active-probes", action="store_true",
        help="Disable all active network probes (overrides --mock-server-url)",
    )
    p.add_argument(
        "--output", metavar="PATH", default="report.html",
        help="Output path for the HTML report (default: report.html)",
    )
    p.add_argument(
        "--fail-on", metavar="SEVERITIES", default="critical,high",
        help=(
            "Comma-separated list of severities that trigger a non-zero exit "
            "code — for CI/CD gating. Options: critical, high, medium, low, info. "
            "Default: critical,high"
        ),
    )
    p.add_argument(
        "--exclude-from-bola", metavar="RESOURCES", default="",
        help=(
            "Comma-separated list of resource-name keywords to exclude from "
            "active BOLA probing (e.g. 'product,category'). Adds to the built-in "
            "exclusion list without requiring source-code changes."
        ),
    )
    p.add_argument(
        "--quiet", "-q", action="store_true",
        help="Suppress progress output; only print the final summary",
    )
    p.add_argument(
        "--version", action="version", version="shadow-scan 1.0.0 (HCIC-SI2026 Project 15)",
    )

    return p
def _resolve_headers_log(log_file: Path, headers_arg: str | None) -> Path | None:
    """
    If --headers-log is not given, look for access_headers.log in the same
    directory as the access log.  Return None if it doesn't exist.
    """
    if headers_arg:
        p = Path(headers_arg)
        if not p.exists():
            _warn(f"--headers-log path not found: {p}  (auth stats will be unavailable)")
            return None
        return p

    candidate = log_file.parent / "access_headers.log"
    if candidate.exists():
        return candidate
    return None


def _parse_fail_on(raw: str) -> set[str]:
    """Return a set of uppercase severity names from the --fail-on string."""
    result: set[str] = set()
    for token in raw.split(","):
        token = token.strip().upper()
        if token not in _SEVERITY_RANK:
            print(
                f"  {_orange('⚠')} Unknown severity in --fail-on: '{token}' "
                f"(valid: critical, high, medium, low, info)",
                file=sys.stderr,
            )
        else:
            result.add(token)
    return result


def _should_fail(highest_severity: str, fail_on: set[str]) -> bool:
    """
    Return True if the scan's highest severity is at or above ANY level in fail_on.

    This means --fail-on medium triggers on CRITICAL and HIGH findings too,
    because their rank is higher than MEDIUM.  The set members define the
    *minimum* threshold(s) that cause a failure, not an exact-match whitelist.
    """
    found_rank = _SEVERITY_RANK.get(highest_severity.upper(), -1)
    return any(found_rank >= _SEVERITY_RANK.get(f, -1) for f in fail_on)
def run_scan(args: argparse.Namespace) -> int:
    """
    Execute the full scan pipeline and return the process exit code.
    """
    quiet = args.quiet
    STEPS = 6  # total pipeline steps

    def step(n: int, msg: str) -> None:
        if not quiet:
            _step(n, STEPS, msg)

    def ok(msg: str) -> None:
        if not quiet:
            _ok(msg)
    log_file = Path(args.log_file)
    if not log_file.exists():
        _err(f"--log-file not found: {log_file}")
        return _EXIT_USAGE

    spec_file = Path(args.spec)
    if not spec_file.exists():
        _err(f"--spec not found: {spec_file}")
        return _EXIT_USAGE

    headers_log = _resolve_headers_log(log_file, args.headers_log)
    fail_on     = _parse_fail_on(args.fail_on)
    mock_url    = "" if args.no_active_probes else args.mock_server_url.strip()
    exclude_from_bola: frozenset[str] = frozenset(
        t.strip().lower()
        for t in args.exclude_from_bola.split(",")
        if t.strip()
    )

    if not quiet:
        print()
        print(_bold("  🛡️  Shadow API Discovery & Vulnerability Scanner"))
        print(_dim("  " + "─" * 54))
        print(f"  Log file  : {log_file}")
        print(f"  Spec      : {spec_file}")
        print(f"  Headers   : {headers_log or _dim('(none — auth stats unavailable)')}")
        print(f"  Probes    : {mock_url if mock_url else _dim('disabled (passive mode)')}")
        print(f"  Output    : {args.output}")
        print(f"  Fail on   : {', '.join(sorted(fail_on)) if fail_on else _dim('(never fail)')}")
        if exclude_from_bola:
            print(f"  BOLA excl.: {', '.join(sorted(exclude_from_bola))}")
        print()
    step(1, "Parsing access logs…")
    try:
        log_result = parse_logs(log_file, headers_log)
    except Exception as exc:
        _err(f"Log parsing failed: {exc}")
        return _EXIT_ERROR
    ok(
        f"Parsed {log_result.total_lines} log lines → "
        f"{len(log_result.endpoint_records)} unique path templates"
        + (f"  ({log_result.parse_errors} parse errors)" if log_result.parse_errors else "")
    )
    step(2, "Loading OpenAPI spec…")
    try:
        spec_result = load_spec(spec_file)
    except Exception as exc:
        _err(f"Spec loading failed: {exc}")
        return _EXIT_ERROR
    ok(
        f"Loaded '{spec_result.title}' v{spec_result.api_version} — "
        f"{len(spec_result.documented_paths)} documented paths"
    )
    step(3, "Computing shadow/documented diff…")
    try:
        diff_result = diff(log_result, spec_result)
    except Exception as exc:
        _err(f"Diff engine failed: {exc}")
        return _EXIT_ERROR
    shadow_n  = len(diff_result.shadow)
    dormant_n = len(diff_result.dormant)
    ok(
        f"Diff complete — "
        f"{_red(str(shadow_n)) if shadow_n else _green('0')} shadow, "
        f"{dormant_n} dormant, "
        f"{len(diff_result.ok)} documented OK"
    )
    probe_status: ProbeStatus
    if mock_url:
        step(4, f"Checking mock server reachability → {mock_url}…")
        probe_status = probe_server_health(mock_url)
        if not probe_status.reachable:
            print()
            print(f"  {_orange('⚠')} {_bold('ACTIVE PROBES DISABLED — mock server unreachable')}",
                  file=sys.stderr)
            print(f"  {_orange('  Reason:')} {probe_status.error_detail}", file=sys.stderr)
            print(f"  {_orange('  URL checked:')} {probe_status.probe_url}", file=sys.stderr)
            print(_dim(
                "  Active BOLA probes will be skipped. Findings will be passive-only.\n"
                "  To suppress this warning, pass --no-active-probes explicitly."
            ), file=sys.stderr)
            print()
            step(4, "Running OWASP risk checks (passive only — server unreachable)…")
        else:
            ok(f"Mock server reachable at {mock_url}")
            step(4, "Running OWASP risk checks + active BOLA probes…")
    else:
        probe_status = ProbeStatus(reachable=False,
                                   error_detail="No mock server URL provided.",
                                   probe_url="")
        step(4, "Running OWASP risk checks (passive only)…")

    try:
        risk_results = run_risk_engine(
            diff_result, spec_result, mock_url, probe_status,
            exclude_from_bola=exclude_from_bola,
        )
    except Exception as exc:
        _err(f"Risk engine failed: {exc}")
        return _EXIT_ERROR
    total_findings = sum(len(v) for v in risk_results.values())
    if probe_status.reachable and probe_status.probes_failed:
        _warn(
            f"{probe_status.probes_failed}/{probe_status.probes_attempted} active probe(s) "
            f"failed mid-scan (ConnectionError). Some findings may be missing."
        )
    ok(f"Risk engine complete — {total_findings} findings across {len(risk_results)} endpoints")
    step(5, "Scoring endpoints…")
    try:
        scored = score_endpoints(risk_results)
    except Exception as exc:
        _err(f"Scorer failed: {exc}")
        return _EXIT_ERROR

    if not quiet:
        crit_eps = [se for se in scored if se.risk_level == "CRITICAL"]
        high_eps = [se for se in scored if se.risk_level == "HIGH"]
        print()
        print(f"  {'Score':>5}  {'Level':<9}  Path")
        print(f"  {'─'*5}  {'─'*9}  {'─'*50}")
        for se in scored:
            if se.score == 0:
                continue
            print(
                f"  {se.score:>5}  "
                f"{_sev(se.risk_level):<9}  "
                f"{se.path_template}"
            )
        if all(se.score == 0 for se in scored):
            _ok("No risk findings detected.")
        print()
    step(6, f"Rendering HTML report → {args.output}")
    try:
        meta = generate_report(scored, diff_result, spec_result, args.output,
                               probe_status=probe_status)
    except Exception as exc:
        _err(f"Report generation failed: {exc}")
        return _EXIT_ERROR
    ok(f"Report written: {_bold(meta.output_path)}")
    print()
    print(_bold("  ── Scan Summary " + "─" * 40))
    print(f"  Overall Risk Exposure : {_sev(meta.highest_severity)}  ({meta.gateway_score}/100)")
    print(f"  Shadow endpoints      : {_red(str(meta.shadow_count)) if meta.shadow_count else _green('0')}")
    print(f"  Critical findings     : {_red(str(meta.critical_count)) if meta.critical_count else _green('0')}")
    if not probe_status.reachable and mock_url:
        print(f"  Active probes         : {_orange('SKIPPED')} — server unreachable ({probe_status.error_detail})")
    elif probe_status.reachable:
        pfail = probe_status.probes_failed
        pline = (f"{_orange(str(pfail))} failed / "
                 if pfail else f"{_green('all')} ") + \
                f"{probe_status.probes_succeeded} succeeded"
        print(f"  Active probes         : {pline}")
    print(f"  Report                : {meta.output_path}")
    print()
    if _should_fail(meta.highest_severity, fail_on):
        print(
            f"  {_red('✖')} Exit 1 — {_sev(meta.highest_severity)} findings present "
            f"(--fail-on includes '{meta.highest_severity.lower()}')",
            file=sys.stderr,
        )
        print(_dim("  CI/CD gate triggered — fix findings before merging."), file=sys.stderr)
        return _EXIT_FINDINGS
    else:
        _ok(f"Exit 0 — no findings at or above the --fail-on threshold ({args.fail_on})")
        return _EXIT_OK
def main() -> None:
    parser = _build_parser()
    args   = parser.parse_args()

    try:
        exit_code = run_scan(args)
    except KeyboardInterrupt:
        print("\n  Interrupted.", file=sys.stderr)
        exit_code = _EXIT_ERROR
    except Exception:
        _err("Unexpected error:")
        traceback.print_exc(file=sys.stderr)
        exit_code = _EXIT_ERROR

    sys.exit(exit_code)


if __name__ == "__main__":
    main()
