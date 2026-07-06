"""
scanner/diff_engine.py
======================
Computes three disjoint sets from the log-parser and spec-loader outputs:

  Shadow    = discovered ∖ documented
              Endpoints actively receiving traffic but absent from the spec.
              These are the primary finding type — potential rogue/legacy APIs.

  Dormant   = documented ∖ discovered
              Endpoints in the spec but never called during the log window.
              Useful for "zombie documented endpoint" / attack-surface hygiene.

  OK        = discovered ∩ documented
              Expected traffic — used to prove false-positive avoidance.

Fuzzy placeholder reconciliation
----------------------------------
Both log_parser.normalise_path() and spec_loader._normalise_path_template()
collapse all {paramName} placeholders to {id}, so the two sets should already
be in the same canonical form.  The fuzzy matcher acts as a safety net for
callers who bypass normalisation (e.g. passing raw spec paths directly) — it
detects templates that differ only in placeholder naming and reconciles them
into OK rather than misreporting them as Shadow.

Method-mismatch handling
--------------------------
This module works on path templates, not (method, path) pairs.  Therefore:

  /api/v1/appointments   (POST documented)  and
  /api/v1/appointments/{id}  (DELETE in logs, no doc)

…are treated as two distinct templates.  /api/v1/appointments lands in OK
(traffic + documented).  /api/v1/appointments/{id} lands in Shadow (traffic,
zero doc entry).  The risk engine (Step 7) is responsible for the secondary
check: "does a Shadow endpoint's method also appear on the documented base
path?" — that is the API9:2023 Improper Inventory Management finding.  We
deliberately do NOT merge or suppress /api/v1/appointments/{id} here.

Public API
----------
    diff(log_result, spec_result) -> DiffResult
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional

# Support both `python scanner/diff_engine.py` (direct run) and
# `from scanner.diff_engine import diff` (package import).
try:
    from scanner.log_parser  import ParseResult, EndpointRecord
    from scanner.spec_loader import SpecResult, SpecEndpoint
except ModuleNotFoundError:
    import sys, os
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
    from scanner.log_parser  import ParseResult, EndpointRecord
    from scanner.spec_loader import SpecResult, SpecEndpoint


# ─────────────────────────────────────────────────────────────────────────────
# Data classes
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class ShadowEndpoint:
    """An endpoint actively receiving traffic that is absent from the spec."""
    path_template: str
    log_record:    EndpointRecord         # full stats from the parser


@dataclass
class DormantEndpoint:
    """An endpoint in the spec that received zero traffic during the log window."""
    path_template: str
    spec_endpoint: SpecEndpoint           # spec metadata


@dataclass
class OkEndpoint:
    """An endpoint present in both the spec and the logs — expected traffic."""
    path_template: str
    log_record:    EndpointRecord
    spec_endpoint: SpecEndpoint


@dataclass
class FuzzyMatch:
    """
    A pair of templates that differ only in placeholder naming.
    Treated as OK (not Shadow) after reconciliation.
    """
    discovered_template: str              # e.g. /api/v1/patients/{patientId}
    spec_template:       str              # e.g. /api/v1/patients/{id}
    log_record:          EndpointRecord
    spec_endpoint:       SpecEndpoint


@dataclass
class DiffResult:
    """
    Top-level result of the diff computation.

    All four lists are exhaustive and disjoint with respect to discovered
    path templates — every template from the log parser appears in exactly
    one of shadow, ok, or fuzzy_reconciled.
    """
    shadow:            list[ShadowEndpoint]   = field(default_factory=list)
    dormant:           list[DormantEndpoint]  = field(default_factory=list)
    ok:                list[OkEndpoint]       = field(default_factory=list)
    fuzzy_reconciled:  list[FuzzyMatch]       = field(default_factory=list)

    # Convenience views
    @property
    def shadow_templates(self) -> set[str]:
        return {s.path_template for s in self.shadow}

    @property
    def dormant_templates(self) -> set[str]:
        return {d.path_template for d in self.dormant}

    @property
    def ok_templates(self) -> set[str]:
        return {o.path_template for o in self.ok}

    @property
    def total_discovered(self) -> int:
        return len(self.shadow) + len(self.ok) + len(self.fuzzy_reconciled)

    @property
    def total_documented(self) -> int:
        return len(self.dormant) + len(self.ok) + len(self.fuzzy_reconciled)


# ─────────────────────────────────────────────────────────────────────────────
# Fuzzy matching
# ─────────────────────────────────────────────────────────────────────────────

# Matches any {…} placeholder in a path segment
_PLACEHOLDER_RE = re.compile(r'^\{[^}]+\}$')


def _is_placeholder(segment: str) -> bool:
    return bool(_PLACEHOLDER_RE.match(segment))


def templates_fuzzy_match(tmpl_a: str, tmpl_b: str) -> bool:
    """
    Return True if two path templates differ only in placeholder naming.

    Rules:
      1. Must have the same number of path segments.
      2. For each segment pair:
           • Both literal  → must match exactly (case-sensitive)
           • Both placeholder  → match regardless of name ({id} == {patientId})
           • One literal, one placeholder  → no match
      3. Query strings are ignored (both should already be stripped).

    Examples:
      /api/v1/patients/{id}    vs /api/v1/patients/{patientId}    → True
      /api/v1/patients/{id}    vs /api/v1/patients/{id}/claims    → False
      /api/v1/patients/{id}    vs /api/v1/patient-records/{id}    → False
      /api/v1/health           vs /api/v1/health                  → True
    """
    # Strip query strings defensively
    a = tmpl_a.split("?")[0]
    b = tmpl_b.split("?")[0]

    segs_a = a.split("/")
    segs_b = b.split("/")

    if len(segs_a) != len(segs_b):
        return False

    for sa, sb in zip(segs_a, segs_b):
        pa, pb = _is_placeholder(sa), _is_placeholder(sb)
        if pa and pb:
            continue                # both placeholders — compatible regardless of name
        if pa != pb:
            return False            # one literal, one placeholder — incompatible
        if sa != sb:
            return False            # both literal but different words

    return True


def _find_fuzzy_spec_match(
    discovered_tmpl: str,
    spec_result: SpecResult,
) -> Optional[SpecEndpoint]:
    """
    Search the spec for a template that fuzzy-matches discovered_tmpl.
    Returns the SpecEndpoint if found, None otherwise.
    """
    for spec_tmpl, spec_ep in spec_result.documented_paths.items():
        if spec_tmpl == discovered_tmpl:
            continue                # exact match handled separately
        if templates_fuzzy_match(discovered_tmpl, spec_tmpl):
            return spec_ep
    return None


# ─────────────────────────────────────────────────────────────────────────────
# Core diff
# ─────────────────────────────────────────────────────────────────────────────

def diff(
    log_result:  ParseResult,
    spec_result: SpecResult,
) -> DiffResult:
    """
    Compute Shadow, Dormant, OK, and FuzzyReconciled sets.

    Parameters
    ----------
    log_result  : output of log_parser.parse_logs()
    spec_result : output of spec_loader.load_spec()

    Returns
    -------
    DiffResult with all four categories populated.
    """
    result = DiffResult()

    # Index log records by template for O(1) lookup
    log_by_tmpl: dict[str, EndpointRecord] = {
        rec.path_template: rec for rec in log_result.endpoint_records
    }
    discovered: set[str] = set(log_by_tmpl.keys())
    documented: set[str] = spec_result.path_templates

    # ── OK: exact intersection ─────────────────────────────────────────────
    exact_ok = discovered & documented
    for tmpl in sorted(exact_ok):
        result.ok.append(OkEndpoint(
            path_template = tmpl,
            log_record    = log_by_tmpl[tmpl],
            spec_endpoint = spec_result.documented_paths[tmpl],
        ))

    # ── Candidates for Shadow or Fuzzy ────────────────────────────────────
    undecided = discovered - documented
    for tmpl in sorted(undecided):
        spec_ep = _find_fuzzy_spec_match(tmpl, spec_result)
        if spec_ep:
            result.fuzzy_reconciled.append(FuzzyMatch(
                discovered_template = tmpl,
                spec_template       = spec_ep.path_template,
                log_record          = log_by_tmpl[tmpl],
                spec_endpoint       = spec_ep,
            ))
        else:
            result.shadow.append(ShadowEndpoint(
                path_template = tmpl,
                log_record    = log_by_tmpl[tmpl],
            ))

    # ── Dormant: in spec but not in logs at all ────────────────────────────
    # Also account for fuzzy-reconciled templates (they count as "seen")
    fuzzy_spec_templates = {fm.spec_template for fm in result.fuzzy_reconciled}
    seen_spec_templates  = exact_ok | fuzzy_spec_templates
    dormant_tmpls        = documented - seen_spec_templates

    for tmpl in sorted(dormant_tmpls):
        result.dormant.append(DormantEndpoint(
            path_template = tmpl,
            spec_endpoint = spec_result.documented_paths[tmpl],
        ))

    # Sort Shadow by hit count descending (highest-traffic shadows first)
    result.shadow.sort(key=lambda s: s.log_record.hit_count, reverse=True)

    return result


# ─────────────────────────────────────────────────────────────────────────────
# __main__
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse as ap
    import sys

    from scanner.log_parser  import parse_logs
    from scanner.spec_loader import load_spec, SpecEndpoint, SpecResult

    cli = ap.ArgumentParser(description="Run diff_engine against logs + spec")
    cli.add_argument("--log",     default="mock_env/access.log")
    cli.add_argument("--headers", default="mock_env/access_headers.log")
    cli.add_argument("--spec",    default="mock_env/openapi_spec.yaml")
    args = cli.parse_args()

    SEP_THICK = "═" * 74
    SEP_THIN  = "─" * 74

    def print_diff_report(result: DiffResult, label: str) -> None:
        print(SEP_THICK)
        print(f"  {label}")
        print(SEP_THICK)
        print(f"  Discovered templates : {result.total_discovered}")
        print(f"  Documented templates : {result.total_documented}")
        print(f"  Shadow               : {len(result.shadow)}")
        print(f"  Dormant              : {len(result.dormant)}")
        print(f"  OK (expected traffic): {len(result.ok)}")
        print(f"  Fuzzy-reconciled     : {len(result.fuzzy_reconciled)}")
        print()

        # Shadow endpoints
        print(f"  {'SHADOW ENDPOINTS':} ({len(result.shadow)}) — undocumented, active traffic")
        print(SEP_THIN)
        if result.shadow:
            for s in result.shadow:
                lr = s.log_record
                methods = ",".join(sorted(lr.methods_seen))
                auth = lr.auth_coverage
                ips = ", ".join(sorted(lr.source_ips)[:3])
                print(f"  ⚠  {s.path_template}")
                print(f"     hits={lr.hit_count:<4}  methods={methods:<10}  {auth}")
                print(f"     source IPs: {ips}")
                if lr.sample_raw_paths:
                    print(f"     sample path: {lr.sample_raw_paths[0]}")
                print()
        else:
            print("  (none)\n")

        # Dormant endpoints
        print(f"  DORMANT ENDPOINTS ({len(result.dormant)}) — in spec, zero traffic")
        print(SEP_THIN)
        if result.dormant:
            for d in result.dormant:
                sec = d.spec_endpoint.security_label
                methods = ",".join(sorted(d.spec_endpoint.declared_methods))
                print(f"  💤  {d.path_template}")
                print(f"     methods={methods}  security={sec}")
                print()
        else:
            print("  (none)\n")

        # OK
        print(f"  OK — EXPECTED TRAFFIC ({len(result.ok)})")
        print(SEP_THIN)
        for o in result.ok:
            sec  = o.spec_endpoint.security_label
            hits = o.log_record.hit_count
            methods = ",".join(sorted(o.log_record.methods_seen))
            print(f"    {o.path_template:<50}  hits={hits:<4}  security={sec}")
        print()

        # Fuzzy
        if result.fuzzy_reconciled:
            print(f"  FUZZY-RECONCILED ({len(result.fuzzy_reconciled)})")
            print(SEP_THIN)
            for fm in result.fuzzy_reconciled:
                print(f"     discovered: {fm.discovered_template}")
                print(f"      spec:       {fm.spec_template}  (placeholder name differed)")
            print()

    # ── RUN 1: Real fixture ────────────────────────────────────────────────
    print(SEP_THICK)
    print("  LOADING REAL FIXTURE")
    print(SEP_THICK)
    log_result  = parse_logs(args.log, args.headers)
    spec_result = load_spec(args.spec)
    print(f"  Parsed {log_result.total_lines} log lines → {len(log_result.endpoint_records)} templates")
    print(f"  Loaded spec with {len(spec_result.documented_paths)} documented paths")
    print()

    real_diff = diff(log_result, spec_result)
    print_diff_report(real_diff, "RUN 1: Real fixture (expect Shadow=5, Dormant=0, OK=4)")

    # Verify expected outcomes
    expected_shadow = {
        "/api/v1/patient-records/{id}",
        "/api/v1/internal/debug/patient/{id}",
        "/api/v1/patients/{id}/insurance-claims",
        "/api/v1/otp/verify",
        "/api/v1/appointments/{id}",
    }
    got_shadow = real_diff.shadow_templates
    shadow_ok  = got_shadow == expected_shadow

    print("  Verification:")
    print(f"  Expected shadow templates: {sorted(expected_shadow)}")
    print(f"  Got shadow templates     : {sorted(got_shadow)}")
    if shadow_ok:
        print("     Shadow set matches expected exactly")
    else:
        missing = expected_shadow - got_shadow
        extra   = got_shadow - expected_shadow
        if missing: print(f"  ❌  Missing from shadow: {missing}")
        if extra:   print(f"  ❌  Unexpected in shadow: {extra}")

    assert len(real_diff.dormant) == 0, "Expected 0 dormant endpoints in real fixture"
    print("     Dormant set is empty (all 4 documented endpoints got traffic)")
    print()

    # ── RUN 2: Synthetic dormant test ─────────────────────────────────────
    print(SEP_THICK)
    print("  RUN 2: Synthetic dormant test")
    print("  (Removing /api/v1/doctors/{id} from discovered set)")
    print(SEP_THICK)
    print()

    # Build a ParseResult with /doctors/{id} dropped
    import dataclasses
    reduced_records = [r for r in log_result.endpoint_records
                       if r.path_template != "/api/v1/doctors/{id}"]
    reduced_log = dataclasses.replace(
        log_result,
        endpoint_records = reduced_records,
        by_template      = {r.path_template: r for r in reduced_records},
    )
    synthetic_diff = diff(reduced_log, spec_result)
    print_diff_report(synthetic_diff,
                      "RUN 2: Synthetic (expect Shadow=5, Dormant=1 [doctors], OK=3)")

    assert len(synthetic_diff.dormant) == 1, "Expected exactly 1 dormant"
    assert synthetic_diff.dormant[0].path_template == "/api/v1/doctors/{id}", \
        f"Wrong dormant endpoint: {synthetic_diff.dormant[0].path_template}"
    print("     Dormant detection works: /api/v1/doctors/{id} correctly flagged as dormant")
    print()

    # ── RUN 3: Fuzzy match test ────────────────────────────────────────────
    print(SEP_THICK)
    print("  RUN 3: Fuzzy-match test")
    print("  (Spec uses {patientId}/{doctorId}; logs normalise to {id})")
    print("  Expected: NO shadow endpoints from naming mismatch alone")
    print(SEP_THICK)
    print()

    # Build a synthetic SpecResult with descriptive placeholder names
    from scanner.spec_loader import SpecEndpoint as SE, OperationMeta
    from copy import deepcopy

    fuzzy_spec = deepcopy(spec_result)
    # Replace /api/v1/patients/{id} with /api/v1/patients/{patientId}
    old_ep = fuzzy_spec.documented_paths.pop("/api/v1/patients/{id}", None)
    old_ep2 = fuzzy_spec.documented_paths.pop("/api/v1/doctors/{id}", None)
    if old_ep:
        old_ep.path_template = "/api/v1/patients/{patientId}"
        old_ep.raw_path      = "/api/v1/patients/{patientId}"
        fuzzy_spec.documented_paths["/api/v1/patients/{patientId}"] = old_ep
    if old_ep2:
        old_ep2.path_template = "/api/v1/doctors/{doctorId}"
        old_ep2.raw_path      = "/api/v1/doctors/{doctorId}"
        fuzzy_spec.documented_paths["/api/v1/doctors/{doctorId}"] = old_ep2
    fuzzy_spec.path_templates = set(fuzzy_spec.documented_paths.keys())

    fuzzy_diff = diff(log_result, fuzzy_spec)
    print_diff_report(fuzzy_diff,
                      "RUN 3: Fuzzy spec — {patientId}/{doctorId} vs log's {id}")

    reconciled_tmpls = {fm.discovered_template for fm in fuzzy_diff.fuzzy_reconciled}
    assert "/api/v1/patients/{id}"  in reconciled_tmpls, \
        "Expected /api/v1/patients/{id} to be fuzzy-reconciled"
    assert "/api/v1/doctors/{id}"   in reconciled_tmpls, \
        "Expected /api/v1/doctors/{id} to be fuzzy-reconciled"
    assert len(fuzzy_diff.shadow) == 5, \
        f"Shadow count should still be 5, got {len(fuzzy_diff.shadow)}"
    print("     Fuzzy reconciliation correct: {patientId}/{doctorId} matched to {id}")
    print("     Shadow count unchanged at 5 (naming mismatch didn't create false positives)")
    print()

    print(SEP_THICK)
    print("  ALL ASSERTIONS PASSED")
    print(SEP_THICK)
