"""
scanner/spec_loader.py
======================
Parses an OpenAPI 3.0 (YAML or JSON) specification file into the same
path-template format used by log_parser.py, so diff_engine.py can perform a
direct set comparison with no extra translation step.

Path template conventions
--------------------------
OpenAPI uses curly-brace placeholders already: /api/v1/patients/{id}
log_parser.normalise_path() produces the same format from concrete paths.
spec_loader therefore reads OpenAPI path keys verbatim — no extra normalisation
is needed beyond lowercasing the placeholder name to ``{id}`` when the spec
uses a different name (e.g. ``{patientId}``, ``{appointmentId}``) so the diff
engine can match them against log-derived templates without false positives.

Public API
----------
    load_spec(spec_path) -> SpecResult
    SpecResult.documented_paths  : dict[str, SpecEndpoint]
    SpecResult.path_templates    : set[str]   (normalised, {id} style)
"""

from __future__ import annotations

import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import yaml  # pyyaml

# ─────────────────────────────────────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────────────────────────────────────

# All standard OpenAPI operation keywords (HTTP verbs used as path-item keys)
_HTTP_METHODS = {"get", "post", "put", "patch", "delete", "head", "options", "trace"}

# Normalise any {paramName} placeholder to {id} so spec templates and log
# templates are comparable even when the spec uses descriptive names.
_PARAM_RE = re.compile(r'\{[^}]+\}')


# ─────────────────────────────────────────────────────────────────────────────
# Data classes
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class OperationMeta:
    """Metadata for one (path, method) pair in the spec."""
    method:        str                  # uppercase: GET, POST, …
    operation_id:  Optional[str]
    summary:       Optional[str]
    security:      str                  # "bearerAuth" | "public" | "undeclared"
    security_raw:  list                 # raw value of the operation's security block


@dataclass
class SpecEndpoint:
    """
    Aggregated metadata for one normalised path template extracted from the spec.
    Mirrors EndpointRecord closely so diff_engine.py can work with both types
    through a common interface.
    """
    path_template:  str                     # normalised, e.g. /api/v1/patients/{id}
    raw_path:       str                     # original path from spec (may use {patientId})
    operations:     list[OperationMeta]     = field(default_factory=list)

    @property
    def declared_methods(self) -> set[str]:
        return {op.method for op in self.operations}

    @property
    def security_label(self) -> str:
        """
        Human-readable security posture for the whole path.

        Rules (applied per path, not per method):
          • All ops have security: []  → 'public'
          • All ops have bearerAuth   → 'bearerAuth'
          • Mixed                     → 'mixed (see per-method)'
          • No security key at all on any op → 'undeclared'
        """
        labels = {op.security for op in self.operations}
        if len(labels) == 1:
            return labels.pop()
        return "mixed"

    @property
    def requires_auth(self) -> bool:
        return any(op.security == "bearerAuth" for op in self.operations)

    @property
    def is_public(self) -> bool:
        return all(op.security == "public" for op in self.operations)


@dataclass
class SpecResult:
    """Top-level result returned by load_spec()."""
    documented_paths: dict[str, SpecEndpoint]   # key = normalised path template
    path_templates:   set[str]                   # convenience: just the template strings
    spec_version:     str                        # e.g. "3.0.3"
    title:            str
    api_version:      str
    global_security:  list                       # top-level security: block (if any)


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _normalise_path_template(raw_path: str) -> str:
    """
    Collapse all {paramName} placeholders to {id}.

    /api/v1/patients/{patientId}         → /api/v1/patients/{id}
    /api/v1/doctors/{doctorId}           → /api/v1/doctors/{id}
    /api/v1/appointments/{appointmentId} → /api/v1/appointments/{id}
    /api/v1/patients/{id}                → /api/v1/patients/{id}   (unchanged)
    /api/v1/health                       → /api/v1/health          (unchanged)
    """
    return _PARAM_RE.sub("{id}", raw_path)


def _resolve_security(
    op_security: Optional[list],
    global_security: list,
) -> tuple[str, list]:
    """
    Resolve the effective security requirement for one operation.

    OpenAPI security precedence:
      1. If the operation has its own ``security`` key, that wins (even [] = public).
      2. Otherwise the global ``security`` block applies.
      3. If neither exists, it is 'undeclared' (risk engine should flag this).

    Returns (label, raw_value) where label ∈ {"bearerAuth","public","undeclared"}.
    """
    raw: Optional[list] = op_security  # may be None (key absent), or [] or [{...}]

    if raw is None:
        # Key absent on the operation — fall back to global
        if not global_security:
            return "undeclared", []
        raw = global_security

    if raw == []:
        return "public", []

    # Extract scheme names from [{schemeName: []}] structure
    schemes = []
    for entry in raw:
        if isinstance(entry, dict):
            schemes.extend(entry.keys())

    label = schemes[0] if len(schemes) == 1 else ("mixed" if schemes else "undeclared")
    return label, raw


# ─────────────────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────────────────

def load_spec(spec_path: str | Path) -> SpecResult:
    """
    Parse an OpenAPI 3.0 YAML/JSON file and return a SpecResult.

    Parameters
    ----------
    spec_path : path to openapi_spec.yaml (or .json)

    Returns
    -------
    SpecResult with one SpecEndpoint per normalised path template.

    Raises
    ------
    FileNotFoundError  — spec file doesn't exist
    ValueError         — file is not valid YAML/JSON, or missing ``paths`` key
    """
    spec_path = Path(spec_path)
    if not spec_path.exists():
        raise FileNotFoundError(f"OpenAPI spec not found: {spec_path}")

    raw_text = spec_path.read_text(encoding="utf-8")

    # Support both YAML and JSON
    try:
        if spec_path.suffix.lower() in (".yaml", ".yml"):
            spec_dict = yaml.safe_load(raw_text)
        else:
            spec_dict = json.loads(raw_text)
    except Exception as exc:
        raise ValueError(f"Failed to parse spec file {spec_path}: {exc}") from exc

    if not isinstance(spec_dict, dict):
        raise ValueError(f"Spec file {spec_path} did not parse to a dict")

    if "paths" not in spec_dict:
        raise ValueError(f"Spec file {spec_path} has no 'paths' key")

    # Extract top-level metadata
    info            = spec_dict.get("info", {})
    spec_version    = spec_dict.get("openapi", "unknown")
    title           = info.get("title", "")
    api_version     = info.get("version", "")
    global_security = spec_dict.get("security", []) or []

    # Parse paths
    documented_paths: dict[str, SpecEndpoint] = {}

    for raw_path, path_item in spec_dict["paths"].items():
        if not isinstance(path_item, dict):
            continue

        tmpl = _normalise_path_template(raw_path)
        endpoint = SpecEndpoint(path_template=tmpl, raw_path=raw_path)

        for verb, op_obj in path_item.items():
            if verb.lower() not in _HTTP_METHODS:
                continue   # skip path-level keys like 'parameters', 'summary'
            if not isinstance(op_obj, dict):
                continue

            op_security_raw: Optional[list] = op_obj.get("security")  # None if key absent
            sec_label, sec_raw = _resolve_security(op_security_raw, global_security)

            endpoint.operations.append(OperationMeta(
                method       = verb.upper(),
                operation_id = op_obj.get("operationId"),
                summary      = op_obj.get("summary"),
                security     = sec_label,
                security_raw = sec_raw,
            ))

        if endpoint.operations:
            documented_paths[tmpl] = endpoint

    return SpecResult(
        documented_paths = documented_paths,
        path_templates   = set(documented_paths.keys()),
        spec_version     = spec_version,
        title            = title,
        api_version      = api_version,
        global_security  = global_security,
    )


# ─────────────────────────────────────────────────────────────────────────────
# __main__ — sanity-check against openapi_spec.yaml
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse as ap

    cli = ap.ArgumentParser(description="Run spec_loader against an OpenAPI spec")
    cli.add_argument("--spec", default="mock_env/openapi_spec.yaml",
                     help="Path to OpenAPI YAML/JSON file")
    args = cli.parse_args()

    print(f"Loading spec: {args.spec}\n")

    result = load_spec(args.spec)

    print(f"Title       : {result.title}")
    print(f"API version : {result.api_version}")
    print(f"OpenAPI ver : {result.spec_version}")
    print(f"Global sec  : {result.global_security or '(none)'}")
    print(f"Paths found : {len(result.documented_paths)}")
    print()

    # ── Normalisation spot-check ───────────────────────────────────────────
    # These are the actual raw paths in the spec — verify they map correctly
    raw_to_expected = {
        "/api/v1/health":                "/api/v1/health",
        "/api/v1/patients/{id}":         "/api/v1/patients/{id}",
        "/api/v1/appointments":          "/api/v1/appointments",
        "/api/v1/doctors/{id}":          "/api/v1/doctors/{id}",
        # Hypothetical — if spec used descriptive names
        "/api/v1/patients/{patientId}":  "/api/v1/patients/{id}",
        "/api/v1/doctors/{doctorId}":    "/api/v1/doctors/{id}",
    }
    print("Placeholder normalisation spot-check:")
    all_ok = True
    for raw, expected in raw_to_expected.items():
        got = _normalise_path_template(raw)
        ok  = got == expected
        if not ok:
            all_ok = False
        print(f"  {'✅' if ok else '❌'}  {raw:<45} → {got}")
    print(f"  {'All pass ✅' if all_ok else 'FAILURES ABOVE ❌'}")
    print()

    # ── Summary table ──────────────────────────────────────────────────────
    COL_PATH = 42
    COL_RAW  = 42
    HDR = (f"{'TEMPLATE (normalised)':<{COL_PATH}}  {'METHODS':<12}  "
           f"{'SECURITY':<12}  {'RAW PATH IN SPEC':<{COL_RAW}}  OPERATION IDs")
    print("=" * (len(HDR) + 2))
    print(HDR)
    print("=" * (len(HDR) + 2))

    for tmpl, ep in result.documented_paths.items():
        methods  = ",".join(sorted(ep.declared_methods))
        sec      = ep.security_label
        op_ids   = ", ".join(op.operation_id or "(none)" for op in ep.operations)
        print(f"{tmpl:<{COL_PATH}}  {methods:<12}  {sec:<12}  {ep.raw_path:<{COL_RAW}}  {op_ids}")

        # Per-method security detail (important if mixed)
        for op in ep.operations:
            auth_marker = {
                "public":      "🌐 public (no auth)",
                "bearerAuth":  "🔐 bearerAuth required",
                "undeclared":  "❓ security undeclared",
            }.get(op.security, f"? {op.security}")
            print(f"  └─ {op.method:<8} {auth_marker}   summary: {op.summary or '(none)'}")
        print()

    print("=" * (len(HDR) + 2))
    print("PATH TEMPLATES SET (what diff_engine.py will compare against log output):")
    print("=" * (len(HDR) + 2))
    for t in sorted(result.path_templates):
        ep = result.documented_paths[t]
        print(f"  {t:<{COL_PATH}}  requires_auth={ep.requires_auth}  is_public={ep.is_public}")
    print()
