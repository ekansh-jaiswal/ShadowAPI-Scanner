"""
scanner/scorer.py
=================
Aggregates findings per endpoint and calculates a normalized risk score
based on severity weights.

Weights: CRITICAL=40, HIGH=25, MEDIUM=10, LOW=5, INFO=1.
Total score is capped at 100.
"""

from dataclasses import dataclass
from typing import Dict, List

try:
    from scanner.risk_engine import Finding
except ModuleNotFoundError:
    import sys, os
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
    from scanner.risk_engine import Finding


@dataclass
class ScoredEndpoint:
    path_template: str
    findings: List[Finding]
    raw_score: int   # uncapped sum — useful for auditing the cap-at-100 behaviour
    score: int       # min(raw_score, 100)
    risk_level: str  # "CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"


def _get_weight(severity: str) -> int:
    weights = {
        "CRITICAL": 40,
        "HIGH": 25,
        "MEDIUM": 10,
        "LOW": 5,
        "INFO": 1
    }
    return weights.get(severity.upper(), 0)


def calculate_score_raw(findings: List[Finding]) -> int:
    """Return the uncapped weighted sum — for auditing purposes."""
    return sum(_get_weight(f.severity) for f in findings)


def calculate_score(findings: List[Finding]) -> int:
    """Return the capped score (max 100)."""
    return min(calculate_score_raw(findings), 100)


def determine_risk_level(score: int) -> str:
    if score >= 75:
        return "CRITICAL"
    elif score >= 50:
        return "HIGH"
    elif score >= 25:
        return "MEDIUM"
    elif score > 0:
        return "LOW"
    else:
        return "NONE"


def score_endpoints(risk_results: Dict[str, List[Finding]]) -> List[ScoredEndpoint]:
    """
    Takes the output of the risk engine and returns a sorted list of scored endpoints,
    from highest risk to lowest.
    """
    scored_endpoints = []

    for endpoint, findings in risk_results.items():
        raw = calculate_score_raw(findings)
        score = min(raw, 100)
        risk_level = determine_risk_level(score)
        
        if any(f.severity == "CRITICAL" for f in findings):
            risk_level = "CRITICAL"

        scored_endpoints.append(ScoredEndpoint(
            path_template=endpoint,
            findings=findings,
            raw_score=raw,
            score=score,
            risk_level=risk_level,
        ))

    # Sort primarily by score (descending), then alphabetically by path
    scored_endpoints.sort(key=lambda x: (-x.score, x.path_template))
    return scored_endpoints


if __name__ == "__main__":
    import json
    import dataclasses
    from scanner.log_parser import parse_logs
    from scanner.spec_loader import load_spec
    from scanner.diff_engine import diff
    from scanner.risk_engine import run_risk_engine

    log_res = parse_logs("mock_env/access.log", "mock_env/access_headers.log")
    spec_res = load_spec("mock_env/openapi_spec.yaml")
    diff_res = diff(log_res, spec_res)
    risk_results = run_risk_engine(diff_res, spec_res, "http://localhost:8000")

    scored = score_endpoints(risk_results)

    print(f"{'SCORE':>5}  {'RAW':>5}  {'LEVEL':<8}  PATH")
    print("-" * 72)
    for se in scored:
        cap_marker = "*" if se.raw_score > 100 else " "
        print(f"[{se.score:3d}/100]{cap_marker} raw={se.raw_score:3d}  {se.risk_level:<8}  {se.path_template}")
        for f in se.findings:
            print(f"   - {f.severity}: {f.title}")

