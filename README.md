# Shadow API Discovery & Vulnerability Scanner

**HCIC-SI2026 — Problem 15 Submission**

> **⚠️ DISCLAIMER: SYNTHETIC DATA ONLY**
>
> All data in this repository — including patient records, Aadhaar numbers, medical diagnoses, API responses, and the contents of the committed `report.html`, `report_up.html`, and `report_down.html` files — is **100% synthetic and fictional**, generated solely for demonstration purposes. **No real Personally Identifiable Information (PII) or live production systems are involved in this project.**

## Overview

This project is a rule-based (no AI/ML) security scanner designed to discover **"Shadow APIs"** — undocumented endpoints that are actively receiving production traffic — and evaluate them for security risks. 

It accomplishes this in two phases:
1. **Passive Log Analysis**: It parses web server access logs (e.g., Nginx) and diffs the discovered traffic patterns against a provided OpenAPI 3.0 specification. Endpoints receiving traffic that aren't in the spec are flagged as "Shadow APIs".
2. **Active Vulnerability Probing**: Once endpoints are discovered, the scanner evaluates them against the **OWASP API Security Top 10 (2023)** heuristics (e.g., missing authentication, missing rate limiting). Crucially, it performs a live **Broken Object Level Authorization (BOLA)** network probe against ownership-scoped endpoints (like `/patient-records/{id}`) by attempting unauthorized cross-user access to confirm vulnerabilities.

## Quick Demo

To run a complete end-to-end scan using the provided mock environment:

```bash
# 1. Start the mock API server in the background (defaults to port 8000)
python mock_env/mock_server.py &

# 2. Generate synthetic traffic (populates mock_env/access.log)
python mock_env/generate_logs.py

# 3. Run the scanner pipeline
python scanner/cli.py \
    --log-file mock_env/access.log \
    --spec mock_env/openapi_spec.yaml \
    --mock-server-url http://localhost:8000 \
    --output report.html \
    --fail-on critical,high
```

*(Note: `--headers-log` defaults to `access_headers.log` in the same directory as `--log-file`, so it can be omitted.)*

## Example Reports

We have pre-generated example reports to demonstrate the scanner's capabilities and resilience:

- [**report.html**](./report.html) / [**report_up.html**](./report_up.html) — Two separate runs against the live mock server, included to demonstrate identical, reproducible results. Both show the full active BOLA probe evidence with a confirmed risk score of 100/100 (CRITICAL).
- [**report_down.html**](./report_down.html) — Demonstrates the scanner's honest fallback behaviour. When the mock server is unreachable, the scanner explicitly warns the user, gracefully skips active BOLA probes, scores findings accurately based only on passive analysis (score drops to 61/100, HIGH), and displays a prominent warning banner rather than silently serving stale or assumed findings.

## Repository Structure

```
.
├── mock_env/
│   ├── access.log              # Synthetic Nginx combined access log
│   ├── access_headers.log      # Companion JSONL log for Auth headers
│   ├── generate_logs.py        # Script to simulate API traffic & attacks
│   ├── mock_server.py          # Vulnerable Flask API server
│   └── openapi_spec.yaml       # Incomplete OpenAPI 3.0 specification
├── scanner/
│   ├── __init__.py
│   ├── cli.py                  # Pipeline orchestrator and CLI entrypoint
│   ├── diff_engine.py          # Compares parsed logs against the spec
│   ├── log_parser.py           # Parses Nginx logs into EndpointRecords
│   ├── report_generator.py     # Renders the self-contained HTML report
│   ├── risk_engine.py          # OWASP heuristics & active BOLA probes
│   ├── scorer.py               # Calculates the 0-100 severity risk score
│   └── spec_loader.py          # Parses and validates OpenAPI specs
├── report.html                 # Pre-generated example report
├── report_down.html            # Pre-generated report (server unreachable)
├── report_up.html              # Pre-generated report (server healthy)
├── research_log.md             # Rule 4 compliance log of cited resources
├── Shadow_API_Scanner_Build_Spec.md  # Detailed engineering design spec
├── USER_MANUAL.md              # Comprehensive usage instructions
├── requirements.txt            # Python dependencies
├── run_gen.sh                  # Helper script for log generation
├── run_risk_engine.sh          # Helper script for risk engine execution
└── smoke_test.sh               # Bash script to test the mock server
```

## Documentation

- [**USER_MANUAL.md**](./USER_MANUAL.md): Detailed instructions on configuration, integration, and interpreting scan results.
- [**research_log.md**](./research_log.md): Record of external references, documentation, and tools consulted during development (HCIC-SI2026 Rule 4 Compliance).

> **🛡️ Responsible Use**
> 
> The active probing feature (`--mock-server-url`) makes real HTTP requests that attempt unauthorized data access (BOLA testing). This feature should **only ever be pointed at systems you own or have explicit authorization to test**. Do not point the scanner at production third-party APIs.
