# Shadow API Discovery & Vulnerability Scanner

**HCIC-SI2026 — Problem 15 Submission**

> **Disclaimer: synthetic data only.**
> All data in this repository — patient records, Aadhaar numbers, medical diagnoses, API responses, and everything in the committed `report.html`, `report_up.html`, and `report_down.html` files — is entirely made up, built for demonstration only. No real personal data and no live production system is involved anywhere in this project.

## Overview

This is a rule-based security scanner, with no AI or machine learning involved, built to find **Shadow APIs** — endpoints that are actively receiving traffic in production but were never documented.

It works in two stages:

1. **Passive log analysis.** It reads web server access logs (Nginx format) and compares the traffic it finds against a given OpenAPI 3.0 spec. Any endpoint receiving traffic that isn't in the spec gets flagged as a Shadow API.
2. **Active vulnerability probing.** Once an endpoint is flagged, the scanner checks it against OWASP API Security Top 10 (2023) heuristics — missing authentication, missing rate limiting, and so on. For endpoints tied to a specific user's data (like `/patient-records/{id}`), it goes further and sends a real request attempting cross-user access, to confirm a Broken Object Level Authorization (BOLA) bug rather than just guessing one might exist.

## Quick Demo

Run a full scan end to end using the included mock environment:

```bash
# 1. Start the mock API server (defaults to port 8000)
python mock_env/mock_server.py &

# 2. Generate synthetic traffic (writes to mock_env/access.log)
python mock_env/generate_logs.py

# 3. Run the scanner
python scanner/cli.py \
    --log-file mock_env/access.log \
    --spec mock_env/openapi_spec.yaml \
    --mock-server-url http://localhost:8000 \
    --output report.html \
    --fail-on critical,high
```

`--headers-log` defaults to `access_headers.log` in the same folder as `--log-file`, so it can be left out.

## Example Reports

Three pre-generated reports are included so you can see the output without running anything yourself:

- **report.html** / **report_up.html** — two separate runs against the live mock server, kept as proof the results are reproducible. Both show the full BOLA probe evidence with a risk score of 100/100 (CRITICAL).
- **report_down.html** — shows what happens when the mock server is unreachable. The scanner warns clearly, skips the active probes instead of guessing, scores findings from log data alone (score drops to 61/100, HIGH), and shows a warning banner rather than silently repeating stale results.

## Repository Structure

```
.
├── mock_env/
│   ├── access.log              Synthetic Nginx-format access log
│   ├── access_headers.log      Companion JSONL log for auth headers
│   ├── generate_logs.py        Simulates realistic traffic and attack patterns
│   ├── mock_server.py          Flask API with 4 legitimate + 5 deliberately shadow endpoints
│   └── openapi_spec.yaml       Spec documenting only the 4 legitimate endpoints
├── scanner/
│   ├── __init__.py
│   ├── cli.py                  Entry point, wires the pipeline together
│   ├── diff_engine.py          Finds shadow / dormant / documented endpoints
│   ├── log_parser.py           Parses access logs into structured records
│   ├── report_generator.py     Builds the self-contained HTML report
│   ├── risk_engine.py          The 7 OWASP-based checks plus the live BOLA probe
│   ├── scorer.py               Turns findings into a 0-100 risk score
│   └── spec_loader.py          Parses and validates the OpenAPI spec
├── report.html                 Pre-generated example report
├── report_down.html            Pre-generated report (server unreachable)
├── report_up.html              Pre-generated report (server healthy)
├── research_log.md             Sources cited and build milestones (Rule 4)
├── Shadow_API_Scanner_Build_Spec.md   Original design spec
├── USER_MANUAL.md              Full usage guide
├── requirements.txt
├── run_gen.sh
├── run_risk_engine.sh
└── smoke_test.sh
```

## Documentation

- **USER_MANUAL.md** — how the tool works, the full CLI reference, and how to read the report
- **research_log.md** — sources consulted during development, logged per HCIC-SI2026 Rule 4

## Responsible Use

The active-probing feature (`--mock-server-url`) sends real requests that attempt unauthorized data access, as part of the BOLA check. Only point it at systems you own or have explicit permission to test. Never run it against a production system or a third party's API without authorization.
