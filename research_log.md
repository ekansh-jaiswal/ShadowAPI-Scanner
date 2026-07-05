# Research Collection Log — Shadow API Discovery & Vulnerability Scanner
### HCIC-SI2026 — Problem 15

Per competition Rule 4, every research/reference resource used throughout the
project lifecycle must be logged here with Date & Timestamp, Resource Name,
and Reference Link. Add an entry every time you consult external material —
docs, standards, articles, Stack Overflow answers, library references, etc.
AI-assistance sessions used for scaffolding should also be logged (Rule 5).

---

## Log Format

| Date & Timestamp (IST) | Resource Name | Reference Link | Notes / What it was used for |
|---|---|---|---|
| 2026-07-05 14:00 | OWASP API Security Top 10 (2023) | https://owasp.org/API-Security/editions/2023/en/0x11-t10/ | Basis for the 7 risk-engine checks (BOLA, Broken Auth, Excessive Data Exposure, etc.) |
| 2026-07-05 14:10 | OpenAPI Specification v3.0.3 | https://spec.openapis.org/oas/v3.0.3 | Format reference for openapi_spec.yaml |
| 2026-07-05 14:15 | openapi-spec-validator (PyPI) | https://pypi.org/project/openapi-spec-validator/ | Used to validate openapi_spec.yaml against OAS schema |
| 2026-07-05 14:20 | Nginx Combined Log Format docs | https://nginx.org/en/docs/http/ngx_http_log_module.html | Format reference for access.log generation |
| 2026-07-05 14:25 | Flask documentation | https://flask.palletsprojects.com/ | Mock API server (mock_server.py) framework reference |
| 2026-07-05 23:52 | Digital Personal Data Protection Act, 2023 (No. 22 of 2023) | https://www.meity.gov.in/writereaddata/files/Digital%20Personal%20Data%20Protection%20Act%202023.pdf | Sections 6, 8(1), and 8(7) cited in the DPDP overlay in report_generator.py. Referenced for data minimisation principle (§6) and data fiduciary obligations including reasonable security safeguards and incident notification (§8). All references phrased as indicative provisions a reader may wish to review — no legal determinations made. |

---

## Milestone / Build Log (internal process record — supplements the table above)

| Date | Milestone | Verified By |
|---|---|---|
| 2026-07-05 | Step 1: mock_server.py built and smoke-tested (11/11 endpoints verified with real curl output) | Manual curl testing, all responses inspected |
| 2026-07-05 | Step 2: openapi_spec.yaml built, validated with openapi-spec-validator (0 errors) | Automated validator + manual review of paths/security schemes |
| 2026-07-05 | Step 3: generate_logs.py built — 485 synthetic requests generated across 9 endpoints, burst patterns grep-confirmed (insurance-claims burst: 45/60 from single IP; OTP brute-force: 52/52 from single IP) | grep verification + manual log sampling |
| 2026-07-05 | Step 4: log_parser.py — positional join to headers log, LogMismatchError guard; 9 templates, correct normalisation spot-check | __main__ block run, all path normalisation assertions passed |
| 2026-07-05 | Step 5: spec_loader.py — 4 documented paths, bearerAuth, is_public/requires_auth properties | __main__ block run, all 4 paths loaded with correct security labels |
| 2026-07-05 | Step 6: diff_engine.py — Shadow=5, Dormant=0, OK=4; dormant synthetic test passed; fuzzy-match test passed | 3-run __main__ block, all assertions passed |
| 2026-07-05 | Step 7: risk_engine.py — 7 OWASP checks; BOLA ownership allowlist (no false positive on /doctors); rate-limit health exemption | Active probe smoke tests + 11/11 curl tests |
| 2026-07-05 | Step 8: scorer.py — weighted 0-100 (CRITICAL=40,HIGH=25,MEDIUM=10,LOW=5,INFO=1); raw_score + cap auditing; 3 CRITICAL endpoints score 100 | __main__ output reviewed, no double-counting verified |
| 2026-07-05 | Step 9: report_generator.py — 96 KB self-contained HTML; 0 CDN refs; BOLA evidence with real Aadhaar-shaped data; sortable table + collapsible cards + SVG severity chart | grep + Python extraction of all 4 sections verified |
| 2026-07-05 | Step 10: cli.py — 6-step pipeline; rank-based --fail-on threshold (bug fixed during verification); exit 0/1/2/3 | 6-test exit code matrix, all results confirmed with echo $? |
| 2026-07-05 | DPDP Overlay — _DPDP_MAP (§6, §8(1), §8(7)) added to report_generator.py; 9/9 notes pass language audit (no "violates"); 24 callout blocks in report | Language audit script + rendered callout text verified |

---

## Notes on Rule Compliance

- **Rule 5 (AI assistance disclosure):** This project's scaffolding was built with
  AI assistance (Claude) as an assistance tool per the allowed use. All generated
  code has been manually reviewed, run, and verified against real curl/log output
  at each step (see Milestone Log above) before proceeding — not accepted blindly.
- **Rule 9/10 (data handling):** All patient data, Aadhaar-shaped numbers, and
  tokens used throughout this project are synthetic/fictional. No real PII,
  credentials, or live third-party systems were accessed. The mock server and
  BOLA probe only ever target `localhost` infrastructure built for this project.
- **Rule 6 (no fabricated results):** All findings/metrics reported at each step
  are outputs of code actually executed, with real terminal output retained as
  evidence (see conversation history / terminal logs).
