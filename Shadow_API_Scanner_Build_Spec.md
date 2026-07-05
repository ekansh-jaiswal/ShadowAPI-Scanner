# Shadow API Discovery & Vulnerability Scanner — Build Spec
### Project 15 (HCIC-SI2026) — Implementation Handoff Document

This document is a complete, self-contained spec. Hand this directly to a coding
assistant (or use it yourself) to begin implementation with no further clarification
needed. Language: **Python 3.11+**. No ML/NLP — all detection logic is rule-based.

---

## 1. PROJECT GOAL (one paragraph)

Build a CLI tool that ingests web server access logs (Nginx/Apache style) from a
simulated Indian digital-health API gateway, extracts every unique API endpoint
actually being hit in production, compares that list against a "known good"
OpenAPI/Swagger spec, flags any endpoint NOT in the spec as a **Shadow API**,
runs a set of rule-based OWASP API Top 10 checks against discovered endpoints
(including an active BOLA probe against a live mock server), scores each finding
by severity, and outputs an interactive single-file HTML report.

---

## 2. SYSTEM ARCHITECTURE

```
┌─────────────────────┐
│  Synthetic Log Gen   │  (one-time setup script, Phase 0)
│  + Mock API Server   │
└──────────┬───────────┘
           │ produces
           ▼
┌──────────────────────┐      ┌────────────────────────┐
│   access.log (Nginx  │      │  openapi_spec.yaml      │
│   combined format)   │      │  (the "known good" spec)│
└──────────┬───────────┘      └───────────┬─────────────┘
           │                              │
           ▼                              ▼
   ┌───────────────┐            ┌──────────────────┐
   │  Log Parser    │            │  Spec Loader      │
   │  Module        │            │  Module           │
   └───────┬────────┘            └─────────┬─────────┘
           │  normalized endpoint list      │  documented endpoint list
           └───────────────┬─────────────────┘
                            ▼
                  ┌───────────────────┐
                  │   Diff Engine      │
                  │ (path-template     │
                  │  matching, e.g.    │
                  │  /patient/{id})    │
                  └─────────┬──────────┘
                            ▼
                  Shadow Endpoints List
                            │
                            ▼
                  ┌───────────────────┐
                  │  Risk / Vuln       │
                  │  Rule Engine       │
                  │  (OWASP API Top 10 │
                  │  heuristics +      │
                  │  active BOLA probe │
                  │  against mock API) │
                  └─────────┬──────────┘
                            ▼
                  Scored Findings (JSON)
                            │
                            ▼
                  ┌───────────────────┐
                  │  HTML Report       │
                  │  Generator         │
                  │  (Jinja2 template, │
                  │  single self-      │
                  │  contained file)   │
                  └───────────────────┘
```

### 2.1 Module breakdown

**`log_parser.py`**
- Input: path to an Nginx "combined" or "combined+" format access log file.
- Regex-parses each line into: `timestamp, method, path, query_params, status_code, response_size, user_agent, source_ip`.
- Normalizes paths into templates by replacing numeric/UUID/token-like segments with placeholders:
  - `/patient/104` → `/patient/{id}`
  - `/api/v1/report/8f14e45f` → `/api/v1/report/{id}`
- Output: a `List[EndpointRecord]` (dataclass) and a deduplicated `Set[str]` of path templates with hit counts, methods seen, and sample raw paths (for evidence in the report).

**`spec_loader.py`**
- Input: path to an OpenAPI 3.0 YAML/JSON file.
- Parses `paths:` section into the same path-template format as the log parser output, so the two are directly comparable.
- Output: `Set[str]` of documented path templates, plus per-path metadata (declared methods, declared auth requirements — `security:` block).

**`diff_engine.py`**
- Input: discovered path templates (from logs) vs documented path templates (from spec).
- Logic:
  - `documented ∩ discovered` → OK / expected traffic
  - `discovered - documented` → **Shadow API** (undocumented endpoint actively receiving traffic)
  - `documented - discovered` → **Dormant/Zombie Documented Endpoint** (bonus finding — documented but never called; interesting for "unused legacy endpoint" narrative)
- Fuzzy-matches path templates that differ only in placeholder naming (`{id}` vs `{patientId}`) so we don't get false positives from naming mismatches.

**`risk_engine.py`** — the OWASP API Top 10 rule-based checks. Each check is an independent function taking an `EndpointRecord` (+ optionally live network access to the mock server) and returning zero or more `Finding` objects with a severity (`CRITICAL/HIGH/MEDIUM/LOW/INFO`).

Implement these checks (all rule-based, no ML):

1. **Shadow Endpoint Existence** (INFO/MEDIUM baseline) — any endpoint not in spec is automatically flagged; severity bumped based on checks 2-7 below.
2. **Sensitive Path Heuristic** — path or query params contain sensitive keywords (`patient`, `ehr`, `aadhaar`, `abha`, `otp`, `prescription`, `diagnosis`, `insurance`, `report`) → severity bump (this is your "sensitivity weighting" creative addition).
3. **Missing Auth Header Heuristic** — cross-reference log entries: does this path template ever appear WITHOUT an `Authorization` header or session cookie in the logs (if log format includes it), or is it a shadow endpoint the spec never assigned a `security:` requirement to → flag as **Broken Authentication (API2:2023)**.
4. **BOLA Active Probe** (the flagship feature) — for any discovered endpoint matching pattern `/{resource}/{id}` where `{id}` is numeric (e.g. `/patient/104`), the tool will (against the MOCK server only, never a real system):
   - Take an observed ID from the logs (e.g. 104)
   - Send a request to `id - 1` and `id + 1` (e.g. 103, 105) with **no auth token**, or with a different test-user's token
   - If the mock server returns HTTP 200 with a full data payload instead of 401/403 → flag as **CRITICAL: Broken Object Level Authorization (API1:2023)**, with the request/response as evidence.
5. **Excessive Data Exposure Heuristic** — parse mock server JSON responses (only against the mock server) for field count/PII-shaped fields (keys like `ssn`, `aadhaar_number`, `full_name`, `dob`, `diagnosis`) beyond what the endpoint's stated purpose needs → flag as **API3:2023 Excessive Data Exposure**.
6. **Rate Limiting Absence** — check if repeated rapid requests (the log generator will simulate a burst) to the same endpoint from the same IP ever get throttled (429) → if never, flag as **API4:2023 Unrestricted Resource Consumption**.
7. **HTTP Method Mismatch** — endpoint appears in logs with a method (e.g. `DELETE`) not declared in the spec for that path → flag as **API9:2023 Improper Inventory Management**.

**`scorer.py`**
- Aggregates all findings per endpoint into an overall risk score (weighted sum, simple 0-100 scale — NOT ML, just a deterministic weighted formula you define and document, e.g. `CRITICAL=40, HIGH=25, MEDIUM=10, LOW=5, INFO=1`, capped at 100).
- Sorts endpoints by score descending for the report.

**`report_generator.py`**
- Uses Jinja2 to render a single self-contained HTML file (`report.html`) with inline CSS/JS (no external CDN dependency, so it works offline — good for judge demo).
- Sections:
  1. Executive summary (total endpoints discovered, # shadow, # critical findings, overall gateway risk score)
  2. Attack surface table (sortable/filterable by severity — vanilla JS, no framework needed)
  3. Per-endpoint detail cards (expandable) showing: path, methods, hit count, matched OWASP category, evidence (raw request/response for BOLA proof), remediation suggestion
  4. Simple bar chart of findings by severity (can hand-roll with SVG/CSS — no charting library needed, or use Chart.js from a local vendored copy to stay offline)
- CLI exits non-zero if any CRITICAL or HIGH finding exists (mirrors Problem 14's CI/CD-friendly exit-code pattern — nice cross-pollination detail to mention in your report as "designed with CI/CD gating in mind, matching industry practice").

**`cli.py`** (entry point)
```
python scanner.py \
  --log-file mock_env/access.log \
  --spec mock_env/openapi_spec.yaml \
  --mock-server-url http://localhost:8000 \
  --output report.html \
  --fail-on critical,high
```

---

## 3. PHASE 0: MOCK ENVIRONMENT (build this FIRST, before the scanner)

You need something real to scan. Build this as a self-contained subfolder `mock_env/`.

### 3.1 Mock API Server (`mock_env/mock_server.py`)

A simple Flask (or FastAPI) app simulating a fictional "Indian digital health gateway"
called **"SwasthyaConnect"** (fictional name — avoid using real Ayushman Bharat/ABDM
branding to keep it clearly a simulation).

Endpoints to implement, SOME documented in the spec, SOME deliberately NOT
(the shadow ones):

**Documented in OpenAPI spec (the "known good" list):**
- `GET /api/v1/patients/{id}` — requires `Authorization: Bearer <token>`, returns basic patient demographic info only (name, age, gender) — NOT diagnosis/aadhaar (deliberately minimal, this is the "correct" version)
- `POST /api/v1/appointments` — requires auth
- `GET /api/v1/doctors/{id}` — requires auth
- `GET /api/v1/health` — public health-check, no auth needed (expected, low-risk, used to show a false-positive-avoidance case)

**Shadow endpoints (exist in the server, NOT in the spec — these are what the scanner should discover):**
- `GET /api/v1/patient-records/{id}` (note: legacy naming, `patient-records` not `patients`) — **BOLA vulnerable**: returns FULL record including `aadhaar_number`, `diagnosis`, `prescription`, regardless of whether the Bearer token matches that patient. No ownership check at all. This is your flagship "found a real vuln" demo endpoint.
- `GET /api/v1/internal/debug/patient/{id}` — no auth required at all, returns raw DB row including internal notes. **Critical excessive-data-exposure + missing-auth combo finding.**
- `DELETE /api/v1/appointments/{id}` — exists and works, but only `POST /api/v1/appointments` is documented in the spec (no DELETE) → **Improper Inventory Management** finding.
- `GET /api/v1/patients/{id}/insurance-claims` — undocumented nested resource, no rate limiting, returns claims history — good candidate for the "Excessive Data Exposure" + "Rate Limiting Absence" combo.
- `GET /api/v1/otp/verify?patient_id={id}&otp={otp}` — undocumented, no rate limiting on OTP attempts (a classic real-world vuln pattern: OTP brute-forcing) → nice "creative but in-scope" finding tied to your earlier DPDP/OTP context.

Use an in-memory Python dict as the "database" seeded with ~15 fake patient records
(use clearly fake data: `Patient_001` names, dummy 12-digit numbers NOT resembling
real Aadhaar checksum-valid numbers, fictional diagnoses). No real PII, obviously.

### 3.2 OpenAPI Spec (`mock_env/openapi_spec.yaml`)

Standard OpenAPI 3.0 YAML documenting ONLY the 4 legitimate endpoints listed above,
with proper `security:` schemes (`bearerAuth`) declared for 3 of them and left open
for `/health`. This is the "ground truth" the scanner diffs against.

### 3.3 Synthetic Log Generator (`mock_env/generate_logs.py`)

A script that:
1. Spins up traffic against the mock server (via `requests`) simulating realistic
   usage over a fake time window (e.g. 24 hours compressed).
2. Hits the documented endpoints normally, with proper auth, at a steady low rate.
3. Hits the shadow endpoints at a lower, "sneaky legacy system" frequency —
   simulates e.g. an old internal dashboard tool still calling
   `/patient-records/{id}` a few times per hour.
4. Includes a deliberate **burst** of rapid requests to
   `/api/v1/patients/{id}/insurance-claims` from one IP (to trigger the rate-limiting-absence check).
5. Includes a deliberate **OTP brute-force pattern**: 50 rapid sequential requests
   to `/api/v1/otp/verify` with incrementing OTP guesses from one IP.
6. Writes all this traffic to `mock_env/access.log` in Nginx combined log format:
   ```
   127.0.0.1 - - [05/Jul/2026:14:23:01 +0530] "GET /api/v1/patient-records/104 HTTP/1.1" 200 512 "-" "SwasthyaLegacyDashboard/1.2"
   ```
7. Also writes a companion `access_headers.log` (JSONL, one object per request) capturing whether an Authorization header was present and what token was used — since standard Nginx combined format doesn't include headers, and the risk engine needs this for the auth-check heuristics. Document this clearly in the README as "in a real deployment this would come from an enhanced Nginx log format (`$http_authorization`) or an APM/WAF log; we simulate it as a paired JSONL file for this project."

---

## 4. SUGGESTED BUILD ORDER (for the coding assistant)

1. `mock_env/mock_server.py` — get the fake API running first, manually curl-test it.
2. `mock_env/openapi_spec.yaml` — write the ground-truth spec.
3. `mock_env/generate_logs.py` — generate `access.log` + `access_headers.log`.
4. `log_parser.py` — parse logs into normalized endpoint records; unit-test against the generated log.
5. `spec_loader.py` — parse the spec into the same normalized format.
6. `diff_engine.py` — compute shadow/dormant sets; print to console first before building the full report.
7. `risk_engine.py` — implement checks 1-7 one at a time, starting with the BOLA active probe since it's the flagship feature (requires the mock server running live during a scan for checks 4-6).
8. `scorer.py` — aggregate.
9. `report_generator.py` + Jinja2 template — build the HTML output last, once findings JSON is stable.
10. `cli.py` — wire it all together with `argparse` or `click`, add the CI-friendly exit codes.

---

## 5. PHASE 2 / "CREATIVE EXTENSION" IDEAS (for your report's Roadmap section — don't build all of these, just 1-2 for the actual demo, list the rest as future work)

- **Attack graph view**: render endpoints as a node graph (which endpoints share auth tokens/session patterns, cluster by resource type) using a simple force-directed layout (D3.js, vendored locally).
- **Temporal drift mode**: run the scanner against two log snapshots (e.g. week 1 vs week 2) and highlight newly-appeared shadow endpoints — "API drift" detection.
- **DPDP compliance overlay**: tag each sensitive-data finding against DPDP Act sections (e.g. Section 8 - data fiduciary obligations, Section 9 - children's data) for a compliance-flavored view — ties back into Problem 7's theme without scope creep.
- **Slack/webhook alerting** on CRITICAL findings — mirrors Problem 14's CI/CD-friendly design philosophy.
- **Multi-format log support**: add Apache combined format and JSON-structured logs (e.g. AWS ALB logs) alongside Nginx.
- **PDF export** of the HTML report (via `weasyprint`) for judges who want a static copy.

---

## 6. TECH STACK SUMMARY

- Python 3.11+
- `flask` (mock server)
- `requests` (log generator + BOLA probe client)
- `pyyaml` (spec parsing)
- `jinja2` (report templating)
- `click` or `argparse` (CLI)
- No ML/NLP libraries anywhere in this stack.
- Optional: `rich` for nice CLI console output during scanning.

---

## 7. DELIVERABLES CHECKLIST (maps to evaluation criteria)

- [ ] Working mock environment (server + spec + logs) — proves you understand the problem domain
- [ ] CLI scanner producing correct shadow-endpoint diff — Technical Execution
- [ ] At least the BOLA active-probe check fully working end-to-end — this is your "wow" moment for judges
- [ ] Interactive HTML report — Documentation & Demonstration
- [ ] README explaining architecture + how to run (`python generate_logs.py && python scanner.py ...`)
- [ ] Research log (per HCIC rules) citing: OWASP API Security Top 10 (2023) list, dependency-confusion-style prior art if referenced, any Nginx log format documentation used
- [ ] 2-3 page report using the provided documentation template (Executive Overview, Technical Architecture, Key Deliverables, Security Highlights, Challenges & Roadmap)

---

*End of build spec. A coding assistant should be able to start with Section 4, Step 1 immediately.*
