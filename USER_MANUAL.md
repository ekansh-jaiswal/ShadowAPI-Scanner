# Shadow API Discovery & Vulnerability Scanner — User Manual

**Project:** HCIC-SI2026, Problem 15
**Version:** 1.0
**Last updated:** July 2026

---

## Table of Contents

1. [What This Tool Is](#1-what-this-tool-is)
2. [How It Works (The Big Picture)](#2-how-it-works-the-big-picture)
3. [Prerequisites & Setup](#3-prerequisites--setup)
4. [Quick Start — Try It in 5 Minutes](#4-quick-start--try-it-in-5-minutes)
5. [Full CLI Reference](#5-full-cli-reference)
6. [Understanding the Report](#6-understanding-the-report)
7. [Using It on a Real Project](#7-using-it-on-a-real-project)
8. [Known Limitations](#8-known-limitations)
9. [Troubleshooting](#9-troubleshooting)
10. [Project File Map](#10-project-file-map)

---

## 1. What This Tool Is

Modern web applications — especially healthcare platforms handling patient
records, prescriptions, and government IDs — expose many API endpoints.
Over time, some of these endpoints stop being documented: an old debug route
someone forgot to remove, a legacy dashboard's private integration, a
"just for testing" endpoint that quietly made it to production. These are
called **Shadow APIs** — undocumented, often forgotten, but very much alive
and reachable.

The danger: undocumented doesn't mean unprotected-by-design, but in practice
it often means **nobody is checking it for security holes**, because nobody
remembers it exists. This tool finds those endpoints and checks them for a
specific, well-known category of security bugs.

**In one sentence:** this tool compares what your API server is *actually*
being asked to do (from access logs) against what it's *supposed to* do
(from your official API documentation), flags the difference, and then
actively tests the flagged endpoints for common, serious vulnerabilities
(especially "can User A see User B's private data").

It does **not** use AI/ML — every check is a deterministic, explainable rule.
If it flags something, you can always trace exactly which rule fired and why.

---

## 2. How It Works (The Big Picture)

```
   Access Logs                  API Spec (OpenAPI/Swagger)
  (what really              (what's supposed to exist)
   happened)
        │                             │
        ▼                             ▼
   ┌─────────┐                  ┌───────────┐
   │  Parser  │                  │   Loader   │
   └────┬────┘                  └─────┬─────┘
        │                             │
        └──────────┬──────────────────┘
                    ▼
             ┌─────────────┐
             │ Diff Engine  │  →  "This endpoint is being called
             └──────┬───────┘      but isn't in your docs."
                    ▼
             ┌─────────────┐
             │ Risk Engine  │  →  Runs 7 rule-based security checks,
             └──────┬───────┘      including LIVE tests against a
                    │               running server (not just log
                    ▼               analysis).
             ┌─────────────┐
             │   Scorer     │  →  Turns findings into a 0-100 risk
             └──────┬───────┘      score per endpoint.
                    ▼
             ┌─────────────┐
             │ HTML Report  │  →  One file, opens in any browser,
             └─────────────┘      no internet needed.
```

### The 7 security checks, explained simply

| # | Check | Plain-English question it asks |
|---|---|---|
| 1 | Shadow Endpoint Existence | "Is this endpoint even documented?" |
| 2 | Sensitive Path Heuristic | "Does this endpoint's name suggest it handles sensitive data (patient, aadhaar, otp, diagnosis...)?" |
| 3 | Missing Authentication | "Does this endpoint ever get called with NO login credentials at all?" |
| 4 | **BOLA Active Probe** (the flagship check) | "If I have User A's login, can I use it to read User B's private data by just changing an ID number in the URL?" — this is **actively tested live**, not guessed from logs |
| 5 | Excessive Data Exposure | "Does the response contain sensitive fields (Aadhaar number, diagnosis, SSN) that this endpoint has no business returning?" |
| 6 | Rate Limiting Absence | "Can someone hammer this endpoint hundreds of times per second with no pushback (no HTTP 429)?" |
| 7 | HTTP Method Mismatch | "Is someone calling DELETE on an endpoint that's only supposed to support GET/POST?" |

**BOLA** = Broken Object Level Authorization. It's the #1 most common and
most damaging API vulnerability in the industry (OWASP API Security Top 10,
2023 edition, ranks it #1). In plain terms: the server checks *that* you're
logged in, but forgets to check *whether the thing you're asking for actually
belongs to you*.

---

## 3. Prerequisites & Setup

- Python 3.11 or newer
- A virtual environment (already set up in this project at `bin/`, `lib/`, etc.)

```bash
cd /home/alpha0/HCIC/project
source bin/activate
pip install -r requirements.txt   # if not already installed
```

Dependencies used: `flask` (mock server), `requests` (HTTP calls / probes),
`pyyaml` (spec parsing), `jinja2` (report templating), `openapi-spec-validator`
(spec validation). No ML/NLP libraries anywhere.

---

## 4. Quick Start — Try It in 5 Minutes

This project ships with a **mock environment**: a fake but fully functional
"SwasthyaConnect" health-gateway API, deliberately seeded with 5 realistic
vulnerabilities, so you can see the scanner work end-to-end without needing
a real production system.

**You need two terminals.**

**Terminal 1 — start the mock server (leave this running):**
```bash
cd /home/alpha0/HCIC/project
source bin/activate
python mock_env/mock_server.py
```
Leave this open. It's a live server the scanner will talk to.

**Terminal 2 — generate traffic, then scan:**
```bash
cd /home/alpha0/HCIC/project
source bin/activate

# Step A: simulate a day of API traffic (creates the log files)
python mock_env/generate_logs.py

# Step B: run the actual scan
python scanner/cli.py \
    --log-file mock_env/access.log \
    --spec mock_env/openapi_spec.yaml \
    --mock-server-url http://localhost:8000 \
    --output report.html \
    --fail-on critical,high

# Step C: open the report
xdg-open report.html   # or open the file manually in your browser
```

You should see console output ending in something like:
```
Overall Risk Exposure : CRITICAL (100/100)
Shadow endpoints      : 5
Critical findings     : 4
✖ Exit 1 — CRITICAL findings present
```

That non-zero exit code is deliberate — it's designed to make a CI/CD
pipeline (e.g. GitHub Actions) automatically block a deployment if serious
issues are found, the same way a failing test suite would.

---

## 5. Full CLI Reference

```
python scanner/cli.py [OPTIONS]
```

| Flag | Required? | Description |
|---|---|---|
| `--log-file PATH` | Yes | Path to an Nginx combined-format access log |
| `--headers-log PATH` | No | Path to the companion JSONL auth-header log. Defaults to `access_headers.log` in the same folder as `--log-file` |
| `--spec PATH` | Yes | Path to your OpenAPI 3.0 YAML/JSON spec — the "ground truth" of what should exist |
| `--mock-server-url URL` | No | Base URL of a **live, test-only** server to run active BOLA probes against. Omit this to skip active probing entirely |
| `--no-active-probes` | No | Force-disable active probing even if a URL is given |
| `--output PATH` | No | Where to write the HTML report (default: `report.html`) |
| `--fail-on SEVERITIES` | No | Comma-separated severities that trigger a non-zero exit code, e.g. `critical,high` (default). Options: `critical`, `high`, `medium`, `low`, `info` |
| `--quiet` / `-q` | No | Suppress step-by-step progress, print only the final summary |
| `--version` | No | Print version and exit |

**Exit codes** (useful for CI/CD gating):
| Code | Meaning |
|---|---|
| 0 | Success, no findings at/above your `--fail-on` threshold |
| 1 | Findings at/above your `--fail-on` threshold were found |
| 2 | Usage error (bad file path, malformed spec, etc.) |

### Common invocations

**Full scan with live vulnerability probing (most thorough):**
```bash
python scanner/cli.py --log-file access.log --spec api.yaml \
    --mock-server-url http://localhost:8000 --output report.html
```

**Passive-only scan — no live requests made anywhere (safest, use this on
logs from a system you don't have permission to actively probe):**
```bash
python scanner/cli.py --log-file access.log --spec api.yaml --no-active-probes
```

**CI/CD gate that only fails the build on CRITICAL (lets HIGH findings pass
with a warning):**
```bash
python scanner/cli.py --log-file access.log --spec api.yaml --fail-on critical
```

---

## 6. Understanding the Report

Open `report.html` in any browser — it's a single file, works fully offline.

### Executive Summary (top of page)
- **Overall Risk Exposure** — a 0-100 score with a color badge (higher = worse; this was deliberately labeled with a CRITICAL/HIGH/etc. badge next to the number so it's never mistaken for a "good" score)
- **Shadow Endpoints** — count of undocumented-but-live endpoints found
- **Critical Findings** — count of the most severe issues
- A severity breakdown bar (CRITICAL/HIGH/MEDIUM/LOW/INFO counts)

### Attack Surface Table
Every discovered endpoint, sortable and filterable by clicking column
headers / severity buttons. Shadow endpoints are marked with a `[SHADOW]`
tag so you can immediately tell "this exists but was never supposed to
publicly."

### Per-Endpoint Detail Cards
Click to expand. Each card shows:
- The path, HTTP methods seen, and how many times it was hit
- Every finding for that endpoint, tagged with its OWASP API Top 10
  category (e.g. `API1:2023 Broken Object Level Authorization`)
- **Evidence blocks** — for BOLA findings, this shows the *actual* request
  URL and response that was captured live during the scan (e.g. "we
  requested patient 111's record using patient 101's login token, and got
  back a 200 OK with their full Aadhaar number and diagnosis"). This is
  real proof, not a guess.
- A remediation suggestion

### DPDP Act Callouts
On findings involving personal/health data, you'll see a small box titled
"⚖ DPDP Act 2023 — Provisions to Review." This lists sections of India's
Digital Personal Data Protection Act that are *relevant to* the finding —
for example, exposing Aadhaar numbers beyond an endpoint's stated purpose
is relevant to the data-minimization principle in Section 6.

**Important:** this tool is not a lawyer and makes no legal determinations.
Every callout is phrased as "relevant to" / "may warrant review," never
"violates" — it's flagging a technical fact worth a compliance professional's
attention, not passing legal judgment.

### The Warning Banner (only appears if probes failed)
If the live server was unreachable when the scan ran, a prominent amber
banner appears at the top stating that active probes were skipped and
findings are passive-only (i.e., **no BOLA vulnerability was actually
re-confirmed live** in that run — you're seeing what the logs suggest
might be worth checking, not a proven exploit).

---

## 7. Using It on a Real Project

The mock environment exists so you can learn the tool safely. To point it
at something real:

1. **Get your access logs.** Nginx: usually `/var/log/nginx/access.log`
   in "combined" format. Apache: similar, `combined` log format.
2. **Get (or write) your OpenAPI spec.** Many frameworks (FastAPI, NestJS
   with Swagger, Spring with springdoc) can auto-generate one. If you
   don't have one, this is itself a valuable exercise — the act of writing
   an accurate spec often *surfaces* forgotten endpoints on its own.
3. **Decide on active probing carefully.** Only point `--mock-server-url`
   at a server you own or have explicit written permission to test. Never
   run active probes against production systems or third-party services
   without authorization — that crosses from security research into
   unauthorized access. For a first pass on an unfamiliar system, always
   start with `--no-active-probes`.
4. Run the scan, review the report, prioritize CRITICAL and HIGH findings
   first.

---

## 8. Known Limitations

Being upfront about these is part of good security practice — no scanner
is complete, and knowing the blind spots matters as much as the findings.

- **BOLA ownership detection uses a keyword allowlist**, not true semantic
  understanding. It assumes endpoints with paths containing words like
  `patient`, `appointment`, `insurance` are "ownership-scoped" resources
  worth testing, while things like `doctors` (a public directory) are not.
  On a real system with differently-named resources, this list would need
  to be customized.
- **The header-log join assumes matching line counts** between the access
  log and the companion auth-header JSONL log. If they ever drift out of
  sync, the tool fails loudly (a `LogMismatchError`) rather than silently
  misattributing auth data — this is intentional, but it does mean the two
  files must be generated/collected together.
- **Rate-limiting detection is a heuristic on log volume**, not a live load
  test — it infers "no rate limiting" from the *absence* of 429 responses
  in historical traffic, which could theoretically miss rate-limiting that
  exists but wasn't triggered during the log window.
- **Active probes require a server that's actually reachable and willing
  to be tested.** This is by design (see Section 7) but means the tool's
  most powerful check (live BOLA confirmation) simply won't run against
  logs from a system you can't currently reach.

---

## 9. Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `curl: (7) Failed to connect` right after starting the mock server | Server and curl command run in the *same* terminal — Ctrl+C (or the command finishing) kills the server before curl can reach it | Use two terminals: one to run the server and leave it alone, one for everything else |
| `--log-file not found: ...` | Typo'd path, or forgot to run `generate_logs.py` first | Check the path; run `python mock_env/generate_logs.py` if using the mock env |
| `LogMismatchError` | `access.log` and `access_headers.log` have different line counts | Re-run `python mock_env/generate_logs.py` to regenerate both files in sync |
| Report shows an amber "Active Probes Skipped" banner unexpectedly | The mock/target server wasn't running (or was unreachable) when the scan ran | Start the server first (Terminal 1), confirm `curl <url>/api/v1/health` works, then re-run the scan |
| Report looks the same whether the server is up or down | This was a real bug found and fixed during development — if you see this on the current version, something has regressed; check that `probe_status` warnings are wired through `cli.py` → `risk_engine.py` → `report_generator.py` | Re-verify using the test in this section: kill the server, re-run a scan, confirm the banner appears and Critical Findings drops to 0 |

---

## 10. Project File Map

```
project/
├── mock_env/
│   ├── mock_server.py       — Fake "SwasthyaConnect" API with 4 legit +
│   │                          5 deliberately-shadow endpoints
│   ├── openapi_spec.yaml    — Ground-truth spec (only documents the 4
│   │                          legitimate endpoints)
│   ├── generate_logs.py     — Simulates realistic traffic + attack patterns
│   ├── access.log           — Generated Nginx-format log (run generate_logs.py)
│   └── access_headers.log   — Companion auth-header data (JSONL)
├── scanner/
│   ├── log_parser.py        — Reads access logs into structured records
│   ├── spec_loader.py       — Reads the OpenAPI spec into the same format
│   ├── diff_engine.py       — Finds Shadow / Dormant / OK endpoints
│   ├── risk_engine.py       — Runs the 7 OWASP-based security checks
│   ├── scorer.py            — Turns findings into a 0-100 score
│   ├── report_generator.py  — Builds the self-contained HTML report
│   └── cli.py                — Ties everything together; the command you run
├── report.html               — Your generated report (after running a scan)
├── research_log.md           — Citations & build milestones (competition rule 4)
└── Shadow_API_Scanner_Build_Spec.md — Original technical build spec
```

---

*This tool was built as part of HCIC-SI2026 (Problem 15). It uses no AI/ML
components — all detection logic is deterministic and rule-based, chosen
specifically so every finding can be traced back to an explainable cause.*
