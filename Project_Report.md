PROJECT TITLE: Shadow API Discovery & Vulnerability Scanner

Date: July 2026 | Author/Lead: Ekansh Jaiswal | Status: Completed / V1 Deployed

Project Links: https://github.com/ekansh-jaiswal/ShadowAPI-Scanner


1. Executive Overview

Objective: To build a rule-based (non-ML) security scanner that discovers
undocumented "Shadow APIs" in production systems by comparing real traffic
against an official API specification, then actively verifies whether those
undocumented endpoints are exploitable.

The Challenge: Digitized healthcare platforms — such as India's ABDM-style
digital health integrations — expose extensive web APIs. Over time, some
endpoints stop being documented: a legacy debug route, an old internal
dashboard's private integration, or a "temporary" endpoint that quietly made
it to production. These Shadow APIs are dangerous specifically because they
are undocumented — nobody is actively monitoring or securing something that
nobody remembers exists, even though it may still be handling sensitive
health data.

The Solution: A Python-based CLI pipeline that (1) parses web server access
logs to determine every endpoint actually receiving traffic, (2) diffs this
against an OpenAPI 3.0 specification to flag any endpoint not officially
documented, (3) runs seven deterministic checks based on the OWASP API
Security Top 10 (2023) against every discovered endpoint, and (4) for
ownership-scoped resources, performs a live active network probe attempting
cross-user access — not inferring a vulnerability exists, but actually
confirming it with a real request and a real response.

Business Impact: Demonstrated against a simulated "SwasthyaConnect" health
gateway seeded with five deliberately undocumented endpoints, the scanner
correctly identified all five Shadow APIs with zero false positives, and
live-confirmed three critical Broken Object Level Authorization (BOLA)
vulnerabilities — each backed by an actual captured HTTP request/response
showing one patient's Aadhaar number, diagnosis, and prescription data being
returned using a different patient's login token. The tool also correctly
avoided flagging two legitimate, non-vulnerable endpoints (a public health
check and a public doctor directory) that an earlier, less careful version
of the risk logic had incorrectly flagged — a false-positive rate that
matters as much as the true-positive rate in a tool meant to be trusted by
a security team.


2. Technical Architecture & Stack

Backend / Scripting: Python 3.11, Flask (mock API server for demonstration),
Jinja2 (report templating)

Data & Parsing: PyYAML (OpenAPI spec parsing), openapi-spec-validator
(spec correctness validation), regex-based Nginx combined-log parsing

Frontend / Report: Single self-contained HTML file — inline CSS and vanilla
JavaScript only, no external CDN dependencies, so the report is fully
viewable offline and requires no server to render

System Flow:
[Access Logs + Auth-Header Log] + [OpenAPI Spec]
   → [Log Parser / Spec Loader]
   → [Diff Engine: Shadow / Dormant / Documented]
   → [Risk Engine: 7 OWASP checks + live BOLA probe]
   → [Scorer: weighted 0–100 risk score per endpoint]
   → [HTML Report Generator]
   → [CLI: CI/CD-ready exit codes]


3. Key Deliverables & Features

Shadow API Discovery: Deterministically diffs discovered traffic against an
OpenAPI spec to surface undocumented endpoints, using path-template
normalization (e.g. /patient/104 and /patient/117 both correctly normalize
to /patient/{id}) so real endpoints aren't miscounted as many different
ones.

Live BOLA Confirmation: The scanner does not merely infer that an endpoint
might be vulnerable from traffic patterns. It performs an active request
using one user's authentication token against another user's resource, and
records the real response. A finding is only marked CRITICAL when this live
request succeeds — the report shows the actual captured evidence, not a
predicted risk.

Ownership-Scope Filtering: An early version of the BOLA probe fired
indiscriminately on any numeric-ID endpoint, incorrectly flagging a public
doctor-directory lookup as a vulnerability (looking up any doctor by ID is
legitimate, expected behavior — there is no "owner" of a doctor record).
This was caught during manual review and fixed by restricting the BOLA
probe to endpoints tied to genuinely ownership-scoped resources, eliminating
this class of false positive.

DPDP Act 2023 Contextual Overlay: Findings involving personal or health
data are annotated with the DPDP Act sections a reader may wish to review
(e.g. Section 6 on purpose/collection limitation, Section 8(1) on
reasonable security safeguards). All such references are deliberately
phrased as "relevant to" or "may warrant review under" rather than
"violates" — the tool makes technical findings, not legal determinations.


4. Implementation of Highlights & Performance

Security & Compliance: All demonstration data (patient records, Aadhaar-
shaped numbers, diagnoses) is entirely synthetic; no real PII or production
systems were accessed at any point in development or testing. The scanner's
own active-probing feature is documented as intended for use only against
systems the user owns or is explicitly authorized to test.

Robustness / Failure Handling: During manual testing, a genuine bug was
discovered: running the scanner with the mock server unreachable still
produced the full set of "confirmed" CRITICAL findings, identical to a run
where the server was live — meaning a network failure could silently
produce misleading results. This was root-caused (a swallowed exception in
the probe request handling) and fixed: the scanner now performs a startup
health check, and if the target server is unreachable, it clearly displays
a warning banner (both in the CLI and in the HTML report), automatically
falls back to passive-only findings, and the risk score correctly drops
(from CRITICAL/100 to HIGH/61 in the test case) rather than silently
repeating stale results.

Quality Assurance: Every pipeline stage was manually verified against real
output at each step — including deliberately breaking the tool (missing
files, malformed specs, a killed mid-scan server) rather than only testing
the happy path. The CLI's exit-code logic (used for CI/CD gating) was
verified across six scenarios: a full scan, a passive-only scan, and four
`--fail-on` severity threshold combinations, including catching and fixing
a rank-comparison bug where `--fail-on medium` failed to trigger on a
CRITICAL finding due to an incorrect set-membership check instead of a
severity-rank comparison.


5. Challenges & Strategic Roadmap

Primary Technical Hurdle: Distinguishing a genuine authorization
vulnerability from a legitimate public lookup endpoint, without using
machine learning. A naive "any endpoint with a numeric ID is BOLA-testable"
rule produces false positives on resources that have no ownership concept
at all (e.g. a public doctor directory).

Resolution: Introduced an ownership-scope classification step using
resource-name heuristics (patient, appointment, insurance, otp, debug,
prescription) to restrict active BOLA probing to endpoints where cross-user
access is a meaningful, checkable concern — verified by confirming the
doctor-directory and health-check endpoints correctly produce zero findings
after the fix, alongside re-confirming the three genuine BOLA vulnerabilities
still triggered correctly.

Next Steps (Phase 2):
- Attack-graph visualization showing relationships between discovered
  endpoints (shared auth patterns, resource clustering)
- Temporal drift detection: comparing two log snapshots over time to
  surface newly appeared shadow endpoints as an early-warning signal
- Extending the ownership-scope classifier beyond keyword matching toward
  a response-diffing approach (comparing responses across different user
  tokens) for more accurate detection on real-world APIs with unfamiliar
  naming conventions


Note: For installation instructions, the full CLI reference, and a guide to
interpreting the HTML report, see USER_MANUAL.md in the project repository.
A complete build log and all external references consulted are recorded in
research_log.md, per project documentation requirements.


6. External Validation via OWASP crAPI (In Progress)

Objective: 
To validate the Shadow API Scanner against a recognized, third-party vulnerable
application (OWASP Completely Ridiculous API) and prove the tool's efficacy and
BOLA detection logic on an external system, rather than just our custom mock server.

Current Status:
- The crAPI codebase (`crAPI-main`) has been integrated into the project workspace.
- The multi-container Docker Compose deployment was successfully configured and initiated.
- The crAPI microservices were successfully brought up, with the main web interface
  confirmed reachable on port 8888.

Next Steps (Validation Underway):
- Capture real user traffic traversing the crAPI application to generate a realistic
  `access.log` representing external traffic patterns.
- Run the scanner's passive log diffing and active BOLA probe against the live crAPI
  endpoints to confirm successful detection of its deliberately vulnerable authorization
  models.
