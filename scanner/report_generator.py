"""
scanner/report_generator.py
============================
Renders a fully self-contained, offline-capable HTML report from scored findings.

Sections
--------
1. Executive Summary   — total endpoints, shadow count, critical count, gateway score
2. Attack Surface Table — all endpoints, sortable/filterable by severity (vanilla JS)
3. Per-Endpoint Detail Cards — collapsible, showing OWASP categories, evidence,
                               remediation suggestions
4. Severity Bar Chart  — hand-rolled SVG bars, no charting library

Public API
----------
    generate_report(scored_endpoints, diff_result, spec_result, output_path) -> ReportMeta
    ReportMeta.highest_severity  : str   — \"CRITICAL\" | \"HIGH\" | ... | \"NONE\"
    ReportMeta.has_critical_or_high : bool  — for CLI exit-code gating
"""

from __future__ import annotations

import dataclasses
import json
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import List, Optional

from jinja2 import Environment, BaseLoader

try:
    from scanner.scorer import ScoredEndpoint
    from scanner.diff_engine import DiffResult
    from scanner.spec_loader import SpecResult
    from scanner.risk_engine import Finding
except ModuleNotFoundError:
    import sys, os
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
    from scanner.scorer import ScoredEndpoint
    from scanner.diff_engine import DiffResult
    from scanner.spec_loader import SpecResult
    from scanner.risk_engine import Finding
_REMEDIATION: dict[str, str] = {
    "API1:2023 Broken Object Level Authorization": (
        "Implement server-side object-level authorization checks on every request. "
        "Verify that the authenticated user owns or has explicit permission to access "
        "the requested resource ID. Never rely on the client to send only their own IDs."
    ),
    "API2:2023 Broken Authentication": (
        "Enforce authentication on all non-public endpoints. Use a centralized auth "
        "middleware or API gateway policy. Rotate and validate JWT/Bearer tokens; "
        "reject requests with missing, expired, or malformed credentials with HTTP 401."
    ),
    "API3:2023 Excessive Data Exposure": (
        "Apply a strict allow-list of fields returned per endpoint. Use API-level "
        "response filtering / DTO projection to ensure internal fields (Aadhaar, "
        "diagnosis, SSN) are never included unless the endpoint's stated purpose "
        "explicitly requires them."
    ),
    "API3:2023 Excessive Data Exposure / Sensitive Data": (
        "Review response payloads and ensure sensitive fields are not leaked. Apply "
        "field-level access controls and consider data masking for sensitive attributes "
        "(e.g. partial Aadhaar masking per DPDP Act guidance)."
    ),
    "API4:2023 Unrestricted Resource Consumption": (
        "Implement rate limiting at the API gateway or application layer. "
        "Return HTTP 429 with a Retry-After header when limits are exceeded. "
        "For OTP endpoints, additionally enforce lockout after N failed attempts "
        "and require CAPTCHA or device binding."
    ),
    "API9:2023 Improper Inventory Management": (
        "Maintain a complete, versioned API inventory. Decommission or document all "
        "shadow/legacy endpoints. Integrate spec-diff scanning into the CI/CD pipeline "
        "so undocumented endpoints are caught at deployment time, not in production."
    ),
}
_DPDP_MAP: dict[str, list[dict]] = {
    "API1:2023 Broken Object Level Authorization": [
        {
            "section": "Section 8(1)",
            "heading": "Obligations of Data Fiduciary — Reasonable Security Safeguards",
            "note": (
                "Unrestricted access to another data principal's record implicates the "
                "data fiduciary's obligation to implement 'reasonable security safeguards' "
                "to prevent unauthorised access to personal data."
            ),
        },
        {
            "section": "Section 8(7)",
            "heading": "Obligation to notify the Board of data security incidents",
            "note": (
                "If a finding of this type were exploited in a production environment, "
                "the resulting unauthorised access to personal data may be relevant to "
                "the notification obligations set out in this provision. "
                "A data protection professional should assess whether Section 8(7) "
                "reporting obligations apply."
            ),
        },
    ],
    "API2:2023 Broken Authentication": [
        {
            "section": "Section 8(1)",
            "heading": "Obligations of Data Fiduciary — Reasonable Security Safeguards",
            "note": (
                "Unauthenticated access to personal data endpoints is relevant to the "
                "fiduciary's duty to prevent unauthorised processing of personal data "
                "through appropriate technical access controls."
            ),
        },
    ],
    "API3:2023 Excessive Data Exposure": [
        {
            "section": "Section 6",
            "heading": "Limitation on purpose, collection, and storage of personal data",
            "note": (
                "Returning fields beyond what the endpoint's stated purpose requires "
                "(e.g. returning diagnosis and Aadhaar when only name/age were needed) "
                "may warrant review under the principle of data minimisation embedded "
                "in this section."
            ),
        },
        {
            "section": "Section 8(1)",
            "heading": "Obligations of Data Fiduciary — Reasonable Security Safeguards",
            "note": (
                "Over-exposure of sensitive health and identity fields in API responses "
                "implicates the fiduciary's obligation to limit unnecessary exposure of "
                "personal data held in processing systems."
            ),
        },
    ],
    "API3:2023 Excessive Data Exposure / Sensitive Data": [
        {
            "section": "Section 6",
            "heading": "Limitation on purpose, collection, and storage of personal data",
            "note": (
                "Exposure of Aadhaar numbers, diagnosis codes, and other sensitive health "
                "identifiers beyond the endpoint's declared purpose is relevant to the "
                "data minimisation principle under this section."
            ),
        },
        {
            "section": "Section 8(1)",
            "heading": "Obligations of Data Fiduciary — Reasonable Security Safeguards",
            "note": (
                "Health data and government ID numbers (Aadhaar) are among the most "
                "sensitive categories of personal data; their uncontrolled API exposure "
                "implicates the heightened safeguard expectations under this provision."
            ),
        },
    ],
    "API4:2023 Unrestricted Resource Consumption": [
        {
            "section": "Section 8(1)",
            "heading": "Obligations of Data Fiduciary — Reasonable Security Safeguards",
            "note": (
                "Absence of rate limiting on OTP and authentication endpoints may be "
                "relevant to the fiduciary's obligation to implement safeguards that "
                "prevent automated credential attacks against systems holding personal data."
            ),
        },
    ],
    "API9:2023 Improper Inventory Management": [
        {
            "section": "Section 8(1)",
            "heading": "Obligations of Data Fiduciary — Reasonable Security Safeguards",
            "note": (
                "Shadow and undocumented endpoints that process personal data without "
                "governance oversight are relevant to the fiduciary's obligation to "
                "maintain an accurate inventory of processing activities and ensure "
                "all data flows are subject to security controls."
            ),
        },
    ],
}

_SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "NONE"]
_SEVERITY_COLOR = {
    "CRITICAL": "#ef4444",
    "HIGH":     "#f97316",
    "MEDIUM":   "#eab308",
    "LOW":      "#3b82f6",
    "INFO":     "#6b7280",
    "NONE":     "#d1d5db",
}
@dataclass
class ReportMeta:
    output_path:          str
    highest_severity:     str    # "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO" | "NONE"
    has_critical_or_high: bool
    total_endpoints:      int
    shadow_count:         int
    critical_count:       int
    gateway_score:        int
_HTML_TEMPLATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{{ title }} — Shadow API Scan Report</title>
<meta name="description" content="Shadow API Discovery and Vulnerability Scan Report for {{ title }}. Generated {{ generated_at }}.">
<style>
/* ── Reset & Tokens ─────────────────────────────────────────────────── */
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
:root {
  --bg:        #0f1117;
  --bg2:       #1a1d27;
  --bg3:       #232736;
  --border:    #2e3348;
  --text:      #e2e8f0;
  --text-muted:#8892a4;
  --accent:    #6366f1;
  --accent2:   #818cf8;
  --crit:      #ef4444;
  --high:      #f97316;
  --med:       #eab308;
  --low:       #3b82f6;
  --info:      #6b7280;
  --green:     #22c55e;
  --radius:    10px;
  --shadow:    0 4px 24px rgba(0,0,0,.45);
  --font:      'Segoe UI', system-ui, -apple-system, sans-serif;
  --mono:      'Cascadia Code', 'Fira Code', 'Consolas', monospace;
}
html { scroll-behavior: smooth; }
body {
  font-family: var(--font);
  background: var(--bg);
  color: var(--text);
  line-height: 1.6;
  min-height: 100vh;
}

/* ── Layout ─────────────────────────────────────────────────────────── */
.page-wrap { max-width: 1280px; margin: 0 auto; padding: 0 24px 64px; }
.header {
  background: linear-gradient(135deg, #1e1b4b 0%, #312e81 50%, #1e1b4b 100%);
  border-bottom: 1px solid #4338ca44;
  padding: 36px 0 32px;
  margin-bottom: 40px;
}
.header-inner { max-width: 1280px; margin: 0 auto; padding: 0 24px; }
.header h1 {
  font-size: 2rem; font-weight: 700; letter-spacing: -0.5px;
  background: linear-gradient(135deg, #a5b4fc, #e0e7ff);
  -webkit-background-clip: text; -webkit-text-fill-color: transparent;
  background-clip: text;
}
.header .subtitle { color: #a5b4fc; margin-top: 6px; font-size: .95rem; }
.header .meta { color: #6366f180; font-size: .8rem; margin-top: 10px; }

/* ── Section headings ────────────────────────────────────────────────── */
.section { margin-bottom: 48px; }
.section-title {
  font-size: 1.25rem; font-weight: 600; color: var(--accent2);
  padding-bottom: 10px;
  border-bottom: 1px solid var(--border);
  margin-bottom: 20px;
  display: flex; align-items: center; gap: 10px;
}
.section-title .icon { font-size: 1.1rem; }

/* ── Stat Cards (Executive Summary) ─────────────────────────────────── */
.stat-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
  gap: 16px;
  margin-bottom: 32px;
}
.stat-card {
  background: var(--bg2);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  padding: 22px 24px;
  position: relative; overflow: hidden;
  transition: transform .2s, box-shadow .2s;
}
.stat-card:hover { transform: translateY(-2px); box-shadow: var(--shadow); }
.stat-card::before {
  content: ''; position: absolute; top: 0; left: 0; right: 0; height: 3px;
  background: var(--accent-line, var(--accent));
}
.stat-card .label { font-size: .78rem; color: var(--text-muted); text-transform: uppercase; letter-spacing: .08em; }
.stat-card .value { font-size: 2.4rem; font-weight: 700; line-height: 1.1; margin-top: 6px; }
.stat-card .sub   { font-size: .82rem; color: var(--text-muted); margin-top: 4px; }
.stat-critical { --accent-line: var(--crit); }
.stat-high     { --accent-line: var(--high); }
.stat-shadow   { --accent-line: #a855f7; }
.stat-score    { --accent-line: var(--accent); }
.stat-clean    { --accent-line: var(--green); }

/* ── Gateway score ring ─────────────────────────────────────────────── */
.score-ring {
  width: 100px; height: 100px; margin: 0 auto 24px;
  position: relative; display: flex; align-items: center; justify-content: center;
}
.score-ring svg { position: absolute; top: 0; left: 0; transform: rotate(-90deg); }
.score-ring .score-num {
  font-size: 1.7rem; font-weight: 700; line-height: 1;
  position: relative;
}
.score-ring .score-label { font-size: .65rem; color: var(--text-muted); }

/* ── Severity Badge ──────────────────────────────────────────────────── */
.badge {
  display: inline-block; padding: 2px 9px; border-radius: 20px;
  font-size: .72rem; font-weight: 700; letter-spacing: .06em; text-transform: uppercase;
}
.badge-CRITICAL { background: #ef444420; color: #ef4444; border: 1px solid #ef444440; }
.badge-HIGH     { background: #f9731620; color: #f97316; border: 1px solid #f9731640; }
.badge-MEDIUM   { background: #eab30820; color: #eab308; border: 1px solid #eab30840; }
.badge-LOW      { background: #3b82f620; color: #60a5fa; border: 1px solid #3b82f640; }
.badge-INFO     { background: #6b728020; color: #94a3b8; border: 1px solid #6b728040; }
.badge-NONE     { background: #1f293720; color: #6b7280; border: 1px solid #2e334840; }
.badge-SHADOW   { background: #a855f720; color: #c084fc; border: 1px solid #a855f740; }
.badge-OK       { background: #22c55e20; color: #22c55e; border: 1px solid #22c55e40; }

/* ── Attack Surface Table ────────────────────────────────────────────── */
.table-controls {
  display: flex; gap: 12px; flex-wrap: wrap; margin-bottom: 16px;
  align-items: center;
}
.search-box {
  flex: 1; min-width: 200px;
  background: var(--bg2); border: 1px solid var(--border);
  color: var(--text); padding: 8px 14px; border-radius: 8px;
  font-family: var(--font); font-size: .9rem; outline: none;
  transition: border-color .2s;
}
.search-box:focus { border-color: var(--accent); }
.filter-btn {
  padding: 7px 14px; border-radius: 8px; border: 1px solid var(--border);
  background: var(--bg2); color: var(--text-muted); cursor: pointer;
  font-size: .82rem; font-family: var(--font); transition: all .2s;
}
.filter-btn:hover { border-color: var(--accent); color: var(--accent2); }
.filter-btn.active { background: var(--accent); color: #fff; border-color: var(--accent); }

.data-table { width: 100%; border-collapse: collapse; }
.data-table th {
  background: var(--bg3); padding: 11px 14px;
  font-size: .78rem; text-transform: uppercase; letter-spacing: .08em;
  color: var(--text-muted); text-align: left; border-bottom: 1px solid var(--border);
  cursor: pointer; user-select: none; white-space: nowrap;
}
.data-table th:hover { color: var(--accent2); }
.data-table th .sort-arrow { margin-left: 4px; opacity: .4; }
.data-table th.sort-asc .sort-arrow::after  { content: ' ▲'; opacity: 1; color: var(--accent2); }
.data-table th.sort-desc .sort-arrow::after { content: ' ▼'; opacity: 1; color: var(--accent2); }
.data-table td {
  padding: 11px 14px; border-bottom: 1px solid var(--border);
  font-size: .88rem; vertical-align: middle;
}
.data-table tr { transition: background .15s; }
.data-table tr:hover td { background: #ffffff06; }
.data-table tr.hidden { display: none; }
.data-table .path-cell {
  font-family: var(--mono); font-size: .82rem; color: var(--accent2);
  max-width: 320px; word-break: break-all;
}
.data-table .method-pill {
  display: inline-block; padding: 1px 7px; border-radius: 4px;
  font-family: var(--mono); font-size: .72rem; font-weight: 700; margin-right: 3px;
  background: #6366f120; color: #818cf8; border: 1px solid #6366f130;
}
.method-DELETE { background: #ef444415; color: #f87171; border-color: #ef444430; }
.method-POST   { background: #22c55e15; color: #4ade80; border-color: #22c55e30; }
.method-GET    { background: #3b82f615; color: #60a5fa; border-color: #3b82f630; }

/* ── Detail Cards ────────────────────────────────────────────────────── */
.endpoint-card {
  background: var(--bg2);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  margin-bottom: 16px;
  overflow: hidden;
  transition: border-color .2s;
}
.endpoint-card:hover { border-color: #4338ca60; }
.endpoint-card.severity-CRITICAL { border-left: 4px solid var(--crit); }
.endpoint-card.severity-HIGH     { border-left: 4px solid var(--high); }
.endpoint-card.severity-MEDIUM   { border-left: 4px solid var(--med); }
.endpoint-card.severity-LOW      { border-left: 4px solid var(--low); }
.endpoint-card.severity-NONE     { border-left: 4px solid var(--border); }

.card-header {
  display: flex; align-items: center; gap: 12px;
  padding: 16px 20px; cursor: pointer;
  transition: background .15s;
}
.card-header:hover { background: #ffffff04; }
.card-path {
  font-family: var(--mono); font-size: .9rem; color: var(--accent2);
  font-weight: 600; flex: 1; word-break: break-all;
}
.card-score {
  font-size: 1.1rem; font-weight: 700;
  min-width: 60px; text-align: right;
}
.score-CRITICAL { color: var(--crit); }
.score-HIGH     { color: var(--high); }
.score-MEDIUM   { color: var(--med); }
.score-LOW      { color: var(--low); }
.score-NONE     { color: var(--text-muted); }
.card-chevron   { color: var(--text-muted); transition: transform .25s; font-size: 1rem; }
.card-header.open .card-chevron { transform: rotate(180deg); }

.card-body { display: none; padding: 0 20px 20px; }
.card-body.open { display: block; }

.card-meta {
  display: flex; flex-wrap: wrap; gap: 10px;
  padding: 12px 0; border-bottom: 1px solid var(--border);
  margin-bottom: 16px; font-size: .83rem;
}
.meta-item { display: flex; align-items: center; gap: 5px; color: var(--text-muted); }
.meta-item strong { color: var(--text); }

/* ── Finding row inside card ─────────────────────────────────────────── */
.finding {
  background: var(--bg3);
  border: 1px solid var(--border);
  border-radius: 8px;
  margin-bottom: 10px;
  overflow: hidden;
}
.finding-header {
  display: flex; align-items: flex-start; gap: 10px;
  padding: 12px 14px;
}
.finding-title { font-weight: 600; font-size: .9rem; }
.finding-category { font-size: .78rem; color: var(--text-muted); margin-top: 2px; font-family: var(--mono); }
.finding-desc { padding: 0 14px 10px; font-size: .85rem; color: var(--text-muted); }
.finding-remediation {
  background: #6366f108;
  border-top: 1px solid var(--border);
  padding: 10px 14px;
  font-size: .82rem;
  color: #a5b4fc;
}
.finding-remediation::before { content: '💡 Remediation: '; font-weight: 600; }

/* DPDP Act overlay callout */
.finding-dpdp {
  background: #0d2d2d;
  border-top: 1px solid #134e4a40;
  padding: 10px 14px;
}
.dpdp-header {
  font-size: .72rem; font-weight: 700; letter-spacing: .07em;
  text-transform: uppercase; color: #2dd4bf; margin-bottom: 6px;
  display: flex; align-items: center; gap: 6px;
}
.dpdp-item {
  margin-bottom: 6px;
  font-size: .8rem;
}
.dpdp-item:last-child { margin-bottom: 0; }
.dpdp-section {
  display: inline-block;
  background: #134e4a40; color: #5eead4;
  border: 1px solid #0d9488; border-radius: 4px;
  padding: 1px 7px; font-size: .72rem; font-weight: 700;
  font-family: var(--mono); margin-right: 6px; white-space: nowrap;
}
.dpdp-heading { color: #99f6e4; font-weight: 600; }
.dpdp-note { color: #5eead4; margin-top: 2px; font-size: .78rem; opacity: .85; }
.dpdp-disclaimer {
  font-size: .7rem; color: #0f766e; margin-top: 8px; font-style: italic;
}

/* ── Probe Warning Banner ─────────────────────────────────────────────── */
.probe-warning {
  background: #fffbeb;
  border-left: 4px solid #f59e0b;
  color: #92400e;
  padding: 14px 18px;
  margin: 0 auto 24px auto;
  border-radius: 4px;
  font-size: 0.95rem;
  display: flex;
  align-items: flex-start;
  gap: 12px;
  box-shadow: 0 1px 3px rgba(0,0,0,0.1);
}
.probe-warning strong {
  display: block;
  font-size: 1.05rem;
  margin-bottom: 4px;
  color: #b45309;
}


/* ── Evidence block (BOLA proof) ──────────────────────────────────────── */
.evidence-block {
  background: #0d1117;
  border: 1px solid #30363d;
  border-radius: 6px;
  margin: 10px 14px;
  overflow: hidden;
}
.evidence-block .ev-header {
  background: #161b22;
  padding: 6px 12px;
  font-size: .72rem;
  color: #7d8590;
  font-family: var(--mono);
  border-bottom: 1px solid #30363d;
  letter-spacing: .06em; text-transform: uppercase;
}
.evidence-block pre {
  padding: 12px;
  font-family: var(--mono);
  font-size: .78rem;
  color: #e6edf3;
  white-space: pre-wrap;
  word-break: break-all;
  overflow-x: auto;
  max-height: 240px;
  overflow-y: auto;
}
.ev-url   { color: #58a6ff; }
.ev-key   { color: #7ee787; }
.ev-val   { color: #f78166; }
.ev-label { color: #d2a8ff; }

/* ── SVG Chart ──────────────────────────────────────────────────────── */
.chart-wrap { background: var(--bg2); border: 1px solid var(--border); border-radius: var(--radius); padding: 24px; }
.chart-title { font-size: .85rem; color: var(--text-muted); margin-bottom: 18px; text-transform: uppercase; letter-spacing: .08em; }
.bar-row { display: flex; align-items: center; gap: 12px; margin-bottom: 14px; }
.bar-label { width: 80px; font-size: .8rem; text-align: right; color: var(--text-muted); }
.bar-track { flex: 1; background: var(--bg3); border-radius: 6px; overflow: hidden; height: 28px; position: relative; }
.bar-fill {
  height: 100%; border-radius: 6px;
  transition: width 1s cubic-bezier(.4,0,.2,1);
  display: flex; align-items: center; justify-content: flex-end; padding-right: 8px;
}
.bar-count { font-size: .78rem; font-weight: 700; color: rgba(255,255,255,.85); }
.bar-zero  { height: 100%; display: flex; align-items: center; padding-left: 10px; font-size: .78rem; color: var(--text-muted); }

/* ── OWASP tag cloud ─────────────────────────────────────────────────── */
.owasp-grid { display: flex; flex-wrap: wrap; gap: 8px; }
.owasp-tag {
  background: var(--bg3); border: 1px solid var(--border);
  border-radius: 6px; padding: 5px 12px; font-size: .78rem; color: var(--text-muted);
}
.owasp-tag strong { color: var(--accent2); }

/* ── Dormant table ───────────────────────────────────────────────────── */
.dormant-table { font-size: .85rem; }
.dormant-empty { color: var(--green); font-style: italic; }

/* ── Footer ─────────────────────────────────────────────────────────── */
.report-footer {
  border-top: 1px solid var(--border); padding-top: 24px;
  color: var(--text-muted); font-size: .8rem; display: flex;
  justify-content: space-between; flex-wrap: wrap; gap: 8px;
}

/* ── Animations ─────────────────────────────────────────────────────── */
@keyframes fadeInUp {
  from { opacity:0; transform: translateY(12px); }
  to   { opacity:1; transform: translateY(0); }
}
.section { animation: fadeInUp .35s ease both; }
.section:nth-child(2) { animation-delay: .07s; }
.section:nth-child(3) { animation-delay: .14s; }
.section:nth-child(4) { animation-delay: .21s; }
.section:nth-child(5) { animation-delay: .28s; }
</style>
</head>
<body>

<div class="header">
  <div class="header-inner">
    <h1>🛡️ Shadow API Discovery &amp; Vulnerability Report</h1>
    <div class="subtitle">{{ title }} — API Gateway Security Audit</div>
    <div class="meta">Generated {{ generated_at }} · Scanner v1.0 · HCIC-SI2026 Project 15</div>
  </div>
</div>

<div class="page-wrap">

{% if probe_warning %}
<div class="probe-warning">
  <span style="font-size:1.4rem">⚠</span>
  <div>
    <strong>Active Probes Skipped</strong>
    <div style="opacity: 0.95">{{ probe_warning }}</div>
  </div>
</div>
{% endif %}

<!-- ══════════════════════════════════════════════════════ -->
<!-- 1. EXECUTIVE SUMMARY                                   -->
<!-- ══════════════════════════════════════════════════════ -->
<div class="section" id="summary">
  <div class="section-title"> Executive Summary</div>

  <div class="stat-grid">
    <div class="stat-card stat-score">
      <div class="label">Overall Risk Exposure <span style="font-size:.7rem;color:var(--text-muted);font-weight:400">(higher = worse)</span></div>
      <div class="value" style="color:{{ gateway_color }}">{{ gateway_score }}<span style="font-size:1.2rem;color:var(--text-muted)">/100</span></div>
      <div class="sub" style="display:flex;align-items:center;gap:6px;margin-top:6px">
        <span class="badge badge-{{ highest_severity }}">{{ highest_severity }}</span>
        <span>{{ gateway_method }} of endpoint scores</span>
      </div>
    </div>
    <div class="stat-card stat-shadow">
      <div class="label">Shadow Endpoints</div>
      <div class="value" style="color:#c084fc">{{ shadow_count }}</div>
      <div class="sub">of {{ total_endpoints }} total discovered</div>
    </div>
    <div class="stat-card stat-critical">
      <div class="label">Critical Findings</div>
      <div class="value" style="color:var(--crit)">{{ critical_count }}</div>
      <div class="sub">{{ high_count }} high, {{ medium_count }} medium</div>
    </div>
    <div class="stat-card">
      <div class="label">Total Findings</div>
      <div class="value">{{ total_findings }}</div>
      <div class="sub">across {{ endpoints_with_findings }} endpoints</div>
    </div>
    <div class="stat-card stat-clean">
      <div class="label">Documented Endpoints</div>
      <div class="value" style="color:var(--green)">{{ documented_count }}</div>
      <div class="sub">{{ dormant_count }} dormant (no traffic)</div>
    </div>
  </div>

  <!-- Severity bar chart -->
  <div class="chart-wrap">
    <div class="chart-title">Findings by Severity</div>
    {% set max_count = [sev_counts.CRITICAL, sev_counts.HIGH, sev_counts.MEDIUM, sev_counts.LOW, sev_counts.INFO] | max %}
    {% for sev, color in [('CRITICAL','#ef4444'),('HIGH','#f97316'),('MEDIUM','#eab308'),('LOW','#3b82f6'),('INFO','#6b7280')] %}
    {% set cnt = sev_counts[sev] %}
    <div class="bar-row">
      <div class="bar-label">{{ sev }}</div>
      <div class="bar-track">
        {% if cnt > 0 %}
        <div class="bar-fill" style="width:{{ ((cnt / max_count) * 100)|int if max_count > 0 else 0 }}%; background:{{ color }}20; border: 1px solid {{ color }}40;">
          <span class="bar-count" style="color:{{ color }}">{{ cnt }}</span>
        </div>
        {% else %}
        <div class="bar-zero">0</div>
        {% endif %}
      </div>
    </div>
    {% endfor %}
  </div>

  <!-- OWASP categories hit -->
  {% if owasp_categories %}
  <div style="margin-top:20px">
    <div style="font-size:.82rem;color:var(--text-muted);margin-bottom:10px;text-transform:uppercase;letter-spacing:.06em">OWASP API Top 10 Categories Detected</div>
    <div class="owasp-grid">
      {% for cat, cnt in owasp_categories %}
      <div class="owasp-tag"><strong>{{ cat }}</strong> &nbsp;·&nbsp; {{ cnt }} finding{{ 's' if cnt != 1 }}</div>
      {% endfor %}
    </div>
  </div>
  {% endif %}
</div>

<!-- ══════════════════════════════════════════════════════ -->
<!-- 2. ATTACK SURFACE TABLE                                -->
<!-- ══════════════════════════════════════════════════════ -->
<div class="section" id="attack-surface">
  <div class="section-title"> Attack Surface Overview</div>

  <div class="table-controls">
    <input class="search-box" id="ep-search" type="text" placeholder="Filter endpoints…" oninput="filterTable()">
    <button class="filter-btn active" data-sev="ALL"      onclick="setSevFilter(this,'ALL')">All</button>
    <button class="filter-btn" data-sev="CRITICAL" onclick="setSevFilter(this,'CRITICAL')">Critical</button>
    <button class="filter-btn" data-sev="HIGH"     onclick="setSevFilter(this,'HIGH')">High</button>
    <button class="filter-btn" data-sev="MEDIUM"   onclick="setSevFilter(this,'MEDIUM')">Medium</button>
    <button class="filter-btn" data-sev="LOW"      onclick="setSevFilter(this,'LOW')">Low</button>
    <button class="filter-btn" data-sev="NONE"     onclick="setSevFilter(this,'NONE')">Clean</button>
  </div>

  <div style="overflow-x:auto">
  <table class="data-table" id="ep-table">
    <thead>
      <tr>
        <th onclick="sortTable(0)" class="sort-desc">Endpoint <span class="sort-arrow"></span></th>
        <th onclick="sortTable(1)">Status <span class="sort-arrow"></span></th>
        <th onclick="sortTable(2)">Methods <span class="sort-arrow"></span></th>
        <th onclick="sortTable(3)">Hits <span class="sort-arrow"></span></th>
        <th onclick="sortTable(4)">Risk Level <span class="sort-arrow"></span></th>
        <th onclick="sortTable(5)">Score <span class="sort-arrow"></span></th>
        <th onclick="sortTable(6)"># Findings <span class="sort-arrow"></span></th>
      </tr>
    </thead>
    <tbody id="ep-tbody">
      {% for se in scored_endpoints %}
      <tr data-sev="{{ se.risk_level }}" data-path="{{ se.path_template }}">
        <td class="path-cell">
          <a href="#card-{{ loop.index }}" style="text-decoration:none;color:inherit">{{ se.path_template }}</a>
        </td>
        <td>
          {% if se.path_template in shadow_paths %}
            <span class="badge badge-SHADOW">Shadow</span>
          {% elif se.path_template in dormant_paths %}
            <span class="badge badge-INFO">Dormant</span>
          {% else %}
            <span class="badge badge-OK">Documented</span>
          {% endif %}
        </td>
        <td>
          {% for m in se.methods | sort %}
          <span class="method-pill method-{{ m }}">{{ m }}</span>
          {% endfor %}
        </td>
        <td>{{ se.hit_count }}</td>
        <td><span class="badge badge-{{ se.risk_level }}">{{ se.risk_level }}</span></td>
        <td><strong class="score-{{ se.risk_level }}">{{ se.score }}</strong><span class="badge badge-{{ se.risk_level }}" style="margin-left:5px;font-size:.65rem">{{ se.risk_level }}</span></td>
        <td>{{ se.findings | length }}</td>
      </tr>
      {% endfor %}
    </tbody>
  </table>
  </div>
  <div id="no-results" style="display:none;text-align:center;padding:32px;color:var(--text-muted)">No endpoints match the current filter.</div>
</div>

<!-- ══════════════════════════════════════════════════════ -->
<!-- 3. PER-ENDPOINT DETAIL CARDS                           -->
<!-- ══════════════════════════════════════════════════════ -->
<div class="section" id="details">
  <div class="section-title"> Endpoint Detail</div>

  {% for se in scored_endpoints %}
  <div class="endpoint-card severity-{{ se.risk_level }}" id="card-{{ loop.index }}">
    <div class="card-header" onclick="toggleCard(this)">
      <span class="badge badge-{{ se.risk_level }}">{{ se.risk_level }}</span>
      <span class="card-path">{{ se.path_template }}</span>
      {% if se.path_template in shadow_paths %}
        <span class="badge badge-SHADOW" style="margin-left:4px">Shadow</span>
      {% endif %}
      <span class="card-score score-{{ se.risk_level }}">{{ se.score }}/100 <span class="badge badge-{{ se.risk_level }}" style="font-size:.7rem;vertical-align:middle">{{ se.risk_level }}</span></span>
      <span class="card-chevron">▼</span>
    </div>
    <div class="card-body {{ 'open' if se.risk_level in ['CRITICAL','HIGH'] else '' }}">
      <div class="card-meta">
        <div class="meta-item"><strong>Hits:</strong> {{ se.hit_count }}</div>
        <div class="meta-item"><strong>Methods:</strong>
          {% for m in se.methods | sort %}<span class="method-pill method-{{ m }}">{{ m }}</span>{% endfor %}
        </div>
        <div class="meta-item"><strong>Auth:</strong> {{ se.auth_coverage }}</div>
        <div class="meta-item"><strong>Raw score:</strong> {{ se.raw_score }} → capped at {{ se.score }}</div>
        {% if se.sample_paths %}
        <div class="meta-item" style="width:100%"><strong>Sample paths:</strong>
          {% for sp in se.sample_paths %}<code style="font-size:.78rem;color:var(--text-muted);margin-left:6px">{{ sp }}</code>{% endfor %}
        </div>
        {% endif %}
      </div>

      {% if se.findings %}
      {% for f in se.findings %}
      <div class="finding">
        <div class="finding-header">
          <span class="badge badge-{{ f.severity }}">{{ f.severity }}</span>
          <div>
            <div class="finding-title">{{ f.title }}</div>
            <div class="finding-category">{{ f.category }}</div>
          </div>
        </div>
        <div class="finding-desc">{{ f.description }}</div>

        {% if f.evidence %}
        <div class="evidence-block">
          <div class="ev-header">Active Probe Evidence</div>
          <pre>{% if f.evidence.url %}<span class="ev-label">URL:    </span><span class="ev-url">{{ f.evidence.url }}</span>
{% endif %}{% if f.evidence.status %}<span class="ev-label">Status: </span><span class="ev-key">{{ f.evidence.status }} OK</span> — unauthorized access confirmed
{% endif %}{% if f.evidence.burst_ip %}<span class="ev-label">Source IP:       </span><span class="ev-url">{{ f.evidence.burst_ip }}</span>
<span class="ev-label">Requests seen:   </span><span class="ev-val">{{ f.evidence.requests_observed }}</span>
<span class="ev-label">Pattern:         </span><span class="ev-key">{{ f.evidence.type }}</span>
{% endif %}{% if f.evidence.keys_found %}<span class="ev-label">PII fields found: </span><span class="ev-val">{{ f.evidence.keys_found | join(', ') }}</span>
{% endif %}{% if f.evidence.response_sample %}<span class="ev-label">Response sample: </span>{{ f.evidence.response_sample }}{% endif %}</pre>
        </div>
        {% endif %}

        {% set remediation = remediation_map.get(f.category) %}
        {% if remediation %}
        <div class="finding-remediation">{{ remediation }}</div>
        {% endif %}

        {% set dpdp_refs = dpdp_map.get(f.category) %}
        {% if dpdp_refs %}
        <div class="finding-dpdp">
          <div class="dpdp-header">DPDP Act 2023 — Provisions to Review</div>
          {% for ref in dpdp_refs %}
          <div class="dpdp-item">
            <span class="dpdp-section">{{ ref.section }}</span><span class="dpdp-heading">{{ ref.heading }}</span>
            <div class="dpdp-note">{{ ref.note }}</div>
          </div>
          {% endfor %}
          <div class="dpdp-disclaimer">⚠ This is a technical finding only. References to DPDP Act provisions are indicative — they highlight sections a reader may wish to review, not determinations of legal non-compliance. Consult a qualified legal or data protection professional for compliance assessment.</div>
        </div>
        {% endif %}
      </div>
      {% endfor %}
      {% else %}
      <div style="color:var(--text-muted);font-style:italic;font-size:.88rem;padding:8px 0">
        No risk findings for this endpoint.
      </div>
      {% endif %}
    </div>
  </div>
  {% endfor %}
</div>

<!-- ══════════════════════════════════════════════════════ -->
<!-- 4. DORMANT ENDPOINTS                                   -->
<!-- ══════════════════════════════════════════════════════ -->
{% if dormant_endpoints %}
<div class="section" id="dormant">
  <div class="section-title"></span> Dormant Documented Endpoints</div>
  <p style="font-size:.85rem;color:var(--text-muted);margin-bottom:16px">
    These endpoints are declared in the OpenAPI spec but received zero traffic
    during the log window. They represent undiscovered or unused attack surface.
  </p>
  <table class="data-table dormant-table">
    <thead><tr><th>Path Template</th><th>Methods</th><th>Security</th></tr></thead>
    <tbody>
    {% for d in dormant_endpoints %}
    <tr>
      <td class="path-cell">{{ d.path_template }}</td>
      <td>{% for m in d.methods %}<span class="method-pill method-{{ m }}">{{ m }}</span>{% endfor %}</td>
      <td><span class="badge badge-INFO">{{ d.security }}</span></td>
    </tr>
    {% endfor %}
    </tbody>
  </table>
</div>
{% else %}
<div class="section" id="dormant">
  <div class="section-title"></span> Dormant Endpoints</div>
  <div class="dormant-empty"> All documented endpoints received traffic — no dormant/zombie APIs detected.</div>
</div>
{% endif %}

<!-- Footer -->
<div class="report-footer">
  <div>Shadow API Discovery &amp; Vulnerability Scanner · HCIC-SI2026 · Project 15</div>
  <div>{{ generated_at }} · All checks are rule-based, no ML/NLP · OWASP API Security Top 10 (2023)</div>
</div>

</div><!-- /page-wrap -->

<!-- ══════════════════════════════════════════════════════ -->
<!-- Vanilla JS: sort, filter, toggle                       -->
<!-- ══════════════════════════════════════════════════════ -->
<script>
// ── Card toggle ──────────────────────────────────────────
function toggleCard(hdr) {
  hdr.classList.toggle('open');
  hdr.nextElementSibling.classList.toggle('open');
}

// ── Severity filter state ─────────────────────────────────
var activeSev = 'ALL';
function setSevFilter(btn, sev) {
  document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  activeSev = sev;
  filterTable();
}

// ── Combined search + severity filter ────────────────────
function filterTable() {
  var query = document.getElementById('ep-search').value.toLowerCase();
  var rows  = document.querySelectorAll('#ep-tbody tr');
  var shown = 0;
  rows.forEach(function(row) {
    var path = row.dataset.path.toLowerCase();
    var sev  = row.dataset.sev;
    var matchSev  = (activeSev === 'ALL' || sev === activeSev);
    var matchText = (!query || path.includes(query));
    if (matchSev && matchText) { row.classList.remove('hidden'); shown++; }
    else                        { row.classList.add('hidden'); }
  });
  document.getElementById('no-results').style.display = (shown === 0) ? 'block' : 'none';
}

// ── Table sort ───────────────────────────────────────────
var sortCol = 5, sortDir = -1; // default: score desc
function sortTable(col) {
  if (sortCol === col) { sortDir *= -1; }
  else { sortCol = col; sortDir = (col === 0) ? 1 : -1; }
  var ths = document.querySelectorAll('.data-table th');
  ths.forEach(function(th, i) {
    th.classList.remove('sort-asc','sort-desc');
    if (i === col) th.classList.add(sortDir === 1 ? 'sort-asc' : 'sort-desc');
  });
  var tbody = document.getElementById('ep-tbody');
  var rows  = Array.from(tbody.querySelectorAll('tr'));
  var sevOrd = {CRITICAL:0,HIGH:1,MEDIUM:2,LOW:3,INFO:4,NONE:5};
  rows.sort(function(a, b) {
    var av = a.cells[col].textContent.trim();
    var bv = b.cells[col].textContent.trim();
    if (col === 4) { // Risk level
      return sortDir * ((sevOrd[av] || 99) - (sevOrd[bv] || 99));
    }
    var an = parseFloat(av), bn = parseFloat(bv);
    if (!isNaN(an) && !isNaN(bn)) return sortDir * (an - bn);
    return sortDir * av.localeCompare(bv);
  });
  rows.forEach(function(r) { tbody.appendChild(r); });
}

// ── Auto-animate bars on load ─────────────────────────────
document.addEventListener('DOMContentLoaded', function() {
  document.querySelectorAll('.bar-fill').forEach(function(bar) {
    var w = bar.style.width;
    bar.style.width = '0';
    setTimeout(function() { bar.style.width = w; }, 100);
  });
  sortTable(5); // sort by score desc on load
});
</script>
</body>
</html>
"""
def _gateway_score(scored: List[ScoredEndpoint]) -> tuple[int, str]:
    """Returns (score, method_description)."""
    if not scored:
        return 0, "max"
    return max(se.score for se in scored), "max"


def _highest_severity(scored: List[ScoredEndpoint]) -> str:
    for sev in _SEVERITY_ORDER:
        for se in scored:
            if se.risk_level == sev and sev != "NONE":
                return sev
    return "NONE"


def _count_by_severity(scored: List[ScoredEndpoint]) -> dict[str, int]:
    counts: dict[str, int] = {s: 0 for s in _SEVERITY_ORDER}
    for se in scored:
        for f in se.findings:
            s = f.severity.upper()
            if s in counts:
                counts[s] += 1
    return counts


def _owasp_categories(scored: List[ScoredEndpoint]) -> list[tuple[str, int]]:
    from collections import Counter
    cat_counter: Counter = Counter()
    for se in scored:
        for f in se.findings:
            cat_counter[f.category] += 1
    return sorted(cat_counter.items(), key=lambda x: -x[1])
def _build_context(
    scored: List[ScoredEndpoint],
    diff_result: DiffResult,
    spec_result: SpecResult,
) -> dict:
    shadow_paths  = {s.path_template for s in diff_result.shadow}
    dormant_paths = {d.path_template for d in diff_result.dormant}

    gateway_score, gateway_method = _gateway_score(scored)
    gateway_color = _SEVERITY_COLOR.get(
        "CRITICAL" if gateway_score >= 75
        else "HIGH" if gateway_score >= 50
        else "MEDIUM" if gateway_score >= 25
        else "LOW", "#6b7280"
    )

    sev_counts = _count_by_severity(scored)
    critical_count = sev_counts["CRITICAL"]
    high_count     = sev_counts["HIGH"]
    medium_count   = sev_counts["MEDIUM"]
    total_findings = sum(sev_counts.values())

    endpoints_with_findings = sum(1 for se in scored if se.findings)
    highest_sev = _highest_severity(scored)
    log_by_tmpl = {}
    for ok in diff_result.ok:
        log_by_tmpl[ok.path_template] = ok.log_record
    for sh in diff_result.shadow:
        log_by_tmpl[sh.path_template] = sh.log_record
    for fz in diff_result.fuzzy_reconciled:
        log_by_tmpl[fz.discovered_template] = fz.log_record

    enriched = []
    for se in scored:
        lr = log_by_tmpl.get(se.path_template)
        enriched.append({
            "path_template": se.path_template,
            "risk_level":    se.risk_level,
            "score":         se.score,
            "raw_score":     se.raw_score,
            "findings":      se.findings,
            "hit_count":     lr.hit_count if lr else 0,
            "methods":       sorted(lr.methods_seen) if lr else [],
            "auth_coverage": lr.auth_coverage if lr else "unknown",
            "sample_paths":  (lr.sample_raw_paths[:3] if lr else []),
        })

    dormant_display = []
    for d in diff_result.dormant:
        dormant_display.append({
            "path_template": d.path_template,
            "methods":       sorted(d.spec_endpoint.declared_methods),
            "security":      d.spec_endpoint.security_label,
        })

    return {
        "title":                 spec_result.title or "SwasthyaConnect API",
        "generated_at":          datetime.now().strftime("%Y-%m-%d %H:%M:%S IST"),
        "gateway_score":         gateway_score,
        "gateway_color":         gateway_color,
        "gateway_method":        gateway_method,
        "shadow_count":          len(diff_result.shadow),
        "total_endpoints":       diff_result.total_discovered,
        "documented_count":      diff_result.total_documented,
        "dormant_count":         len(diff_result.dormant),
        "critical_count":        critical_count,
        "high_count":            high_count,
        "medium_count":          medium_count,
        "total_findings":        total_findings,
        "endpoints_with_findings": endpoints_with_findings,
        "sev_counts":            sev_counts,
        "owasp_categories":      _owasp_categories(scored),
        "scored_endpoints":      enriched,
        "shadow_paths":          shadow_paths,
        "dormant_paths":         dormant_paths,
        "dormant_endpoints":     dormant_display,
        "remediation_map":       _REMEDIATION,
        "dpdp_map":               _DPDP_MAP,
        "highest_severity":      highest_sev,
    }
def generate_report(
    scored_endpoints: List[ScoredEndpoint],
    diff_result: DiffResult,
    spec_result: SpecResult,
    output_path: str | Path = "report.html",
    probe_status: object = None,   # Optional[ProbeStatus] — avoids circular import
) -> ReportMeta:
    """
    Render the HTML report and write it to output_path.

    Parameters
    ----------
    probe_status
        ProbeStatus from risk_engine.probe_server_health().  When
        reachable=False the report will render a prominent warning banner
        above the executive summary so readers know findings are passive-only.
        Pass None or omit for backwards compatibility.

    Returns a ReportMeta with highest_severity and has_critical_or_high
    for use by cli.py's exit-code logic.
    """
    output_path = Path(output_path)
    probe_warning: str = ""
    if probe_status is not None and not getattr(probe_status, 'reachable', True):
        probe_warning = getattr(probe_status, 'summary_line',
            'Active BOLA probes were skipped — mock server was unreachable. '
            'Findings shown are passive-only and may under-report CRITICAL severity.'
        )

    ctx = _build_context(scored_endpoints, diff_result, spec_result)
    ctx["probe_warning"] = probe_warning

    env = Environment(loader=BaseLoader(), autoescape=False)
    template = env.from_string(_HTML_TEMPLATE)
    html = template.render(**ctx)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(html, encoding="utf-8")

    highest = ctx["highest_severity"]

    return ReportMeta(
        output_path          = str(output_path.resolve()),
        highest_severity     = highest,
        has_critical_or_high = highest in ("CRITICAL", "HIGH"),
        total_endpoints      = ctx["total_endpoints"],
        shadow_count         = ctx["shadow_count"],
        critical_count       = ctx["critical_count"],
        gateway_score        = ctx["gateway_score"],
    )
if __name__ == "__main__":
    import argparse as ap
    from scanner.log_parser   import parse_logs
    from scanner.spec_loader  import load_spec
    from scanner.diff_engine  import diff
    from scanner.risk_engine  import run_risk_engine
    from scanner.scorer       import score_endpoints

    cli = ap.ArgumentParser(description="Generate Shadow API HTML report")
    cli.add_argument("--log",     default="mock_env/access.log")
    cli.add_argument("--headers", default="mock_env/access_headers.log")
    cli.add_argument("--spec",    default="mock_env/openapi_spec.yaml")
    cli.add_argument("--url",     default="http://localhost:8000")
    cli.add_argument("--output",  default="report.html")
    args = cli.parse_args()

    print("📂 Parsing logs…")
    log_res  = parse_logs(args.log, args.headers)
    spec_res = load_spec(args.spec)

    print("🔍 Running diff engine…")
    diff_res = diff(log_res, spec_res)

    print("⚙️  Running risk engine (requires mock server at", args.url, ")…")
    risk_res = run_risk_engine(diff_res, spec_res, args.url)

    print("📊 Scoring…")
    scored = score_endpoints(risk_res)

    print(f"📝 Rendering report → {args.output}")
    meta = generate_report(scored, diff_res, spec_res, args.output)

    print(f"\n✅ Report written: {meta.output_path}")
    print(f"   Gateway score   : {meta.gateway_score}/100")
    print(f"   Highest severity: {meta.highest_severity}")
    print(f"   Shadow endpoints: {meta.shadow_count}")
    print(f"   Critical findings: {meta.critical_count}")
    print(f"   CI exit non-zero: {meta.has_critical_or_high}")
