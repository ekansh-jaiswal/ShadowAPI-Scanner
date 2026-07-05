#!/usr/bin/env python3
"""
mock_env/generate_logs.py
=========================
Synthetic log generator for the SwasthyaConnect Shadow API Scanner demo.

Makes real HTTP requests against the live mock server and records every request
in two log files:

  mock_env/access.log
      Standard Nginx "combined" log format — one line per request.
      Format: $remote_addr - - [$time_local] "$request" $status $body_bytes_sent
              "$http_referer" "$http_user_agent"

  mock_env/access_headers.log
      Companion JSONL file — one JSON object per request — capturing the
      Authorization header value and whether it was present.  Standard Nginx
      combined format does not include request headers, so in a real deployment
      this data would come from an enhanced Nginx log format that includes
      $http_authorization, or from an APM/WAF log (e.g. Datadog APM, AWS WAF
      full request logging, or a reverse-proxy sidecar).  We simulate it as a
      paired JSONL file for this project so the risk engine can perform
      auth-presence heuristics without losing that information.

Traffic simulation covers a fake 24-hour window (2026-07-04 00:00 → 23:59 +0530):
  • Steady documented-endpoint traffic  (~normal business hours, proper auth)
  • Low-frequency legacy shadow traffic  (old internal dashboard, off-hours)
  • Deliberate burst to /insurance-claims from one rogue IP
  • Deliberate OTP brute-force sequence (~50 requests, incrementing guesses)

Usage:
  python mock_env/generate_logs.py [--server-url URL] [--out-dir DIR] [--seed N]

The mock server must already be running before calling this script.
"""

import argparse
import datetime
import json
import os
import random
import sys
import time
from dataclasses import dataclass, field
from typing import Optional

import requests

# ─────────────────────────────────────────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────────────────────────────────────────

# Fake day base (IST)
BASE_DAY = datetime.datetime(2026, 7, 4, 0, 0, 0)
DAY_SECONDS = 86400

# Tokens accepted by the mock server
PATIENT_TOKENS = {
    101: "token-patient-101",
    102: "token-patient-102",
    103: "token-patient-103",
    104: "token-patient-104",
    105: "token-patient-105",
}
DOCTOR_TOKEN = "token-doctor-1"
ADMIN_TOKEN  = "token-admin-99"

# Patient IDs in the DB
PATIENT_IDS = list(range(101, 116))   # 101-115

# User agents – vary by traffic type
UA_WEBAPP   = "SwasthyaConnect-WebApp/2.1 (Mozilla/5.0)"
UA_MOBILE   = "SwasthyaConnect-Mobile/3.4 (Android 14)"
UA_LEGACY   = "SwasthyaLegacyDashboard/1.2"
UA_DEBUG    = "InternalDebugTool/0.9 (curl/7.88)"
UA_ATTACKER = "python-requests/2.31.0"
UA_MONITOR  = "HealthCheckBot/1.0"

# Source IPs
IP_WEBAPP_POOL = ["10.0.1.10", "10.0.1.11", "10.0.1.12", "10.0.1.13"]
IP_MOBILE_POOL = ["203.0.113.20", "203.0.113.21", "203.0.113.22"]
IP_LEGACY      = "192.168.100.50"   # old internal dashboard
IP_DEBUG       = "192.168.100.99"   # internal dev machine
IP_BURST       = "45.33.32.156"     # rate-limit attacker IP
IP_OTP_BRUTE   = "198.51.100.77"    # OTP brute-forcer IP
IP_MONITOR     = "127.0.0.1"

# ─────────────────────────────────────────────────────────────────────────────
# Data classes
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class RequestRecord:
    """Represents a single HTTP exchange to be written to both log files."""
    fake_ts: datetime.datetime      # simulated timestamp within the fake 24h day
    source_ip: str
    method: str
    path: str                       # full path incl. query string for log
    status: int
    response_size: int
    referer: str
    user_agent: str
    has_auth: bool
    token: Optional[str]            # raw token value, None if no auth header sent
    token_owner: Optional[str]      # human label, e.g. "patient-101" or None


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def nginx_ts(dt: datetime.datetime) -> str:
    return dt.strftime("%d/%b/%Y:%H:%M:%S +0530")


def nginx_line(r: RequestRecord) -> str:
    """Render one Nginx combined-format log line."""
    ts = nginx_ts(r.fake_ts)
    path_field = r.path.replace('"', '\\"')
    return (
        f'{r.source_ip} - - [{ts}] '
        f'"{r.method} {path_field} HTTP/1.1" '
        f'{r.status} {r.response_size} '
        f'"{r.referer}" "{r.user_agent}"'
    )


def header_log_entry(r: RequestRecord) -> str:
    """Render one JSONL line for access_headers.log."""
    obj = {
        "timestamp": r.fake_ts.strftime("%Y-%m-%dT%H:%M:%S+05:30"),
        "source_ip": r.source_ip,
        "method": r.method,
        "path": r.path,
        "status": r.status,
        "has_authorization": r.has_auth,
        "token": r.token,          # None becomes JSON null
        "token_owner": r.token_owner,
        "user_agent": r.user_agent,
    }
    return json.dumps(obj, ensure_ascii=False)


def fake_time(hour_lo: float, hour_hi: float, rng: random.Random) -> datetime.datetime:
    """Return a random datetime within [hour_lo, hour_hi] on the fake day."""
    offset_s = rng.uniform(hour_lo * 3600, hour_hi * 3600)
    return BASE_DAY + datetime.timedelta(seconds=offset_s)


def do_request(
    session: requests.Session,
    server_url: str,
    method: str,
    path: str,
    token: Optional[str] = None,
    json_body: Optional[dict] = None,
    timeout: int = 5,
) -> tuple[int, int]:
    """
    Fire the real HTTP request.  Returns (status_code, response_body_bytes).
    Swallows connection errors gracefully (server may not be perfectly stable).
    """
    headers = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if json_body is not None:
        headers["Content-Type"] = "application/json"

    url = server_url.rstrip("/") + path.split("?")[0]
    params = None
    if "?" in path:
        qs = path.split("?", 1)[1]
        params = dict(kv.split("=", 1) for kv in qs.split("&") if "=" in kv)

    try:
        resp = session.request(
            method,
            url,
            headers=headers,
            json=json_body,
            params=params,
            timeout=timeout,
        )
        return resp.status_code, len(resp.content)
    except requests.RequestException as e:
        print(f"  [WARN] Request failed: {method} {path} — {e}", file=sys.stderr)
        return 0, 0


# ─────────────────────────────────────────────────────────────────────────────
# Traffic generators — each returns a list of RequestRecord (unsorted by time)
# ─────────────────────────────────────────────────────────────────────────────

def gen_documented_traffic(
    session: requests.Session, server_url: str, rng: random.Random
) -> list[RequestRecord]:
    """
    Steady, realistic traffic to the 4 documented endpoints during business
    hours (08:00–20:00) with proper Bearer tokens.
    """
    records: list[RequestRecord] = []

    # --- Health checks (monitoring bot, all day, high frequency) ---
    for _ in range(80):
        ts = fake_time(0, 24, rng)
        status, size = do_request(session, server_url, "GET", "/api/v1/health")
        if status == 0:
            continue
        records.append(RequestRecord(
            fake_ts=ts, source_ip=IP_MONITOR,
            method="GET", path="/api/v1/health",
            status=status, response_size=size,
            referer="-", user_agent=UA_MONITOR,
            has_auth=False, token=None, token_owner=None,
        ))

    # --- GET /api/v1/patients/{id} — webapp and mobile clients ---
    for _ in range(120):
        pid = rng.choice(PATIENT_IDS[:10])   # most traffic on first 10 patients
        token_pid = rng.choice([101, 102, 103, 104, 105])
        token = PATIENT_TOKENS[token_pid]
        ts = fake_time(8, 20, rng)
        ip = rng.choice(IP_WEBAPP_POOL + IP_MOBILE_POOL)
        ua = rng.choice([UA_WEBAPP, UA_MOBILE])
        path = f"/api/v1/patients/{pid}"
        status, size = do_request(session, server_url, "GET", path, token=token)
        if status == 0:
            continue
        records.append(RequestRecord(
            fake_ts=ts, source_ip=ip,
            method="GET", path=path,
            status=status, response_size=size,
            referer="-", user_agent=ua,
            has_auth=True, token=token, token_owner=f"patient-{token_pid}",
        ))

    # --- GET /api/v1/patients/{id} — a few without auth (misconfigured client) ---
    for pid in rng.sample(PATIENT_IDS, 4):
        ts = fake_time(9, 18, rng)
        path = f"/api/v1/patients/{pid}"
        status, size = do_request(session, server_url, "GET", path, token=None)
        if status == 0:
            continue
        records.append(RequestRecord(
            fake_ts=ts, source_ip=rng.choice(IP_MOBILE_POOL),
            method="GET", path=path,
            status=status, response_size=size,
            referer="-", user_agent=UA_MOBILE,
            has_auth=False, token=None, token_owner=None,
        ))

    # --- GET /api/v1/doctors/{id} ---
    for _ in range(60):
        did = rng.randint(1, 5)
        token = rng.choice([PATIENT_TOKENS[101], PATIENT_TOKENS[102], DOCTOR_TOKEN])
        token_owner = "doctor-1" if token == DOCTOR_TOKEN else f"patient-{[k for k,v in PATIENT_TOKENS.items() if v==token][0]}"
        ts = fake_time(8, 18, rng)
        path = f"/api/v1/doctors/{did}"
        status, size = do_request(session, server_url, "GET", path, token=token)
        if status == 0:
            continue
        records.append(RequestRecord(
            fake_ts=ts, source_ip=rng.choice(IP_WEBAPP_POOL),
            method="GET", path=path,
            status=status, response_size=size,
            referer="-", user_agent=UA_WEBAPP,
            has_auth=True, token=token, token_owner=token_owner,
        ))

    # --- POST /api/v1/appointments ---
    for i in range(40):
        pid = rng.choice(PATIENT_IDS[:8])
        did = rng.randint(1, 5)
        token_pid = rng.choice([101, 102, 103, 104, 105])
        token = PATIENT_TOKENS[token_pid]
        ts = fake_time(8, 17, rng)
        body = {"patient_id": pid, "doctor_id": did,
                "date": "2026-07-05", "slot": f"{rng.randint(9,16):02d}:00"}
        status, size = do_request(
            session, server_url, "POST", "/api/v1/appointments",
            token=token, json_body=body
        )
        if status == 0:
            continue
        records.append(RequestRecord(
            fake_ts=ts, source_ip=rng.choice(IP_WEBAPP_POOL),
            method="POST", path="/api/v1/appointments",
            status=status, response_size=size,
            referer="-", user_agent=UA_WEBAPP,
            has_auth=True, token=token, token_owner=f"patient-{token_pid}",
        ))

    return records


def gen_shadow_legacy_traffic(
    session: requests.Session, server_url: str, rng: random.Random
) -> list[RequestRecord]:
    """
    Low-frequency 'legacy dashboard' hits against shadow endpoints.
    Simulates an old internal system still calling undocumented routes,
    mostly off-hours but also some during the day.
    """
    records: list[RequestRecord] = []

    # --- SHADOW: GET /api/v1/patient-records/{id}  (BOLA-vulnerable) ---
    # Legacy dashboard uses a single service-account-like token but fetches
    # arbitrary patient IDs — classic BOLA pattern
    legacy_token = PATIENT_TOKENS[101]   # service account borrowing patient-101 token
    for _ in range(35):
        pid = rng.choice(PATIENT_IDS)
        ts = fake_time(0, 24, rng)
        path = f"/api/v1/patient-records/{pid}"
        status, size = do_request(session, server_url, "GET", path, token=legacy_token)
        if status == 0:
            continue
        records.append(RequestRecord(
            fake_ts=ts, source_ip=IP_LEGACY,
            method="GET", path=path,
            status=status, response_size=size,
            referer="-", user_agent=UA_LEGACY,
            has_auth=True, token=legacy_token, token_owner="patient-101(legacy-svc)",
        ))

    # --- SHADOW: GET /api/v1/internal/debug/patient/{id}  (no auth!) ---
    for _ in range(20):
        pid = rng.choice(PATIENT_IDS)
        ts = fake_time(0, 24, rng)
        path = f"/api/v1/internal/debug/patient/{pid}"
        status, size = do_request(session, server_url, "GET", path, token=None)
        if status == 0:
            continue
        records.append(RequestRecord(
            fake_ts=ts, source_ip=IP_DEBUG,
            method="GET", path=path,
            status=status, response_size=size,
            referer="-", user_agent=UA_DEBUG,
            has_auth=False, token=None, token_owner=None,
        ))

    # --- SHADOW: DELETE /api/v1/appointments/{id}  (undocumented method) ---
    for appt_id in range(1005, 1025):   # IDs created by documented POST traffic
        if rng.random() > 0.4:
            continue
        ts = fake_time(10, 22, rng)
        path = f"/api/v1/appointments/{appt_id}"
        token = rng.choice([PATIENT_TOKENS[101], PATIENT_TOKENS[102]])
        token_pid = 101 if token == PATIENT_TOKENS[101] else 102
        status, size = do_request(session, server_url, "DELETE", path, token=token)
        if status == 0:
            continue
        records.append(RequestRecord(
            fake_ts=ts, source_ip=rng.choice(IP_WEBAPP_POOL),
            method="DELETE", path=path,
            status=status, response_size=size,
            referer="-", user_agent=UA_WEBAPP,
            has_auth=True, token=token, token_owner=f"patient-{token_pid}",
        ))

    # --- SHADOW: GET /api/v1/patients/{id}/insurance-claims  (low-freq baseline) ---
    # Normal-looking but undocumented; the burst is in gen_rate_limit_burst()
    for _ in range(15):
        pid = rng.choice(PATIENT_IDS[:8])
        ts = fake_time(9, 18, rng)
        token_pid = rng.choice([101, 102, 103])
        token = PATIENT_TOKENS[token_pid]
        path = f"/api/v1/patients/{pid}/insurance-claims"
        status, size = do_request(session, server_url, "GET", path, token=token)
        if status == 0:
            continue
        records.append(RequestRecord(
            fake_ts=ts, source_ip=rng.choice(IP_WEBAPP_POOL),
            method="GET", path=path,
            status=status, response_size=size,
            referer="-", user_agent=UA_WEBAPP,
            has_auth=True, token=token, token_owner=f"patient-{token_pid}",
        ))

    return records


def gen_rate_limit_burst(
    session: requests.Session, server_url: str, rng: random.Random
) -> list[RequestRecord]:
    """
    Deliberate rapid burst of ~45 requests to /api/v1/patients/{id}/insurance-claims
    from a single attacker IP (IP_BURST) within a 90-second window.
    The mock server has no rate limiting → all return 200 → triggers API4:2023 check.
    """
    records: list[RequestRecord] = []

    # Burst starts at a random hour between 02:00–04:00 (quiet hours — more suspicious)
    burst_start_s = rng.uniform(2 * 3600, 4 * 3600)
    burst_token = PATIENT_TOKENS[103]   # attacker holds one valid token

    for i in range(45):
        pid = rng.choice(PATIENT_IDS)   # scanning different patient IDs
        path = f"/api/v1/patients/{pid}/insurance-claims"
        ts = BASE_DAY + datetime.timedelta(seconds=burst_start_s + i * 2)  # 1 req/2s
        status, size = do_request(session, server_url, "GET", path, token=burst_token)
        if status == 0:
            continue
        records.append(RequestRecord(
            fake_ts=ts, source_ip=IP_BURST,
            method="GET", path=path,
            status=status, response_size=size,
            referer="-", user_agent=UA_ATTACKER,
            has_auth=True, token=burst_token, token_owner="patient-103(attacker)",
        ))

    return records


def gen_otp_brute_force(
    session: requests.Session, server_url: str, rng: random.Random
) -> list[RequestRecord]:
    """
    ~50 rapid sequential OTP guesses against patient_id=104 from IP_OTP_BRUTE,
    within a ~60-second window.  Simulates an attacker who knows the patient ID
    and is brute-forcing the 6-digit OTP.  The correct OTP for patient 104 is
    924561 — the attacker doesn't know this, so they iterate.
    No rate limiting or lockout on the mock server → all requests land.
    """
    records: list[RequestRecord] = []

    # Burst starts around 03:00–05:00
    brute_start_s = rng.uniform(3 * 3600, 5 * 3600)
    target_patient = 104

    # Attacker tries sequential guesses starting from a random 6-digit base
    start_guess = rng.randint(900000, 930000)

    for i in range(52):
        guess = str(start_guess + i).zfill(6)
        path = f"/api/v1/otp/verify?patient_id={target_patient}&otp={guess}"
        ts = BASE_DAY + datetime.timedelta(seconds=brute_start_s + i * 1.2)
        status, size = do_request(session, server_url, "GET", path, token=None)
        if status == 0:
            continue
        records.append(RequestRecord(
            fake_ts=ts, source_ip=IP_OTP_BRUTE,
            method="GET", path=path,
            status=status, response_size=size,
            referer="-", user_agent=UA_ATTACKER,
            has_auth=False, token=None, token_owner=None,
        ))

    return records


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate synthetic Nginx access logs for SwasthyaConnect scanner demo"
    )
    parser.add_argument(
        "--server-url", default="http://localhost:8000",
        help="Base URL of the running mock server (default: http://localhost:8000)"
    )
    parser.add_argument(
        "--out-dir", default="mock_env",
        help="Directory to write access.log and access_headers.log (default: mock_env)"
    )
    parser.add_argument(
        "--seed", type=int, default=42,
        help="Random seed for reproducibility (default: 42)"
    )
    args = parser.parse_args()

    rng = random.Random(args.seed)
    os.makedirs(args.out_dir, exist_ok=True)
    access_log_path   = os.path.join(args.out_dir, "access.log")
    headers_log_path  = os.path.join(args.out_dir, "access_headers.log")

    # Quick connectivity check
    print(f"[*] Checking mock server at {args.server_url} ...")
    try:
        r = requests.get(f"{args.server_url}/api/v1/health", timeout=4)
        if r.status_code != 200:
            print(f"[!] Server returned {r.status_code} on /health — is it running?",
                  file=sys.stderr)
            sys.exit(1)
        print(f"[+] Server is up: {r.json()}")
    except requests.RequestException as e:
        print(f"[!] Cannot reach server: {e}\n    Start it with: python mock_env/mock_server.py",
              file=sys.stderr)
        sys.exit(1)

    session = requests.Session()
    all_records: list[RequestRecord] = []

    print("\n[*] Generating traffic segments...")

    print("    → Documented endpoint traffic (health, patients, doctors, appointments)...")
    all_records += gen_documented_traffic(session, args.server_url, rng)

    print("    → Shadow / legacy endpoint traffic (patient-records, debug, insurance-claims, DELETE)...")
    all_records += gen_shadow_legacy_traffic(session, args.server_url, rng)

    print("    → Rate-limit absence burst (45 rapid insurance-claims requests, IP_BURST)...")
    all_records += gen_rate_limit_burst(session, args.server_url, rng)

    print("    → OTP brute-force sequence (52 sequential guesses, IP_OTP_BRUTE)...")
    all_records += gen_otp_brute_force(session, args.server_url, rng)

    # Sort chronologically by fake timestamp (mirrors a real log file)
    all_records.sort(key=lambda r: r.fake_ts)

    # Filter out failed requests (server timeout / connection error)
    good = [r for r in all_records if r.status != 0]
    dropped = len(all_records) - len(good)
    if dropped:
        print(f"[!] Dropped {dropped} records where server returned no response")

    print(f"\n[*] Writing {len(good)} log entries...")

    with open(access_log_path, "w", encoding="utf-8") as af, \
         open(headers_log_path, "w", encoding="utf-8") as hf:
        for r in good:
            af.write(nginx_line(r) + "\n")
            hf.write(header_log_entry(r) + "\n")

    print(f"[+] Wrote: {access_log_path}")
    print(f"[+] Wrote: {headers_log_path}")

    # ── Summary statistics ────────────────────────────────────────────────────
    from collections import Counter
    import re

    # Normalize path for counting (strip query string, collapse numeric IDs)
    def norm(path: str) -> str:
        p = path.split("?")[0]
        p = re.sub(r"/\d+", "/{id}", p)
        return p

    endpoint_hits: Counter = Counter()
    method_hits: Counter   = Counter()
    status_hits: Counter   = Counter()
    ip_hits: Counter       = Counter()

    for r in good:
        key = f"{r.method} {norm(r.path)}"
        endpoint_hits[key] += 1
        method_hits[r.method] += 1
        status_hits[r.status] += 1
        ip_hits[r.source_ip] += 1

    print("\n" + "═" * 62)
    print(f"  SUMMARY — {len(good)} total requests logged")
    print("═" * 62)
    print(f"\n  Requests by normalised endpoint (sorted by count):")
    for ep, cnt in endpoint_hits.most_common():
        bar = "█" * min(cnt // 2, 30)
        print(f"    {cnt:4d}  {ep:<55} {bar}")

    print(f"\n  HTTP methods:  {dict(method_hits)}")
    print(f"  Status codes:  {dict(sorted(status_hits.items()))}")

    print(f"\n  Top source IPs:")
    for ip, cnt in ip_hits.most_common(8):
        label = {
            IP_LEGACY:    " ← legacy dashboard",
            IP_DEBUG:     " ← debug tool",
            IP_BURST:     " ← RATE-LIMIT BURST attacker",
            IP_OTP_BRUTE: " ← OTP brute-forcer",
            IP_MONITOR:   " ← health monitor",
        }.get(ip, "")
        print(f"    {cnt:4d}  {ip:<20}{label}")

    # Special checks for the two required burst patterns
    insurance_hits = sum(v for k, v in endpoint_hits.items() if "insurance-claims" in k)
    otp_hits       = sum(v for k, v in endpoint_hits.items() if "otp/verify" in k)
    burst_ip_hits  = ip_hits.get(IP_BURST, 0)
    otp_ip_hits    = ip_hits.get(IP_OTP_BRUTE, 0)

    print(f"\n  Burst verification:")
    print(f"    insurance-claims total hits : {insurance_hits}  "
          f"(burst IP {IP_BURST}: {burst_ip_hits})")
    print(f"    otp/verify total hits       : {otp_hits}  "
          f"(brute-force IP {IP_OTP_BRUTE}: {otp_ip_hits})")
    print("═" * 62)
    print()


if __name__ == "__main__":
    main()
