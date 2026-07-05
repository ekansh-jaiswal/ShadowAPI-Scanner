#!/usr/bin/env bash
set -e
cd "$(dirname "$0")"
source bin/activate

# Kill any stale instance
pkill -f "mock_server.py" 2>/dev/null || true
sleep 0.3

# Start server in background
python mock_env/mock_server.py --port 8000 >/tmp/swasthya.log 2>&1 &
SERVER_PID=$!
echo "Server PID=$SERVER_PID  (log: /tmp/swasthya.log)"

# Poll until port answers (max 6 s)
for i in $(seq 1 12); do
  sleep 0.5
  if curl -s --max-time 1 http://localhost:8000/api/v1/health >/dev/null 2>&1; then
    echo "Port 8000 is up after ~$((i/2))s"
    break
  fi
  echo "  waiting... ($i/12)"
done

SEP="━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

echo ""
echo "$SEP"
echo " 1. GET /api/v1/health  (public — no auth)"
echo "$SEP"
curl -s -w "\n[HTTP %{http_code}]\n" http://localhost:8000/api/v1/health

echo ""
echo "$SEP"
echo " 2. GET /api/v1/patients/104  — NO auth  (expect 401)"
echo "$SEP"
curl -s -w "\n[HTTP %{http_code}]\n" http://localhost:8000/api/v1/patients/104

echo ""
echo "$SEP"
echo " 3. GET /api/v1/patients/104  — WITH auth token-patient-101"
echo "    (documented endpoint: MINIMAL fields, no aadhaar/diagnosis)"
echo "$SEP"
curl -s -w "\n[HTTP %{http_code}]\n" \
  -H "Authorization: Bearer token-patient-101" \
  http://localhost:8000/api/v1/patients/104

echo ""
echo "$SEP"
echo " 4. SHADOW: GET /api/v1/patient-records/104"
echo "    token=token-patient-101 (patient 101 reading patient 104) — BOLA"
echo "$SEP"
curl -s -w "\n[HTTP %{http_code}]\n" \
  -H "Authorization: Bearer token-patient-101" \
  http://localhost:8000/api/v1/patient-records/104

echo ""
echo "$SEP"
echo " 5. SHADOW: GET /api/v1/internal/debug/patient/104  — NO AUTH AT ALL"
echo "    (critical: raw DB row, internal_notes, ssn, insurance_claims)"
echo "$SEP"
curl -s -w "\n[HTTP %{http_code}]\n" \
  http://localhost:8000/api/v1/internal/debug/patient/104

echo ""
echo "$SEP"
echo " 6. SHADOW: GET /api/v1/patients/104/insurance-claims"
echo "    wrong-user token — ownership bypass + aadhaar in response"
echo "$SEP"
curl -s -w "\n[HTTP %{http_code}]\n" \
  -H "Authorization: Bearer token-patient-101" \
  "http://localhost:8000/api/v1/patients/104/insurance-claims"

echo ""
echo "$SEP"
echo " 7. SHADOW: GET /api/v1/otp/verify — WRONG OTP  (expect 401)"
echo "$SEP"
curl -s -w "\n[HTTP %{http_code}]\n" \
  "http://localhost:8000/api/v1/otp/verify?patient_id=101&otp=999999"

echo ""
echo "$SEP"
echo " 8. SHADOW: GET /api/v1/otp/verify — CORRECT OTP 482915"
echo "    (no rate-limit, no lockout — brute-forceable)"
echo "$SEP"
curl -s -w "\n[HTTP %{http_code}]\n" \
  "http://localhost:8000/api/v1/otp/verify?patient_id=101&otp=482915"

echo ""
echo "$SEP"
echo " 9. SHADOW: DELETE /api/v1/appointments/1002"
echo "    undocumented DELETE method — Improper Inventory Management"
echo "$SEP"
curl -s -w "\n[HTTP %{http_code}]\n" \
  -X DELETE \
  -H "Authorization: Bearer token-patient-101" \
  http://localhost:8000/api/v1/appointments/1002

echo ""
echo "$SEP"
echo "10. GET /api/v1/doctors/2  — documented, with auth"
echo "$SEP"
curl -s -w "\n[HTTP %{http_code}]\n" \
  -H "Authorization: Bearer token-patient-101" \
  http://localhost:8000/api/v1/doctors/2

echo ""
echo "$SEP"
echo "11. POST /api/v1/appointments  — documented, with auth"
echo "$SEP"
curl -s -w "\n[HTTP %{http_code}]\n" \
  -X POST \
  -H "Authorization: Bearer token-patient-101" \
  -H "Content-Type: application/json" \
  -d '{"patient_id": 101, "doctor_id": 3, "date": "2026-07-20", "slot": "11:00"}' \
  http://localhost:8000/api/v1/appointments

echo ""
echo "$SEP"
echo "Killing server PID=$SERVER_PID"
kill $SERVER_PID 2>/dev/null && echo "Server stopped cleanly."
