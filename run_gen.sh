#!/usr/bin/env bash
set -e
cd /home/alpha0/HCIC/project
source bin/activate

echo "=== [1/4] Starting fresh mock server on port 8000 ==="
pkill -f "mock_server.py" 2>/dev/null || true
sleep 0.5
python mock_env/mock_server.py --port 8000 >/tmp/swasthya.log 2>&1 &
SERVER_PID=$!
echo "Server PID=$SERVER_PID"

# Poll until ready (max 6s)
for i in $(seq 1 12); do
  sleep 0.5
  if curl -s --max-time 1 http://localhost:8000/api/v1/health >/dev/null 2>&1; then
    echo "Server up after ${i} polls."
    break
  fi
done

echo ""
echo "=== [2/4] Running generate_logs.py ==="
python mock_env/generate_logs.py \
  --server-url http://localhost:8000 \
  --out-dir mock_env \
  --seed 42

echo ""
echo "=== [3/4] Sample lines from access.log ==="
echo "--- First 8 lines ---"
head -8 mock_env/access.log
echo ""
echo "--- 7 lines from around line 200 ---"
sed -n "200,206p" mock_env/access.log

echo ""
echo "=== [4/4] First 5 lines from access_headers.log (pretty-printed) ==="
head -5 mock_env/access_headers.log | python3 -c "
import sys, json
for line in sys.stdin:
    line = line.strip()
    if line:
        print(json.dumps(json.loads(line), indent=2))
        print()
"

echo ""
echo "=== Burst verification (grep counts) ==="
TOTAL_INSURANCE=$(grep -c "insurance-claims" mock_env/access.log 2>/dev/null || echo 0)
BURST_INSURANCE=$(grep "45.33.32.156" mock_env/access.log | grep -c "insurance-claims" 2>/dev/null || echo 0)
TOTAL_OTP=$(grep -c "otp/verify" mock_env/access.log 2>/dev/null || echo 0)
BRUTE_OTP=$(grep "198.51.100.77" mock_env/access.log | grep -c "otp/verify" 2>/dev/null || echo 0)

echo "insurance-claims total hits          : $TOTAL_INSURANCE"
echo "insurance-claims from burst IP       : $BURST_INSURANCE  (45.33.32.156)"
echo "otp/verify total hits                : $TOTAL_OTP"
echo "otp/verify from brute-force IP       : $BRUTE_OTP  (198.51.100.77)"

echo ""
ACCESS_LINES=$(wc -l < mock_env/access.log)
HEADER_LINES=$(wc -l < mock_env/access_headers.log)
echo "Total lines in access.log            : $ACCESS_LINES"
echo "Total lines in access_headers.log    : $HEADER_LINES"

echo ""
echo "=== Killing server ==="
kill $SERVER_PID 2>/dev/null && echo "Server PID $SERVER_PID stopped cleanly."
