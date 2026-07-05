#!/usr/bin/env bash
set -e
cd /home/alpha0/HCIC/project
source bin/activate

echo "=== Starting mock server ==="
pkill -f "mock_server.py" 2>/dev/null || true
sleep 0.5
python mock_env/mock_server.py --port 8000 >/tmp/swasthya.log 2>&1 &
SERVER_PID=$!
echo "Server PID=$SERVER_PID"

# Poll until ready
for i in $(seq 1 12); do
  sleep 0.5
  if curl -s --max-time 1 http://localhost:8000/api/v1/health >/dev/null 2>&1; then
    echo "Server up."
    break
  fi
done

echo ""
echo "=== Running Risk Engine ==="
python scanner/risk_engine.py

echo ""
echo "=== Killing server ==="
kill $SERVER_PID 2>/dev/null || true
