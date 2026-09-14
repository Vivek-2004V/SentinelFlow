#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BACKEND_DIR="${ROOT_DIR}/backend"
FRONTEND_DIR="${ROOT_DIR}/frontend"

echo "============================================================"
echo "    🛡️  SentinelFlow: Starting Autonomous Detection Stack    "
echo "============================================================"
echo "Workspace Root: ${ROOT_DIR}"
echo "Passive Mode:   ENFORCED (One-way telemetry, ALERT_ONLY)"
echo "------------------------------------------------------------"

# Trap INT and TERM for graceful cleanup
cleanup() {
    echo ""
    echo "Shutting down SentinelFlow services..."
    if [[ -n "${BACKEND_PID:-}" ]] && kill -0 "${BACKEND_PID}" 2>/dev/null; then
        echo "Stopping backend (PID ${BACKEND_PID})..."
        kill -SIGTERM "${BACKEND_PID}" 2>/dev/null || true
    fi
    if [[ -n "${FRONTEND_PID:-}" ]] && kill -0 "${FRONTEND_PID}" 2>/dev/null; then
        echo "Stopping frontend (PID ${FRONTEND_PID})..."
        kill -SIGTERM "${FRONTEND_PID}" 2>/dev/null || true
    fi
    echo "SentinelFlow stopped cleanly."
    exit 0
}

trap cleanup SIGINT SIGTERM EXIT

# 1. Start Backend
echo "[1/3] Launching FastAPI Backend on :8000..."
cd "${BACKEND_DIR}"
if [[ -d ".venv" ]]; then
    PYTHON_EXEC="${BACKEND_DIR}/.venv/bin/python"
elif command -v python3 &>/dev/null; then
    PYTHON_EXEC="python3"
else
    echo "ERROR: Python 3 executable not found!"
    exit 1
fi

"${PYTHON_EXEC}" -m uvicorn app.main:app --host 0.0.0.0 --port 8000 &
BACKEND_PID=$!

# Wait for backend health check
echo "Waiting for backend health check at http://localhost:8000/health..."
MAX_RETRIES=20
COUNT=0
until curl -s http://localhost:8000/health | grep -q "healthy" || [ $COUNT -ge $MAX_RETRIES ]; do
    sleep 0.5
    COUNT=$((COUNT + 1))
done

if [ $COUNT -ge $MAX_RETRIES ]; then
    echo "Backend did not report healthy in time. Check logs above."
    exit 1
fi
echo "Backend is HEALTHY (PID: ${BACKEND_PID})."

# 2. Start Frontend
echo "[2/3] Launching Next.js Frontend on :3000..."
cd "${FRONTEND_DIR}"
if ! command -v npm &>/dev/null; then
    echo "ERROR: npm is required to run the frontend."
    exit 1
fi

npm run dev -- -p 3000 &
FRONTEND_PID=$!

echo "[3/3] SentinelFlow Stack is Live!"
echo "============================================================"
echo "  Dashboard: http://localhost:3000"
echo "  API Docs:  http://localhost:8000/docs"
echo "  Metrics:   http://localhost:8000/api/v1/stream/metrics"
echo "  Live SSE:  http://localhost:8000/api/v1/stream/live"
echo "============================================================"
echo "Press Ctrl+C to terminate both services."

# Wait indefinitely on child processes
wait
