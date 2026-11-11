#!/usr/bin/env bash
set -e

echo "═══════════════════════════════════════════════════════"
echo "   AgentGuard — Local Setup"
echo "═══════════════════════════════════════════════════════"

# ── Backend ───────────────────────────────────────────────
echo ""
echo "▶ Setting up Python backend..."
cd backend

if ! command -v python3 &>/dev/null; then
  echo "ERROR: python3 not found. Install Python 3.11+"; exit 1
fi

python3 -m venv .venv 2>/dev/null || true
source .venv/bin/activate 2>/dev/null || source .venv/Scripts/activate 2>/dev/null || true

pip install -q --upgrade pip
pip install -q -r requirements.txt

echo "✓ Backend dependencies installed"

# Start backend in background. Binds loopback by default; set AGT_HOST to expose.
uvicorn main:app --host "${AGT_HOST:-127.0.0.1}" --port 8000 --reload &
BACKEND_PID=$!
echo "✓ Backend started on http://${AGT_HOST:-127.0.0.1}:8000  (PID $BACKEND_PID)"

cd ..

# ── Frontend ──────────────────────────────────────────────
echo ""
echo "▶ Setting up React frontend..."
cd frontend

if ! command -v node &>/dev/null; then
  echo "ERROR: Node.js not found. Install Node 18+"; kill $BACKEND_PID; exit 1
fi

npm install --silent
echo "✓ Frontend dependencies installed"
echo "✓ Starting frontend on http://localhost:3000"

BROWSER=none npm start &
FRONTEND_PID=$!

cd ..

echo ""
echo "═══════════════════════════════════════════════════════"
echo "  ✅  Dashboard ready at  http://localhost:3000"
echo "  ✅  API docs at         http://localhost:8000/docs"
echo "═══════════════════════════════════════════════════════"
echo ""
echo "  Press Ctrl+C to stop both servers"
echo ""

trap "kill $BACKEND_PID $FRONTEND_PID 2>/dev/null; echo 'Stopped.'" EXIT INT TERM
wait
