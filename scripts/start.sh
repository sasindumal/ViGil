#!/bin/bash
# ViGiL — Start Script
# Starts both backend and frontend in development mode

# Resolve repo root regardless of where the script is called from
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

BACKEND_DIR="$ROOT_DIR/backend"
FRONTEND_DIR="$ROOT_DIR/frontend"

# Ensure ~/bin (capa, floss) is in PATH
export PATH="$HOME/bin:$PATH"

echo "════════════════════════════════════════"
echo "  ViGiL — Malware Analysis Platform"
echo "════════════════════════════════════════"

# Check if .env exists
if [ ! -f "$ROOT_DIR/.env" ]; then
    echo "⚠️  No .env found — copying from .env.example"
    cp "$ROOT_DIR/.env.example" "$ROOT_DIR/.env"
fi
# Free ports before starting (handles re-runs without manual cleanup)
echo "▶ Freeing ports 8000 and 5173..."
lsof -ti:8000,5173 | xargs kill -9 2>/dev/null || true
sleep 1

# Start backend
echo ""
echo "▶ Starting Backend (FastAPI)..."
cd "$BACKEND_DIR"

if [ -d "venv" ]; then
    source venv/bin/activate
    echo "  Using virtualenv: $BACKEND_DIR/venv"
fi

uvicorn main:app --host 0.0.0.0 --port 8000 --reload &
BACKEND_PID=$!
echo "  Backend PID: $BACKEND_PID"
echo "  API: http://localhost:8000"
echo "  Docs: http://localhost:8000/api/docs"

# Wait for backend to start
sleep 2

# Start frontend
echo ""
echo "▶ Starting Frontend (Vite)..."
cd "$FRONTEND_DIR"
npm run dev &
FRONTEND_PID=$!
echo "  Frontend PID: $FRONTEND_PID"
echo "  UI: http://localhost:5173"

echo ""
echo "════════════════════════════════════════"
echo "  ViGiL is running!"
echo "  Open: http://localhost:5173"
echo "  Ctrl+C to stop all services"
echo "════════════════════════════════════════"

# Wait for Ctrl+C
trap "kill $BACKEND_PID $FRONTEND_PID 2>/dev/null; echo 'Stopped.'" SIGINT SIGTERM
wait
