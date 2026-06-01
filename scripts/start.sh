#!/bin/bash
# ViGiL — Start Script
# Starts both backend and frontend in development mode

set -e

BACKEND_DIR="$(cd "$(dirname "$0")/backend" && pwd)"
FRONTEND_DIR="$(cd "$(dirname "$0")/frontend" && pwd)"

echo "════════════════════════════════════════"
echo "  ViGiL — Malware Analysis Platform"
echo "════════════════════════════════════════"

# Check if .env exists
if [ ! -f "$(dirname "$0")/.env" ]; then
    echo "⚠️  No .env found — copying from .env.example"
    cp "$(dirname "$0")/.env.example" "$(dirname "$0")/.env"
fi

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
