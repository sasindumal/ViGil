#!/bin/bash

# ViGiL Agentic Malware Analysis Startup Script
# Verifies environment, loads .env variables, and launches the FastAPI app.

echo "=================================================================="
echo "🛡️  Starting ViGiL Agentic CPG Malware Analysis Pipeline..."
echo "=================================================================="

# Move to the workspace root directory (which contains agentic_analyzer and uir folders)
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
WORKSPACE_DIR="$(dirname "$SCRIPT_DIR")"
cd "$WORKSPACE_DIR"

echo "Workspace root: $WORKSPACE_DIR"

# Verify that python can import needed dependencies
echo "Verifying active environment packages..."
python -c "
import fastapi, uvicorn, websockets, dotenv
print('✓ FastAPI, Uvicorn, Websockets, Dotenv: OK')
" 2>/dev/null

if [ $? -ne 0 ]; then
    echo "⚠️  Missing core dependencies in current python environment. Installing..."
    python -m pip install fastapi uvicorn websockets python-dotenv
fi

python -c "
import crewai
print('✓ CrewAI Core: OK')
" 2>/dev/null

if [ $? -ne 0 ]; then
    echo "⚠️  Missing CrewAI. Installing package..."
    python -m pip install crewai langchain-openai
fi

# Load configurations
if [ -f "$WORKSPACE_DIR/agentic_analyzer/.env" ]; then
    echo "✓ Loaded environment settings from agentic_analyzer/.env"
else
    echo "⚠️  agentic_analyzer/.env not found! Copying from template..."
    cp "$WORKSPACE_DIR/agentic_analyzer/.env.template" "$WORKSPACE_DIR/agentic_analyzer/.env"
fi

echo "🚀 Launching FastAPI server on http://localhost:8000..."
echo "Press Ctrl+C to stop."
echo "------------------------------------------------------------------"

python -m uvicorn agentic_analyzer.backend.app:app --host 0.0.0.0 --port 8000 --reload
