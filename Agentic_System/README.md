# ViGil Malware & Vulnerability Analysis System — Running Guide

This document provides step-by-step instructions on setting up, configuring, and running the backend API and Next.js frontend of the **ViGil** agentic malware analysis system.

---

## 🛠 Prerequisites

Ensure you have the following installed on your system:
1. **Python 3.10+** (with pip)
2. **Node.js 18+** (with npm)
3. **Rust** / **Cargo** (optional, required if installing `yara-python` from source, though pre-built wheels are usually available)

---

## 1. Backend Setup & Running

The backend is a FastAPI application that handles deep static PE analysis (15 modules), runs the Monte Carlo BNN PyTorch joint model, manages short/long term SQLite memory, and runs the 24-agent CrewAI orchestration.

### Step 1.1: Navigate to the Project Root
```bash
cd Agentic_System
```

### Step 1.2: Set Up a Python Virtual Environment
We recommend using a virtual environment (`venv` or `conda`):
```bash
# Using venv
python3 -m venv venv
source venv/bin/activate
```

### Step 1.3: Install Dependencies
```bash
pip install -r requirements.txt
```

### Step 1.4: Configure Environment Variables
Copy the template `.env.example` file to `.env` and configure your API keys (e.g. OpenAI, Google Gemini, NVIDIA NIM, OpenRouter):
```bash
cp .env.example .env
```
Open `.env` in your editor and add your LLM API keys. *Note: You can also configure these keys dynamically through the Web UI Settings panel later.*

### Step 1.5: Start the Backend Server
Start the Uvicorn ASGI server:
```bash
uvicorn backend.main:app --host 0.0.0.0 --port 8000
```
Upon startup, the backend will auto-initialize storage directories, load the PyTorch `joint_model.pt` checkpoint, and listen on `http://127.0.0.1:8000`.

---

## 2. Frontend Setup & Running

The frontend is an ultramodern, dark-themed Next.js 16 web interface featuring responsive grids, glassmorphism panels, real-time analysis logs via WebSockets, and MITRE ATT&CK technique matrices.

### Step 2.1: Navigate to the Frontend Directory
```bash
cd frontend
```

### Step 2.2: Install Node Dependencies
```bash
npm install
```

### Step 2.3: Start the Development Server
```bash
npm run dev
```
Open [http://localhost:3000](http://localhost:3000) in your web browser.

### Step 2.4: Build for Production (Optional)
To build a highly optimized production bundle:
```bash
npm run build
npm run start
```

---

## 3. Verifying the System

Once both services are running, verify the connection:
1. Open your browser at `http://localhost:3000`.
2. Navigate to the **Settings** panel on the left sidebar.
3. Select your preferred LLM provider, input your API key (if not already set in `.env`), and click **Test Connection**. It should report a successful connection.
4. Go back to the **Dashboard**, upload a portable executable (`.exe` or `.dll`) or script, and watch the real-time agent workflow run!
