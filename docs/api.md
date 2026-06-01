# ViGiL API Reference

## Base URL

```
http://localhost:8000
```

## Endpoints

### Health Check

```http
GET /api/health
```

**Response:**
```json
{
  "status": "ok",
  "version": "1.0.0",
  "llm_provider": "openai",
  "threat_intel_enabled": false,
  "demo_mode": true
}
```

---

### Submit Analysis

```http
POST /api/analyze
Content-Type: multipart/form-data
```

**Body:** `file` (binary PE file, max 100MB)

**Response:**
```json
{
  "job_id": "uuid-...",
  "filename": "sample.exe",
  "status": "queued",
  "created_at": "2024-01-01T00:00:00Z",
  "progress": 0
}
```

**Errors:**
- `400` — Not a PE file (missing MZ header)
- `413` — File too large

---

### Get Job Status

```http
GET /api/job/{job_id}
```

**Response:**
```json
{
  "job_id": "uuid-...",
  "filename": "sample.exe",
  "status": "running|completed|failed",
  "progress": 65,
  "current_agent": "Evasion Detection",
  "created_at": "...",
  "completed_at": null,
  "error": null
}
```

---

### Get Full Report

```http
GET /api/report/{job_id}
```

Returns `202 Accepted` if analysis not yet complete.

Returns full `VigilReport` JSON when complete (see models.py for schema).

---

### Download Artifact

```http
GET /api/download/{job_id}/{artifact}
```

**Artifacts:**

| Value | File | MIME |
|-------|------|------|
| `report_json` | `report.json` | application/json |
| `report_stix` | `report.stix.json` | application/json |
| `yara` | `generated.yara` | text/plain |
| `attack_navigator` | `attack_layer.json` | application/json |

---

### List All Jobs

```http
GET /api/jobs
```

---

## WebSocket

### Connect

```
ws://localhost:8000/ws/{job_id}
```

### Event Schema

```json
{
  "job_id": "uuid-...",
  "agent_name": "Evasion Detection",
  "agent_index": 6,
  "total_agents": 17,
  "status": "started|completed|failed",
  "message": "Detecting anti-VM, anti-debug, API obfuscation...",
  "timestamp": "2024-01-01T00:00:05Z",
  "result_summary": {
    "score": 75,
    "anti_vm": true,
    "anti_debug": true
  }
}
```

### Status Events

When a job completes or fails, a final event is sent:

```json
{
  "type": "job_status",
  "job_id": "uuid-...",
  "status": "completed"
}
```

---

## Interactive Docs

Swagger UI: http://localhost:8000/api/docs  
ReDoc: http://localhost:8000/api/redoc
