# ViGiL — Technology Stack

## Backend

| Component | Technology | Rationale |
|-----------|-----------|-----------|
| API Framework | FastAPI | Async, WebSocket support, auto OpenAPI docs |
| Orchestration | Custom Pipeline | Sequential agent pipeline with progress broadcasting |
| PE Analysis | pefile + LIEF | Industry-standard PE parsing libraries |
| String Recovery | FLOSS + strings | FLOSS handles obfuscated strings; strings as fallback |
| Capability Detection | CAPA | Gold standard for malware capability identification |
| Emulation | Speakeasy | Safe x86/x64 emulation without OS execution |
| CFG Analysis | angr + rizin | angr for deep analysis; rizin as lightweight fallback |
| Clustering | HDBSCAN | Density-based clustering for novel family detection |
| Vector Search | FAISS (demo) → Qdrant (prod) | FAISS for zero-config; Qdrant for persistent corpus |
| LLM Integration | OpenAI / Gemini / Ollama / LM Studio | Configurable — supports cloud and local models including LM Studio (OpenAI-compatible API) |
| STIX | stix2 | OASIS STIX 2.1 compliant exports |
| YARA | yara-python | Native YARA rule validation |
| Settings | pydantic-settings | Type-safe environment configuration |
| HTTP Client | httpx | Async HTTP for threat intel APIs |

## Frontend

| Component | Technology | Rationale |
|-----------|-----------|-----------|
| Framework | React + Vite | Fast HMR, modern ES modules |
| Routing | React Router v6 | Client-side navigation |
| Animation | Framer Motion | Smooth page transitions and micro-animations |
| Charts | Recharts | Composable chart library with dark theme support |
| Icons | Lucide React | Consistent, lightweight SVG icons |
| PDF Export | jsPDF + html2canvas | Client-side PDF generation, no server dependency |
| HTTP | Fetch API | Native browser fetch, no axios needed |
| Styling | Vanilla CSS | Maximum control, zero runtime overhead |
| Design | Custom design system | Glass morphism, neon cyan/green palette |

## Security Considerations

- Files are analyzed statically and via safe emulation — **never executed**
- Each job runs in its own isolated directory under `reports/`
- API keys stored in `.env` (never committed)
- File size limit: 100MB (configurable)
- File type validation: MZ header check before processing
- CORS configured for localhost development (restrict in production)

## Production Deployment

For production deployment:

1. **Backend**: Deploy with `uvicorn main:app --workers 4`
2. **Queue**: Replace in-memory job store with Redis + Celery
3. **Storage**: Replace local filesystem with S3 or similar
4. **Vector DB**: Deploy Qdrant server for persistent malware corpus
5. **CORS**: Restrict to your frontend domain
6. **Auth**: Add API key authentication middleware
7. **Limits**: Configure rate limiting per client

## Optional Tool Installation

| Tool | Installation |
|------|-------------|
| CAPA | `pip install capa` or binary from releases |
| FLOSS | Binary from GitHub releases |
| Speakeasy | `pip install speakeasy-emulator` |
| angr | `pip install angr` (large install ~2GB) |
| rizin | `brew install rizin` (macOS) / apt / choco |
| UPX | `brew install upx` / package manager |
