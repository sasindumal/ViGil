import os
from pathlib import Path

# Paths
AGENTIC_ROOT = Path("/Users/sasindumalhara/Workspace/ViGil/Agentic_System")
PE_AGENTS_DIR = AGENTIC_ROOT / "backend" / "agents" / "pe_agents"
SCRIPT_AGENTS_DIR = AGENTIC_ROOT / "backend" / "agents" / "script_agents"

PE_AGENTS_DIR.mkdir(parents=True, exist_ok=True)
SCRIPT_AGENTS_DIR.mkdir(parents=True, exist_ok=True)

# ---------------------------------------------------------------------------
# PE AGENTS (1 - 8)
# ---------------------------------------------------------------------------

pe_agents_spec = {
    "structural_analyst": {
        "role": "Senior PE Structural Analyst",
        "goal": "Analyze PE file structure and detect anomalies indicating tampering or packing",
        "backstory": "Expert in Windows PE format with decades of reverse engineering experience. You can spot a packed or tampered binary from a mile away.",
        "sees_model": False,
        "task_desc": "Analyze the structural aspects of the PE file including headers, sections, entropy, and packer detection data. Flag anomalies like RWX sections, missing checksums, size mismatches, and known packing signatures. Context data: {context_data}",
        "expected_output": "A detailed structural analysis report highlighting sections, entropy, packing indicators, and flagged anomalies."
    },
    "import_behavior": {
        "role": "API Import Behavior Analyst",
        "goal": "Classify imported APIs into behavior groups and predict file behavior from static imports",
        "backstory": "Expert in Windows API analysis, specializing in behavioral classification of imported functions and detecting API sequences used by malware.",
        "sees_model": False,
        "task_desc": "Examine the imported DLLs and API functions. Group them into behavior categories (process injection, execution, network, crypto, anti-analysis, persistence). Assess the presence of suspicious API patterns. Context data: {context_data}",
        "expected_output": "An import behavior assessment detailing classified APIs, suspicious call flows, and predicted runtime actions."
    },
    "network_intel": {
        "role": "Network Intelligence Analyst",
        "goal": "Detect communication patterns, C2 infrastructure, and network-based indicators",
        "backstory": "Cybersecurity intelligence specialist with expertise in C2 infrastructure analysis, domain generation algorithms (DGA), and extraction of network indicators.",
        "sees_model": False,
        "task_desc": "Search and extract all network-related indicators from the strings and metadata. Check for IP addresses, URLs, domains, email addresses, and look for C2 command patterns or DGA-like naming conventions. Context data: {context_data}",
        "expected_output": "A network intelligence report listing IOCs, reputation indicators, and potential command-and-control signatures."
    },
    "evasion_specialist": {
        "role": "Evasion & Obfuscation Specialist",
        "goal": "Detect anti-analysis, anti-debug, VM detection, and evasion techniques",
        "backstory": "Former malware developer turned security researcher, expert in evasion techniques, sandbox bypasses, and control-flow obfuscation.",
        "sees_model": False,
        "task_desc": "Scan for anti-debugging APIs, timing check patterns (like rdtsc), VM detection markers, sandbox evasion tactics, and obfuscated/encrypted strings. Analyze control-flow indicators for flattening or indirect branches. Context data: {context_data}",
        "expected_output": "An evasion and obfuscation report detail mapping evasion techniques and scoring the evasion probability."
    },
    "string_nlp": {
        "role": "String & NLP Intelligence Analyst",
        "goal": "Extract semantic meaning from embedded strings to classify malware intent",
        "backstory": "NLP specialist in malware forensics, expert in extracting semantic intent from plain text and obfuscated string blobs in binaries.",
        "sees_model": False,
        "task_desc": "Process all extracted ASCII/Unicode strings. Search for base64 blobs, ransomware indicators (ransom note keywords, onion links), persistence paths, or command executions. Context data: {context_data}",
        "expected_output": "A semantic string analysis detailing base64 decoding results, malware intent markers, and text-based findings."
    },
    "results_analyzer": {
        "role": "Results Analysis Coordinator",
        "goal": "Synthesize findings from structural, import, network, evasion, and string analysts into a unified threat assessment",
        "backstory": "Senior threat analyst who correlates multiple technical data sources into actionable cyber threat intelligence.",
        "sees_model": False,
        "task_desc": "Review and correlate the outputs of the Structural, Import, Network, Evasion, and String analysts. Summarize the key findings, identify consensus or contradictions, and formulate a unified malware/benign threat verdict with supporting evidence. Context data: {context_data}",
        "expected_output": "A synthesized threat assessment compiling evidence from all specialist agents and recommending a primary verdict."
    },
    "model_comparator": {
        "role": "ML Model & Agent Consensus Analyst",
        "goal": "Compare ML model prediction with agent analysis to reach a final authoritative verdict",
        "backstory": "Data scientist specializing in ensemble methods and model-human consensus, balancing machine learning confidence with analyst reasoning.",
        "sees_model": True,
        "task_desc": "Compare the ML model prediction (label, confidence, variance) with the Results Coordinator's verdict. Resolve any disagreements. If the model has high variance, rely more on structural/evasion findings. Output a final authoritative verdict, confidence score, and clear logic. Context data: {context_data}",
        "expected_output": "A consensus report resolving machine vs. agent findings, with a final authoritative verdict and confidence score."
    },
    "report_generator": {
        "role": "Senior Threat Intelligence Report Writer",
        "goal": "Generate comprehensive, executive-ready malware analysis reports",
        "backstory": "Technical writer with deep cybersecurity expertise, producing detailed reports for security operations center (SOC) teams and executives.",
        "sees_model": True,
        "task_desc": "Generate a structured markdown malware report based on the findings from all previous agents. Follow the template: Executive Summary, File Overview, Threat Classification, Detailed Analysis, Evidence Chain, Attack Narrative, IOCs, MITRE ATT&CK Mapping, and Recommendations. Context data: {context_data}",
        "expected_output": "A complete, beautifully formatted markdown threat intelligence report matching the system template."
    }
}

for name, spec in pe_agents_spec.items():
    file_path = PE_AGENTS_DIR / f"{name}.py"
    content = f'''"""
ViGil Agent — {spec["role"]}
"""

from __future__ import annotations

from crewai import Agent, Task
from crewai.tools import tool

@tool("custom_pe_analyzer_tool")
def pe_analyzer_tool(query: str) -> str:
    """Helper tool for custom PE queries or lookup."""
    return f"PE query results for: {{query}}"

def create_agent(llm) -> Agent:
    return Agent(
        role="{spec["role"]}",
        goal="{spec["goal"]}",
        backstory="{spec["backstory"]}",
        tools=[pe_analyzer_tool],
        llm=llm,
        verbose=True,
        memory=True,
    )

def create_task(agent: Agent, context_data: dict) -> Task:
    return Task(
        description="""{spec["task_desc"]}""",
        expected_output="{spec["expected_output"]}",
        agent=agent,
    )
'''
    with open(file_path, "w") as f:
        f.write(content)

print("Generated 8 PE Agents successfully.")
