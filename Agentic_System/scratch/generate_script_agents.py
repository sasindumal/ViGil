import os
from pathlib import Path

AGENTIC_ROOT = Path("/Users/sasindumalhara/Workspace/ViGil/Agentic_System")
SCRIPT_AGENTS_DIR = AGENTIC_ROOT / "backend" / "agents" / "script_agents"
SCRIPT_AGENTS_DIR.mkdir(parents=True, exist_ok=True)

script_agents_spec = {
    "language_id": {
        "role": "Script Language Identifier",
        "goal": "Detect language of the script (PowerShell, JS, VBS, VBA, Batch, Bash, Python, etc.)",
        "backstory": "Specialist in analyzing file structures, keywords, shebangs, and code syntax to identify the scripting engine.",
        "task_desc": "Analyze the file content and identify the script language. Note shebangs, file extensions, and syntactic properties. Context: {context_data}",
        "expected_output": "The detected script language (e.g. PowerShell, JavaScript) with confidence."
    },
    "deobfuscation": {
        "role": "Script Deobfuscator",
        "goal": "Detect and decode Base64, hex, XOR, string concatenations, or nested evaluations in the script",
        "backstory": "Expert in malware deobfuscation, specializing in unpacking layered scripts, resolving string manipulation, and revealing hidden code.",
        "task_desc": "Analyze the script for obfuscation patterns like Base64 encoding, hex strings, char replacements, or compression. Decode them to recover the primary payload. Context: {context_data}",
        "expected_output": "The deobfuscated/decoded script contents, detailing the techniques detected."
    },
    "behavior_analysis": {
        "role": "Script Behavioral Analyst",
        "goal": "Predict runtime actions of the script from static source code analysis",
        "backstory": "Static code analyst specializing in pattern matching and abstract syntax tree heuristics to predict script execution patterns.",
        "task_desc": "Analyze the script behavior, such as file drops, process creation, registry modifications, or execution of other commands. Context: {context_data}",
        "expected_output": "A list of predicted behavioral actions with severity ratings."
    },
    "network_intel": {
        "role": "Script Network Analyst",
        "goal": "Extract network IOCs, download links, webhooks, and communication APIs from scripts",
        "backstory": "Network forensic specialist focused on extracting C2 URLs, Discord webhooks, Telegram bot tokens, and HTTP requests in scripts.",
        "task_desc": "Find and extract all network-related indicators, including API endpoints, download links, web client queries, or Discord/Telegram configurations. Context: {context_data}",
        "expected_output": "A list of extracted network IOCs and their communication intent."
    },
    "credential_theft": {
        "role": "Script Credential Theft Specialist",
        "goal": "Detect credentials, cookies, LSASS dumping, or token theft patterns in script files",
        "backstory": "Security researcher expert in credential access methods, focusing on infostealers that target browsers, tokens, or system secrets.",
        "task_desc": "Analyze the script for patterns targeting Chrome/Edge databases, Firefox cookies, Discord tokens, AWS keys, or Windows Credential Manager. Context: {context_data}",
        "expected_output": "A report flagging potential credential theft behaviors and targeted assets."
    },
    "persistence_analysis": {
        "role": "Script Persistence Analyst",
        "goal": "Identify registry run keys, scheduled tasks, startup folder drops, or service creation in scripts",
        "backstory": "Expert in OS persistence mechanisms, identifying how scripts try to survive reboots and system cleanup.",
        "task_desc": "Scan the script for registry modifications (Run/RunOnce keys), task scheduler commands (schtasks), startup folder file creations, or service configurations. Context: {context_data}",
        "expected_output": "A mapping of persistence methods identified in the script."
    },
    "priv_escalation": {
        "role": "Script Privilege Escalation Specialist",
        "goal": "Identify UAC bypasses, token manipulation, or exploit attempts in scripts",
        "backstory": "Red teamer focused on OS internals, expert at spotting UAC bypass methods and privilege hijack techniques.",
        "task_desc": "Examine the script for privilege escalation indicators, including fodhelper UAC bypasses, token impersonation, or registry hijacks. Context: {context_data}",
        "expected_output": "A list of UAC bypass or privilege escalation methods identified."
    },
    "lolbin_detection": {
        "role": "Script LOLBin Abuse Analyst",
        "goal": "Monitor and flag execution of legitimate system tools (LOLBins) like certutil, mshta, regsvr32",
        "backstory": "Defense engineer specializing in detecting Living-off-the-Land (LOLBins) abuse by malicious scripts.",
        "task_desc": "Check the script for commands invoking powershell, cmd, certutil, mshta, regsvr32, wmic, or bitsadmin. Context: {context_data}",
        "expected_output": "A log of LOLBin executions, their arguments, and abuse risk."
    },
    "vulnerability_discovery": {
        "role": "Script Vulnerability Discovery Specialist",
        "goal": "Identify common software vulnerabilities like command injection, SQL injection, or path traversal",
        "backstory": "Static application security testing (SAST) specialist, expert in spotting insecure coding practices in scripting languages.",
        "task_desc": "Analyze the script for insecure input handling, command injection, path traversal, SQL injection, or unsafe deserialization. Context: {context_data}",
        "expected_output": "A list of code vulnerabilities found, with severity and code snippet references."
    },
    "secret_discovery": {
        "role": "Script Secret Exposure Analyst",
        "goal": "Find hardcoded passwords, API keys, private keys, or tokens in scripts",
        "backstory": "Secret scanner expert, capable of identifying high-entropy secret patterns, JWT tokens, AWS keys, and private key blocks.",
        "task_desc": "Scan the script for hardcoded secrets, password constants, API keys, private certificates, or database credentials. Context: {context_data}",
        "expected_output": "A list of exposed secrets with high-entropy ratings."
    },
    "ransomware_detection": {
        "role": "Script Ransomware Specialist",
        "goal": "Detect bulk file encryption, shadow copy deletion, or ransomware notes in scripts",
        "backstory": "Anti-ransomware engineer, expert in identifying bulk file locking commands and shadow copy deletion (vssadmin).",
        "task_desc": "Analyze the script for bulk file access, callouts to crypto libraries (AES/RSA), deletion of backups/shadow copies, or embedded ransom notes. Context: {context_data}",
        "expected_output": "A summary of ransomware indicators and encryption intents."
    },
    "supply_chain": {
        "role": "Script Supply Chain Inspector",
        "goal": "Inspect script dependencies and library imports for vulnerable or malicious packages",
        "backstory": "Software supply chain engineer, specialized in detecting package typosquatting, malicious dependencies, and insecure repository endpoints.",
        "task_desc": "Analyze script imports, require statements, or command lines downloading libraries (pip install, npm install) for malicious package indicators. Context: {context_data}",
        "expected_output": "A dependency audit flagging potentially compromised libraries."
    },
    "mitre_mapper": {
        "role": "Script MITRE ATT&CK Mapper",
        "goal": "Map script behavioral findings to MITRE ATT&CK techniques",
        "backstory": "MITRE ATT&CK framework specialist, mapping malicious operations directly to canonical technique matrices.",
        "task_desc": "Correlate findings from all other agents and map them to MITRE ATT&CK technique IDs (e.g. T1059 Command and Scripting Interpreter). Context: {context_data}",
        "expected_output": "A structured mapping of script actions to MITRE ATT&CK IDs."
    },
    "threat_intel": {
        "role": "Script Threat Intel Analyst",
        "goal": "Correlate script IOCs with known malware campaigns and threat groups",
        "backstory": "Cyber threat intelligence (CTI) analyst, correlating IPs, domains, and code signatures with known APT groups and campaigns.",
        "task_desc": "Compare extracted indicators (URLs, domains, code snippets) with threat intelligence signatures and campaigns. Context: {context_data}",
        "expected_output": "A CTI briefing linking findings to known malware families or actor groups."
    },
    "risk_scoring": {
        "role": "Script Risk Scoring Specialist",
        "goal": "Calculate overall script risk score (0-100) based on cumulative indicators",
        "backstory": "Quantitative risk modeler, specializing in threat scoring and risk-level categorization.",
        "task_desc": "Compile findings from all script analysts. Compute a weighted risk score (0-100) based on severity of detected indicators and output severity category. Context: {context_data}",
        "expected_output": "A risk score report containing final score, severity tier, and primary risk drivers."
    },
    "knowledge_writer": {
        "role": "Script Knowledge Writer",
        "goal": "Commit learned script patterns and IOCs to the system knowledge base",
        "backstory": "Knowledge graph manager, translating raw script findings into schema-structured JSON memory.",
        "task_desc": "Commit the IOCs, techniques, and script findings to the permanent JSON knowledge base. Context: {context_data}",
        "expected_output": "Confirmation of knowledge base update."
    }
}

for name, spec in script_agents_spec.items():
    file_path = SCRIPT_AGENTS_DIR / f"{name}.py"
    content = f'''"""
ViGil Agent — {spec["role"]}
"""

from __future__ import annotations

from crewai import Agent, Task
from crewai.tools import tool

@tool("custom_script_analyzer_tool")
def script_analyzer_tool(query: str) -> str:
    """Helper tool for custom script queries or lookup."""
    return f"Script query results for: {{query}}"

def create_agent(llm) -> Agent:
    return Agent(
        role="{spec["role"]}",
        goal="{spec["goal"]}",
        backstory="{spec["backstory"]}",
        tools=[script_analyzer_tool],
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

print("Generated 16 Script Agents successfully.")
