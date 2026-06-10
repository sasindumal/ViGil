"""
ViGil Agent — Senior Threat Intelligence Report Writer
"""

from __future__ import annotations

from crewai import Agent, Task
from crewai.tools import tool

@tool("custom_pe_analyzer_tool")
def pe_analyzer_tool(query: str) -> str:
    """Helper tool for custom PE queries or lookup."""
    return f"PE query results for: {query}"

def create_agent(llm) -> Agent:
    return Agent(
        role="Senior Threat Intelligence Report Writer",
        goal="Generate comprehensive, executive-ready malware analysis reports",
        backstory="Technical writer with deep cybersecurity expertise, producing detailed reports for security operations center (SOC) teams and executives.",
        tools=[pe_analyzer_tool],
        llm=llm,
        verbose=True,
        memory=True,
    )

def create_task(agent: Agent, context_data: dict) -> Task:
    return Task(
        description="""Generate a premium, modern, highly structured Markdown threat intelligence report based on the findings from all previous agents. 

Use the following exact structure and style:

# THREAT INTELLIGENCE & FORENSICS REPORT

## 1. Executive Summary
> [!WARNING] (or [!NOTE] if benign, [!CAUTION] if high danger malware)
> **VERDICT**: MALWARE (or BENIGN) | **RISK SCORE**: <score>/100 | **CONFIDENCE**: <confidence>%
> 
> *Write a 3-4 sentence high-level executive summary of the file nature, major threats detected, and impact.*

## 2. File Metadata & Overview
Use a Markdown table:
| Property | Value |
| --- | --- |
| File Name | <filename> |
| SHA256 Hash | <hash> |
| File Size | <size> |
| Format / Language | <e.g., PE32 executable, Python script> |
| Danger Level | <Critical / High / Medium / Low / None> |

## 3. Consensus & Logic Chain
- **Machine Learning Predictor**: <Verdict, confidence, and feature importance highlights>
- **Security Agent Swarm Consensus**: <Consensus verdict and reasoning details>
- **Orchestrator Synthesis**: <Summary explanation of final aggregated verdict decision>

## 4. In-Depth Technical Analysis
### A. Static Forensics & Indicators
Describe critical imports, section anomalies, high entropy levels, or suspicious resource entries.

### B. Evasion & Anti-Analysis Detection
Detail packers detected, anti-debugging tricks, VM/sandbox detection routines, or code obfuscation.

### C. Network & C2 Indicators (IOCs)
If none, state "No network indicators identified." Otherwise, use a Markdown table:
| Indicator Type | Value | Classification / Reputation |
| --- | --- | --- |
| <IP / Domain / URL / Registry / File Path> | <value> | <Malicious / Suspicious / Action Required> |

## 5. MITRE ATT&CK Mapping
Use a Markdown table:
| Tactic | Technique ID | Technique Name | Evidence / Abuse Details |
| --- | --- | --- | --- |
| <Tactic name> | <e.g., T1059> | <Technique name> | <Specific findings in this file> |

## 6. Defensive Recommendations & Mitigation
List 3-4 actionable security recommendations or defensive measures.

Context data: {context_data}""",
        expected_output="A complete, beautifully formatted markdown threat intelligence report matching the modern system template.",
        agent=agent,
    )
