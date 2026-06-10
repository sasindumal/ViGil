"""
ViGil — Script Crew Orchestrator (Single Agent)
================================================

Orchestrates a single senior script threat analyst agent to perform end-to-end
analysis and generate the final security report.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
from typing import Any, Optional

from crewai import Agent, Task, Crew, Process

from backend.agents.llm_config import get_llm
from backend.agents.memory_manager import MemoryManager
from backend.core.event_emitter import EventType

logger = logging.getLogger("vigil.agents.script_crew")


class ScriptAnalysisCrew:
    """Manages creation and execution of the simplified single-agent Script analysis pipeline."""

    def __init__(self, llm_config: Optional[dict] = None):
        self.llm = get_llm(llm_config)
        self.memory_mgr = MemoryManager()

        # Instantiate a single comprehensive script analyst agent
        self.agent = Agent(
            role="Universal Script Threat Analyst",
            goal="Analyze script source code (PowerShell, JavaScript, VBScript, Python, HTA, Batch) to discover obfuscation, credential theft, lolbin abuse, network indicators, evasion tricks, and generate a comprehensive security report.",
            backstory="You are a senior malware analyst specializing in script-based threats, command-and-control communication, and obfuscation techniques. You analyze script source code thoroughly, identify potential indicators of compromise (IOCs), map techniques to the MITRE ATT&CK framework, and write a unified, premium report with a clear verdict and risk score.",
            llm=self.llm,
            verbose=True,
            memory=True,
        )

    async def run(
        self,
        script_content: str,
        file_path: str,
        event_emitter: Any = None,
        analysis_id: str = None
    ) -> dict[str, Any]:
        """Execute the simplified script analysis crew.

        Parameters
        ----------
        script_content:
            The text content of the script file.
        file_path:
            The file name or path of the script.
        event_emitter:
            Optional event emitter for streaming agent steps.
        analysis_id:
            Optional unique ID of the analysis session.

        Returns
        -------
        dict
            Contains report markdown, individual agent outputs, and final verdict.
        """
        logger.info("Initializing Script analysis crew...")
        
        # Prepare context data
        context_str = json.dumps({
            "file_name": file_path,
            "script_content": script_content[:20000]  # truncate to prevent token limits
        }, default=str, indent=2)

        # Create a single task for the script analyst
        task = Task(
            description=f"""Analyze the following script file:
File Name: {file_path}
Script Content:
{script_content[:20000]}

Perform a comprehensive security analysis of this script:
1. Language & Obfuscation: Identify the script language and deobfuscate any encoded payloads (Base64, hex, XOR, etc.).
2. Suspicious Behaviors: Detect malicious patterns such as credential theft, LOLBin abuse, registry modifications, process injection, and networking/C2 connection strings (domains, URLs, IPs).
3. Persistence & Evasion: Flag indicators of persistence (e.g. startup registry entries, scheduled tasks) and VM/sandbox evasion tricks.
4. MITRE ATT&CK: Map all identified malicious behaviors to the MITRE ATT&CK framework.
5. Executive Assessment: Calculate a risk score (0 to 100) and provide a final verdict ("MALWARE" or "BENIGN") with confidence (0 to 100).

You must write a premium, modern, highly structured Markdown security report using this exact structure:

# THREAT INTELLIGENCE & FORENSICS REPORT

# VERDICT: MALWARE (or BENIGN)
## CONFIDENCE: <confidence>% | VIGIL THREAT MATRIX SCORE: <score>/100

---

## 1. Executive Summary
> [!WARNING] (or [!NOTE] if benign, [!CAUTION] if high danger malware)
> *Write a 3-4 sentence high-level executive summary of the script's nature, suspicious actions detected, and threat impact.*

## 2. File Metadata & Overview
Use a Markdown table:
| Property | Value |
| --- | --- |
| File Name | <filename> |
| File Size | <size> |
| Script Language | <e.g., PowerShell, JavaScript, Python> |
| Intent Category | <e.g., Trojan, Ransomware, Stealer, Downloader, Suspicious, Benign> |
| Danger Level | <Critical / High / Medium / Low / None> |

## 3. In-Depth Technical Analysis
### A. Code Analysis & Deobfuscation
Describe obfuscation techniques used (Base64, hex, XOR, string concatenation) and show deobfuscated payload snippets if found.

### B. Suspicious Behaviors & Persistence
Detail credential theft indicators, LOLBin abuse, registry updates, process injections, startup items, or scheduled tasks.

### C. Network & C2 Indicators (IOCs)
If none, state "No network indicators identified." Otherwise, use a Markdown table:
| Indicator Type | Value | Classification / Reputation |
| --- | --- | --- |
| <IP / Domain / URL / Hostname> | <value> | <Malicious / Suspicious / Action Required> |

## 4. MITRE ATT&CK Mapping
Use a Markdown table:
| Tactic | Technique ID | Technique Name | Evidence / Abuse Details |
| --- | --- | --- | --- |
| <Tactic name> | <e.g., T1059> | <Technique name> | <Specific script findings> |

## 5. Defensive Recommendations & Mitigation
List 3-4 actionable security recommendations or defensive measures.
""",
            expected_output="A comprehensive script security analysis report in Markdown format with a final verdict (MALWARE or BENIGN), risk score (0-100), and confidence percentage.",
            agent=self.agent,
        )

        # Fetch memory settings
        crew_mem_config = self.memory_mgr.get_crew_memory_config(self.llm, "script_analysis_crew")

        crew = Crew(
            agents=[self.agent],
            tasks=[task],
            process=Process.sequential,
            verbose=True,
            **crew_mem_config
        )

        # Setup callback to stream live progress to frontend via WebSocket
        loop = asyncio.get_event_loop()

        def task_callback(task_output):
            if event_emitter and analysis_id:
                raw_text = getattr(task_output, "raw", str(task_output))
                asyncio.run_coroutine_threadsafe(
                    event_emitter.emit_agent(
                        analysis_id=analysis_id,
                        agent_name=self.agent.role,
                        event_type=EventType.AGENT_COMPLETED,
                        message="Universal Script Threat Analyst completed analysis.",
                        data={"output": raw_text}
                    ),
                    loop
                )

        task.callback = task_callback

        # Helper callback to stream progress
        if event_emitter and analysis_id:
            await event_emitter.emit_step(
                analysis_id=analysis_id,
                step="agents_analysis",
                event_type=EventType.STEP_STARTED,
                message="CrewAI Script Analyst starting analysis...",
                progress=0.0
            )
            # Emit starting event for the analyst agent
            await event_emitter.emit_agent(
                analysis_id=analysis_id,
                agent_name=self.agent.role,
                event_type=EventType.AGENT_STARTED,
                message="Universal Script Threat Analyst starting script analysis...",
            )

        # Kickoff crew execution
        # We run inside the event loop executor to prevent blocking
        def run_crew():
            return crew.kickoff()

        logger.info("Starting Script CrewAI execution...")
        crew_output = await asyncio.get_event_loop().run_in_executor(None, run_crew)
        logger.info("Script CrewAI execution completed.")

        # Extract results
        final_report = crew_output.raw if hasattr(crew_output, "raw") else str(crew_output)
        agent_outputs = {
            self.agent.role: final_report
        }

        # Parse verdict, risk score, and confidence from final report
        verdict = "BENIGN"
        confidence = 80.0
        risk_score = 20.0

        report_upper = final_report.upper()
        if "VERDICT: MALWARE" in report_upper or "VERDICT**: MALWARE" in report_upper or "VERDICT**: MALWARE" in report_upper:
            verdict = "MALWARE"
            risk_score = 75.0
            confidence = 85.0
        elif "VERDICT: BENIGN" in report_upper or "VERDICT**: BENIGN" in report_upper or "VERDICT**: BENIGN" in report_upper:
            verdict = "BENIGN"
            risk_score = 15.0
            confidence = 90.0
        elif "MALWARE" in report_upper[:1500]:
            verdict = "MALWARE"
            risk_score = 70.0
            confidence = 80.0

        # Extract risk score and confidence if explicitly mentioned
        try:
            risk_match = re.search(r"(?:RISK\s*SCORE|MATRIX\s*SCORE|THREAT\s*MATRIX\s*SCORE)\s*\*?[:*]*\s*(\d+)", report_upper)
            if risk_match:
                risk_score = float(risk_match.group(1))
            conf_match = re.search(r"CONFIDENCE\s*\*?[:*]*\s*(\d+)", report_upper)
            if conf_match:
                confidence = float(conf_match.group(1))
        except Exception:
            pass

        if event_emitter and analysis_id:
            await event_emitter.emit_step(
                analysis_id=analysis_id,
                step="agents_analysis",
                event_type=EventType.STEP_COMPLETED,
                message="CrewAI script analysis complete.",
                progress=1.0,
                data={
                    "verdict": verdict,
                    "confidence": confidence,
                    "risk_score": risk_score,
                }
            )

        return {
            "verdict": verdict,
            "confidence": confidence,
            "risk_score": risk_score,
            "agent_outputs": agent_outputs,
            "report_markdown": final_report,
        }
