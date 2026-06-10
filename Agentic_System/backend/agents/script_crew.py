"""
ViGil — Script Crew Orchestrator
================================

Orchestrates the 16 specialized CrewAI agents for analyzing malicious scripts
(PowerShell, JavaScript, VBScript, Batch, Python, HTA, etc.) along with the
shared report generator and knowledge writer.
"""

from __future__ import annotations

import json
import logging
from typing import Any, Optional

from crewai import Crew, Process

from backend.agents.llm_config import get_llm
from backend.agents.memory_manager import MemoryManager

# Import agent creators
import backend.agents.script_agents.language_id as language_id
import backend.agents.script_agents.deobfuscation as deobfuscation
import backend.agents.script_agents.behavior_analysis as behavior_analysis
import backend.agents.script_agents.network_intel as network_intel
import backend.agents.script_agents.credential_theft as credential_theft
import backend.agents.script_agents.persistence_analysis as persistence_analysis
import backend.agents.script_agents.priv_escalation as priv_escalation
import backend.agents.script_agents.lolbin_detection as lolbin_detection
import backend.agents.script_agents.vulnerability_discovery as vulnerability_discovery
import backend.agents.script_agents.secret_discovery as secret_discovery
import backend.agents.script_agents.ransomware_detection as ransomware_detection
import backend.agents.script_agents.supply_chain as supply_chain
import backend.agents.script_agents.mitre_mapper as mitre_mapper
import backend.agents.script_agents.threat_intel as threat_intel
import backend.agents.script_agents.risk_scoring as risk_scoring
import backend.agents.script_agents.knowledge_writer as knowledge_writer
import backend.agents.pe_agents.report_generator as report_generator

from backend.core.event_emitter import EventType

logger = logging.getLogger("vigil.agents.script_crew")


class ScriptAnalysisCrew:
    """Manages creation and execution of the Script threat analysis Crew."""

    def __init__(self, llm_config: Optional[dict] = None):
        self.llm = get_llm(llm_config)
        self.memory_mgr = MemoryManager()

        # Instantiate agents (9 to 24 + 8)
        self.agent_lang = language_id.create_agent(self.llm)
        self.agent_deobf = deobfuscation.create_agent(self.llm)
        self.agent_behavior = behavior_analysis.create_agent(self.llm)
        self.agent_network = network_intel.create_agent(self.llm)
        self.agent_creds = credential_theft.create_agent(self.llm)
        self.agent_persist = persistence_analysis.create_agent(self.llm)
        self.agent_priv = priv_escalation.create_agent(self.llm)
        self.agent_lolbin = lolbin_detection.create_agent(self.llm)
        self.agent_vuln = vulnerability_discovery.create_agent(self.llm)
        self.agent_secrets = secret_discovery.create_agent(self.llm)
        self.agent_ransom = ransomware_detection.create_agent(self.llm)
        self.agent_supply = supply_chain.create_agent(self.llm)
        self.agent_mitre = mitre_mapper.create_agent(self.llm)
        self.agent_threat = threat_intel.create_agent(self.llm)
        self.agent_risk = risk_scoring.create_agent(self.llm)
        self.agent_report = report_generator.create_agent(self.llm)
        self.agent_knowledge = knowledge_writer.create_agent(self.llm)

    async def run(
        self,
        script_content: str,
        file_path: str,
        event_emitter: Any = None,
        analysis_id: str = None
    ) -> dict[str, Any]:
        """Execute the script analysis crew.

        Parameters
        ----------
        script_content:
            The raw text content of the script file.
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

        # Instantiate tasks
        task_lang = language_id.create_task(self.agent_lang, context_str)
        task_deobf = deobfuscation.create_task(self.agent_deobf, context_str)
        task_behavior = behavior_analysis.create_task(self.agent_behavior, context_str)
        task_network = network_intel.create_task(self.agent_network, context_str)
        task_creds = credential_theft.create_task(self.agent_creds, context_str)
        task_persist = persistence_analysis.create_task(self.agent_persist, context_str)
        task_priv = priv_escalation.create_task(self.agent_priv, context_str)
        task_lolbin = lolbin_detection.create_task(self.agent_lolbin, context_str)
        task_vuln = vulnerability_discovery.create_task(self.agent_vuln, context_str)
        task_secrets = secret_discovery.create_task(self.agent_secrets, context_str)
        task_ransom = ransomware_detection.create_task(self.agent_ransom, context_str)
        task_supply = supply_chain.create_task(self.agent_supply, context_str)
        task_mitre = mitre_mapper.create_task(self.agent_mitre, context_str)
        task_threat = threat_intel.create_task(self.agent_threat, context_str)
        task_risk = risk_scoring.create_task(self.agent_risk, context_str)
        task_report = report_generator.create_task(self.agent_report, context_str)
        task_knowledge = knowledge_writer.create_task(self.agent_knowledge, context_str)

        tasks = [
            task_lang,
            task_deobf,
            task_behavior,
            task_network,
            task_creds,
            task_persist,
            task_priv,
            task_lolbin,
            task_vuln,
            task_secrets,
            task_ransom,
            task_supply,
            task_mitre,
            task_threat,
            task_risk,
            task_report,
            task_knowledge,
        ]

        agents = [
            self.agent_lang,
            self.agent_deobf,
            self.agent_behavior,
            self.agent_network,
            self.agent_creds,
            self.agent_persist,
            self.agent_priv,
            self.agent_lolbin,
            self.agent_vuln,
            self.agent_secrets,
            self.agent_ransom,
            self.agent_supply,
            self.agent_mitre,
            self.agent_threat,
            self.agent_risk,
            self.agent_report,
            self.agent_knowledge,
        ]

        # Fetch memory settings
        crew_mem_config = self.memory_mgr.get_crew_memory_config()

        crew = Crew(
            agents=agents,
            tasks=tasks,
            process=Process.sequential,
            verbose=True,
            **crew_mem_config
        )

        # Helper callback to stream progress
        if event_emitter and analysis_id:
            await event_emitter.emit_step(
                analysis_id=analysis_id,
                step="agents_analysis",
                event_type=EventType.STEP_STARTED,
                message="CrewAI Script Agents starting analysis...",
                progress=0.0
            )

        # Kickoff crew execution
        # We run inside the event loop executor to prevent blocking
        def run_crew():
            return crew.kickoff(inputs={"context_data": context_str})

        logger.info("Starting Script CrewAI execution...")
        crew_output = await asyncio.get_event_loop().run_in_executor(None, run_crew)
        logger.info("Script CrewAI execution completed.")

        # Extract results
        agent_outputs = {}
        for task in tasks:
            agent_role = task.agent.role
            if hasattr(task, "output") and task.output:
                agent_outputs[agent_role] = task.output.raw
            else:
                agent_outputs[agent_role] = "Task completed successfully."

        # The final report is the output of the task (report_generator)
        final_report = task_report.output.raw if hasattr(task_report, "output") and task_report.output else str(crew_output)

        # Parse verdict from risk scoring agent
        verdict = "BENIGN"
        confidence = 70.0
        risk_score = 15.0

        risk_output = agent_outputs.get(self.agent_risk.role, "").upper()
        # Heuristic checking of risk score output
        # If the risk analyzer flags severe threats, categorize as MALWARE
        if "CRITICAL" in risk_output or "HIGH" in risk_output or "MALWARE" in risk_output:
            verdict = "MALWARE"
            risk_score = 80.0
            confidence = 85.0
        elif "MEDIUM" in risk_output:
            verdict = "MALWARE"  # treat medium as suspicious/malware
            risk_score = 50.0
            confidence = 75.0

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
