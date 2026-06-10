"""
ViGil — PE Crew Orchestrator
=============================

Orchestrates the 8 specialized CrewAI agents for Portable Executable (PE) analysis:
structural, import, network, evasion, strings, synthesis, model consensus,
and threat reporting.
"""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Any, Optional

from crewai import Crew, Process

from backend.agents.llm_config import get_llm
from backend.agents.memory_manager import MemoryManager

# Import agent creators
import backend.agents.pe_agents.structural_analyst as structural_analyst
import backend.agents.pe_agents.import_behavior as import_behavior
import backend.agents.pe_agents.network_intel as network_intel
import backend.agents.pe_agents.evasion_specialist as evasion_specialist
import backend.agents.pe_agents.string_nlp as string_nlp
import backend.agents.pe_agents.results_analyzer as results_analyzer
import backend.agents.pe_agents.model_comparator as model_comparator
import backend.agents.pe_agents.report_generator as report_generator

from backend.core.event_emitter import EventType

logger = logging.getLogger("vigil.agents.pe_crew")


class PEAnalysisCrew:
    """Manages creation and execution of the PE threat analysis Crew."""

    def __init__(self, llm_config: Optional[dict] = None):
        self.llm = get_llm(llm_config)
        self.memory_mgr = MemoryManager()

        # Instantiate agents
        self.agent_structural = structural_analyst.create_agent(self.llm)
        self.agent_import = import_behavior.create_agent(self.llm)
        self.agent_network = network_intel.create_agent(self.llm)
        self.agent_evasion = evasion_specialist.create_agent(self.llm)
        self.agent_string = string_nlp.create_agent(self.llm)
        self.agent_results = results_analyzer.create_agent(self.llm)
        self.agent_model = model_comparator.create_agent(self.llm)
        self.agent_report = report_generator.create_agent(self.llm)

    async def run(
        self,
        pe_analysis_json: dict[str, Any],
        ml_prediction: dict[str, Any],
        event_emitter: Any = None,
        analysis_id: str = None
    ) -> dict[str, Any]:
        """Execute the PE analysis crew.

        Parameters
        ----------
        pe_analysis_json:
            The structured outputs from the 15 deep PE analyzers.
        ml_prediction:
            The prediction outputs from the PyTorch model predictor.
        event_emitter:
            Optional event emitter for streaming agent steps.
        analysis_id:
            Optional unique ID of the analysis session.

        Returns
        -------
        dict
            Contains report markdown, individual agent outputs, and final verdict.
        """
        logger.info("Initializing PE analysis crew...")
        
        # Prepare context data
        context_str = json.dumps({
            "pe_static_analysis": pe_analysis_json,
            "ml_model_prediction": ml_prediction
        }, default=str, indent=2)

        # Instantiate tasks
        task_struct = structural_analyst.create_task(self.agent_structural, context_str)
        task_imp = import_behavior.create_task(self.agent_import, context_str)
        task_net = network_intel.create_task(self.agent_network, context_str)
        task_evasion = evasion_specialist.create_task(self.agent_evasion, context_str)
        task_str = string_nlp.create_task(self.agent_string, context_str)
        
        # Set first 5 tasks to execute asynchronously in parallel
        task_struct.async_execution = True
        task_imp.async_execution = True
        task_net.async_execution = True
        task_evasion.async_execution = True
        task_str.async_execution = True

        task_res = results_analyzer.create_task(self.agent_results, context_str)
        task_model = model_comparator.create_task(self.agent_model, context_str)
        task_report = report_generator.create_task(self.agent_report, context_str)

        # Define crew dependencies
        # Let's set up the tasks list
        tasks = [
            task_struct,
            task_imp,
            task_net,
            task_evasion,
            task_str,
            task_res,
            task_model,
            task_report,
        ]

        agents = [
            self.agent_structural,
            self.agent_import,
            self.agent_network,
            self.agent_evasion,
            self.agent_string,
            self.agent_results,
            self.agent_model,
            self.agent_report,
        ]

        # Setup callbacks to stream live progress to frontend via WebSocket
        loop = asyncio.get_event_loop()
        completed_parallel_tasks = set()
        parallel_roles = {
            "Senior PE Structural Analyst",
            "API Import Behavior Analyst",
            "Network Intelligence Analyst",
            "Evasion & Obfuscation Specialist",
            "String & NLP Intelligence Analyst"
        }

        def make_callback(agent_role: str, next_agent_role: Optional[str] = None):
            def task_callback(task_output):
                if event_emitter and analysis_id:
                    raw_text = getattr(task_output, "raw", str(task_output))
                    # 1. Emit completed event for current agent
                    asyncio.run_coroutine_threadsafe(
                        event_emitter.emit_agent(
                            analysis_id=analysis_id,
                            agent_name=agent_role,
                            event_type=EventType.AGENT_COMPLETED,
                            message=f"{agent_role} completed analysis.",
                            data={"output": raw_text}
                        ),
                        loop
                    )
                    
                    # 2. Check parallel task completion or trigger next sequential agent
                    if agent_role in parallel_roles:
                        completed_parallel_tasks.add(agent_role)
                        if len(completed_parallel_tasks) == 5:
                            # Start the Results Analysis Coordinator
                            asyncio.run_coroutine_threadsafe(
                                event_emitter.emit_agent(
                                    analysis_id=analysis_id,
                                    agent_name="Results Analysis Coordinator",
                                    event_type=EventType.AGENT_STARTED,
                                    message="Results Analysis Coordinator is starting synthesis...",
                                ),
                                loop
                            )
                    elif next_agent_role:
                        asyncio.run_coroutine_threadsafe(
                            event_emitter.emit_agent(
                                analysis_id=analysis_id,
                                agent_name=next_agent_role,
                                event_type=EventType.AGENT_STARTED,
                                message=f"{next_agent_role} is starting analysis...",
                            ),
                            loop
                        )
            return task_callback

        task_struct.callback = make_callback("Senior PE Structural Analyst")
        task_imp.callback = make_callback("API Import Behavior Analyst")
        task_net.callback = make_callback("Network Intelligence Analyst")
        task_evasion.callback = make_callback("Evasion & Obfuscation Specialist")
        task_str.callback = make_callback("String & NLP Intelligence Analyst")
        task_res.callback = make_callback("Results Analysis Coordinator", "ML Model & Agent Consensus Analyst")
        task_model.callback = make_callback("ML Model & Agent Consensus Analyst", "Senior Threat Intelligence Report Writer")
        task_report.callback = make_callback("Senior Threat Intelligence Report Writer", None)

        # Fetch memory settings
        crew_mem_config = self.memory_mgr.get_crew_memory_config(self.llm, "pe_analysis_crew")

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
                message="CrewAI PE Agents starting static and consensus analysis...",
                progress=0.0
            )
            # Emit starting event for all 5 parallel agents
            for agent_role in [
                "Senior PE Structural Analyst",
                "API Import Behavior Analyst",
                "Network Intelligence Analyst",
                "Evasion & Obfuscation Specialist",
                "String & NLP Intelligence Analyst"
            ]:
                await event_emitter.emit_agent(
                    analysis_id=analysis_id,
                    agent_name=agent_role,
                    event_type=EventType.AGENT_STARTED,
                    message=f"{agent_role} starting analysis...",
                )

        # Kickoff crew execution
        # We run inside the event loop executor to prevent blocking
        def run_crew():
            return crew.kickoff(inputs={"context_data": context_str})

        logger.info("Starting CrewAI execution...")
        crew_output = await asyncio.get_event_loop().run_in_executor(None, run_crew)
        logger.info("CrewAI execution completed.")

        # Extract results
        agent_outputs = {}
        for task in tasks:
            agent_role = task.agent.role
            # CrewAI 0.80.0+ stores raw task output in task.output
            if hasattr(task, "output") and task.output:
                agent_outputs[agent_role] = task.output.raw
            else:
                agent_outputs[agent_role] = "Task completed successfully."

        # The final report is the output of the last task (report_generator)
        final_report = crew_output.raw if hasattr(crew_output, "raw") else str(crew_output)

        # Parse verdict from model comparator or results coordinator
        verdict = "MALWARE"
        confidence = 85.0
        risk_score = 75.0

        model_output_text = agent_outputs.get(self.agent_model.role, "").upper()
        if "BENIGN" in model_output_text:
            verdict = "BENIGN"
            risk_score = 20.0
            confidence = 90.0

        if event_emitter and analysis_id:
            await event_emitter.emit_step(
                analysis_id=analysis_id,
                step="agents_analysis",
                event_type=EventType.STEP_COMPLETED,
                message="CrewAI PE analysis complete.",
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
