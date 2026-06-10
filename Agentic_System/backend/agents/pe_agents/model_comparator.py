"""
ViGil Agent — ML Model & Agent Consensus Analyst
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
        role="ML Model & Agent Consensus Analyst",
        goal="Compare ML model prediction with agent analysis to reach a final authoritative verdict",
        backstory="Data scientist specializing in ensemble methods and model-human consensus, balancing machine learning confidence with analyst reasoning.",
        tools=[pe_analyzer_tool],
        llm=llm,
        verbose=True,
        memory=False,
    )

def create_task(agent: Agent, context_data: dict) -> Task:
    return Task(
        description="""Compare the ML model prediction (label, confidence, variance) with the Results Coordinator's verdict. Resolve any disagreements. If the model has high variance, rely more on structural/evasion findings. Output a final authoritative verdict, confidence score, and clear logic. Context data: {context_data}""",
        expected_output="A consensus report resolving machine vs. agent findings, with a final authoritative verdict and confidence score.",
        agent=agent,
    )
