"""
ViGil Agent — Script Risk Scoring Specialist
"""

from __future__ import annotations

from crewai import Agent, Task
from crewai.tools import tool

@tool("custom_script_analyzer_tool")
def script_analyzer_tool(query: str) -> str:
    """Helper tool for custom script queries or lookup."""
    return f"Script query results for: {query}"

def create_agent(llm) -> Agent:
    return Agent(
        role="Script Risk Scoring Specialist",
        goal="Calculate overall script risk score (0-100) based on cumulative indicators",
        backstory="Quantitative risk modeler, specializing in threat scoring and risk-level categorization.",
        tools=[script_analyzer_tool],
        llm=llm,
        verbose=True,
        memory=True,
    )

def create_task(agent: Agent, context_data: dict) -> Task:
    return Task(
        description="""Compile findings from all script analysts. Compute a weighted risk score (0-100) based on severity of detected indicators and output severity category. Context: {context_data}""",
        expected_output="A risk score report containing final score, severity tier, and primary risk drivers.",
        agent=agent,
    )
