"""
ViGil Agent — Script MITRE ATT&CK Mapper
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
        role="Script MITRE ATT&CK Mapper",
        goal="Map script behavioral findings to MITRE ATT&CK techniques",
        backstory="MITRE ATT&CK framework specialist, mapping malicious operations directly to canonical technique matrices.",
        tools=[script_analyzer_tool],
        llm=llm,
        verbose=True,
        memory=True,
    )

def create_task(agent: Agent, context_data: dict) -> Task:
    return Task(
        description="""Correlate findings from all other agents and map them to MITRE ATT&CK technique IDs (e.g. T1059 Command and Scripting Interpreter). Context: {context_data}""",
        expected_output="A structured mapping of script actions to MITRE ATT&CK IDs.",
        agent=agent,
    )
