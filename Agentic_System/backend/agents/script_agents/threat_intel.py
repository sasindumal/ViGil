"""
ViGil Agent — Script Threat Intel Analyst
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
        role="Script Threat Intel Analyst",
        goal="Correlate script IOCs with known malware campaigns and threat groups",
        backstory="Cyber threat intelligence (CTI) analyst, correlating IPs, domains, and code signatures with known APT groups and campaigns.",
        tools=[script_analyzer_tool],
        llm=llm,
        verbose=True,
        memory=True,
    )

def create_task(agent: Agent, context_data: dict) -> Task:
    return Task(
        description="""Compare extracted indicators (URLs, domains, code snippets) with threat intelligence signatures and campaigns. Context: {context_data}""",
        expected_output="A CTI briefing linking findings to known malware families or actor groups.",
        agent=agent,
    )
