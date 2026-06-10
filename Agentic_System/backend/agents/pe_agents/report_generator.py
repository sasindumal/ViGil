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
        description="""Generate a structured markdown malware report based on the findings from all previous agents. Follow the template: Executive Summary, File Overview, Threat Classification, Detailed Analysis, Evidence Chain, Attack Narrative, IOCs, MITRE ATT&CK Mapping, and Recommendations. Context data: {context_data}""",
        expected_output="A complete, beautifully formatted markdown threat intelligence report matching the system template.",
        agent=agent,
    )
