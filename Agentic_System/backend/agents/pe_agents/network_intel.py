"""
ViGil Agent — Network Intelligence Analyst
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
        role="Network Intelligence Analyst",
        goal="Detect communication patterns, C2 infrastructure, and network-based indicators",
        backstory="Cybersecurity intelligence specialist with expertise in C2 infrastructure analysis, domain generation algorithms (DGA), and extraction of network indicators.",
        tools=[pe_analyzer_tool],
        llm=llm,
        verbose=True,
        memory=False,
    )

def create_task(agent: Agent, context_data: dict) -> Task:
    return Task(
        description="""Search and extract all network-related indicators from the strings and metadata. Check for IP addresses, URLs, domains, email addresses, and look for C2 command patterns or DGA-like naming conventions. Context data: {context_data}""",
        expected_output="A network intelligence report listing IOCs, reputation indicators, and potential command-and-control signatures.",
        agent=agent,
    )
