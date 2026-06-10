"""
ViGil Agent — Script Privilege Escalation Specialist
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
        role="Script Privilege Escalation Specialist",
        goal="Identify UAC bypasses, token manipulation, or exploit attempts in scripts",
        backstory="Red teamer focused on OS internals, expert at spotting UAC bypass methods and privilege hijack techniques.",
        tools=[script_analyzer_tool],
        llm=llm,
        verbose=True,
        memory=True,
    )

def create_task(agent: Agent, context_data: dict) -> Task:
    return Task(
        description="""Examine the script for privilege escalation indicators, including fodhelper UAC bypasses, token impersonation, or registry hijacks. Context: {context_data}""",
        expected_output="A list of UAC bypass or privilege escalation methods identified.",
        agent=agent,
    )
