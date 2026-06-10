"""
ViGil Agent — Script Persistence Analyst
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
        role="Script Persistence Analyst",
        goal="Identify registry run keys, scheduled tasks, startup folder drops, or service creation in scripts",
        backstory="Expert in OS persistence mechanisms, identifying how scripts try to survive reboots and system cleanup.",
        tools=[script_analyzer_tool],
        llm=llm,
        verbose=True,
        memory=True,
    )

def create_task(agent: Agent, context_data: dict) -> Task:
    return Task(
        description="""Scan the script for registry modifications (Run/RunOnce keys), task scheduler commands (schtasks), startup folder file creations, or service configurations. Context: {context_data}""",
        expected_output="A mapping of persistence methods identified in the script.",
        agent=agent,
    )
