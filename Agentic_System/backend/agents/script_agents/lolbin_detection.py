"""
ViGil Agent — Script LOLBin Abuse Analyst
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
        role="Script LOLBin Abuse Analyst",
        goal="Monitor and flag execution of legitimate system tools (LOLBins) like certutil, mshta, regsvr32",
        backstory="Defense engineer specializing in detecting Living-off-the-Land (LOLBins) abuse by malicious scripts.",
        tools=[script_analyzer_tool],
        llm=llm,
        verbose=True,
        memory=True,
    )

def create_task(agent: Agent, context_data: dict) -> Task:
    return Task(
        description="""Check the script for commands invoking powershell, cmd, certutil, mshta, regsvr32, wmic, or bitsadmin. Context: {context_data}""",
        expected_output="A log of LOLBin executions, their arguments, and abuse risk.",
        agent=agent,
    )
