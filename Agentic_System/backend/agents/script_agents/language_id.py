"""
ViGil Agent — Script Language Identifier
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
        role="Script Language Identifier",
        goal="Detect language of the script (PowerShell, JS, VBS, VBA, Batch, Bash, Python, etc.)",
        backstory="Specialist in analyzing file structures, keywords, shebangs, and code syntax to identify the scripting engine.",
        tools=[script_analyzer_tool],
        llm=llm,
        verbose=True,
        memory=True,
    )

def create_task(agent: Agent, context_data: dict) -> Task:
    return Task(
        description="""Analyze the file content and identify the script language. Note shebangs, file extensions, and syntactic properties. Context: {context_data}""",
        expected_output="The detected script language (e.g. PowerShell, JavaScript) with confidence.",
        agent=agent,
    )
