"""
ViGil Agent — Script Supply Chain Inspector
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
        role="Script Supply Chain Inspector",
        goal="Inspect script dependencies and library imports for vulnerable or malicious packages",
        backstory="Software supply chain engineer, specialized in detecting package typosquatting, malicious dependencies, and insecure repository endpoints.",
        tools=[script_analyzer_tool],
        llm=llm,
        verbose=True,
        memory=True,
    )

def create_task(agent: Agent, context_data: dict) -> Task:
    return Task(
        description="""Analyze script imports, require statements, or command lines downloading libraries (pip install, npm install) for malicious package indicators. Context: {context_data}""",
        expected_output="A dependency audit flagging potentially compromised libraries.",
        agent=agent,
    )
