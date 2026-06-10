"""
ViGil Agent — Script Credential Theft Specialist
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
        role="Script Credential Theft Specialist",
        goal="Detect credentials, cookies, LSASS dumping, or token theft patterns in script files",
        backstory="Security researcher expert in credential access methods, focusing on infostealers that target browsers, tokens, or system secrets.",
        tools=[script_analyzer_tool],
        llm=llm,
        verbose=True,
        memory=True,
    )

def create_task(agent: Agent, context_data: dict) -> Task:
    return Task(
        description="""Analyze the script for patterns targeting Chrome/Edge databases, Firefox cookies, Discord tokens, AWS keys, or Windows Credential Manager. Context: {context_data}""",
        expected_output="A report flagging potential credential theft behaviors and targeted assets.",
        agent=agent,
    )
