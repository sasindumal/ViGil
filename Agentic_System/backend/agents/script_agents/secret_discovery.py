"""
ViGil Agent — Script Secret Exposure Analyst
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
        role="Script Secret Exposure Analyst",
        goal="Find hardcoded passwords, API keys, private keys, or tokens in scripts",
        backstory="Secret scanner expert, capable of identifying high-entropy secret patterns, JWT tokens, AWS keys, and private key blocks.",
        tools=[script_analyzer_tool],
        llm=llm,
        verbose=True,
        memory=True,
    )

def create_task(agent: Agent, context_data: dict) -> Task:
    return Task(
        description="""Scan the script for hardcoded secrets, password constants, API keys, private certificates, or database credentials. Context: {context_data}""",
        expected_output="A list of exposed secrets with high-entropy ratings.",
        agent=agent,
    )
