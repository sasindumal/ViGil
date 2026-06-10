"""
ViGil Agent — Script Knowledge Writer
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
        role="Script Knowledge Writer",
        goal="Commit learned script patterns and IOCs to the system knowledge base",
        backstory="Knowledge graph manager, translating raw script findings into schema-structured JSON memory.",
        tools=[script_analyzer_tool],
        llm=llm,
        verbose=True,
        memory=True,
    )

def create_task(agent: Agent, context_data: dict) -> Task:
    return Task(
        description="""Commit the IOCs, techniques, and script findings to the permanent JSON knowledge base. Context: {context_data}""",
        expected_output="Confirmation of knowledge base update.",
        agent=agent,
    )
