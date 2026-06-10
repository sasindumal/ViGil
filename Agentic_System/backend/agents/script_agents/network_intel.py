"""
ViGil Agent — Script Network Analyst
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
        role="Script Network Analyst",
        goal="Extract network IOCs, download links, webhooks, and communication APIs from scripts",
        backstory="Network forensic specialist focused on extracting C2 URLs, Discord webhooks, Telegram bot tokens, and HTTP requests in scripts.",
        tools=[script_analyzer_tool],
        llm=llm,
        verbose=True,
        memory=True,
    )

def create_task(agent: Agent, context_data: dict) -> Task:
    return Task(
        description="""Find and extract all network-related indicators, including API endpoints, download links, web client queries, or Discord/Telegram configurations. Context: {context_data}""",
        expected_output="A list of extracted network IOCs and their communication intent.",
        agent=agent,
    )
