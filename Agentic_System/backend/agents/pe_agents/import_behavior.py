"""
ViGil Agent — API Import Behavior Analyst
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
        role="API Import Behavior Analyst",
        goal="Classify imported APIs into behavior groups and predict file behavior from static imports",
        backstory="Expert in Windows API analysis, specializing in behavioral classification of imported functions and detecting API sequences used by malware.",
        tools=[pe_analyzer_tool],
        llm=llm,
        verbose=True,
        memory=True,
    )

def create_task(agent: Agent, context_data: dict) -> Task:
    return Task(
        description="""Examine the imported DLLs and API functions. Group them into behavior categories (process injection, execution, network, crypto, anti-analysis, persistence). Assess the presence of suspicious API patterns. Context data: {context_data}""",
        expected_output="An import behavior assessment detailing classified APIs, suspicious call flows, and predicted runtime actions.",
        agent=agent,
    )
