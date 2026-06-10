"""
ViGil Agent — Senior PE Structural Analyst
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
        role="Senior PE Structural Analyst",
        goal="Analyze PE file structure and detect anomalies indicating tampering or packing",
        backstory="Expert in Windows PE format with decades of reverse engineering experience. You can spot a packed or tampered binary from a mile away.",
        tools=[pe_analyzer_tool],
        llm=llm,
        verbose=True,
        memory=False,
    )

def create_task(agent: Agent, context_data: dict) -> Task:
    return Task(
        description="""Analyze the structural aspects of the PE file including headers, sections, entropy, and packer detection data. Flag anomalies like RWX sections, missing checksums, size mismatches, and known packing signatures. Context data: {context_data}""",
        expected_output="A detailed structural analysis report highlighting sections, entropy, packing indicators, and flagged anomalies.",
        agent=agent,
    )
