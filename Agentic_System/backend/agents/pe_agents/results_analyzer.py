"""
ViGil Agent — Results Analysis Coordinator
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
        role="Results Analysis Coordinator",
        goal="Synthesize findings from structural, import, network, evasion, and string analysts into a unified threat assessment",
        backstory="Senior threat analyst who correlates multiple technical data sources into actionable cyber threat intelligence.",
        tools=[pe_analyzer_tool],
        llm=llm,
        verbose=True,
        memory=True,
    )

def create_task(agent: Agent, context_data: dict) -> Task:
    return Task(
        description="""Review and correlate the outputs of the Structural, Import, Network, Evasion, and String analysts. Summarize the key findings, identify consensus or contradictions, and formulate a unified malware/benign threat verdict with supporting evidence. Context data: {context_data}""",
        expected_output="A synthesized threat assessment compiling evidence from all specialist agents and recommending a primary verdict.",
        agent=agent,
    )
