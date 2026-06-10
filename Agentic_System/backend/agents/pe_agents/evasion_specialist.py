"""
ViGil Agent — Evasion & Obfuscation Specialist
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
        role="Evasion & Obfuscation Specialist",
        goal="Detect anti-analysis, anti-debug, VM detection, and evasion techniques",
        backstory="Former malware developer turned security researcher, expert in evasion techniques, sandbox bypasses, and control-flow obfuscation.",
        tools=[pe_analyzer_tool],
        llm=llm,
        verbose=True,
        memory=False,
    )

def create_task(agent: Agent, context_data: dict) -> Task:
    return Task(
        description="""Scan for anti-debugging APIs, timing check patterns (like rdtsc), VM detection markers, sandbox evasion tactics, and obfuscated/encrypted strings. Analyze control-flow indicators for flattening or indirect branches. Context data: {context_data}""",
        expected_output="An evasion and obfuscation report detail mapping evasion techniques and scoring the evasion probability.",
        agent=agent,
    )
