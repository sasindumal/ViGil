"""
ViGil Agent — Script Deobfuscator
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
        role="Script Deobfuscator",
        goal="Detect and decode Base64, hex, XOR, string concatenations, or nested evaluations in the script",
        backstory="Expert in malware deobfuscation, specializing in unpacking layered scripts, resolving string manipulation, and revealing hidden code.",
        tools=[script_analyzer_tool],
        llm=llm,
        verbose=True,
        memory=True,
    )

def create_task(agent: Agent, context_data: dict) -> Task:
    return Task(
        description="""Analyze the script for obfuscation patterns like Base64 encoding, hex strings, char replacements, or compression. Decode them to recover the primary payload. Context: {context_data}""",
        expected_output="The deobfuscated/decoded script contents, detailing the techniques detected.",
        agent=agent,
    )
