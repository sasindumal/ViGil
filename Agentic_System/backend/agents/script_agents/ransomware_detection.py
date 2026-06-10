"""
ViGil Agent — Script Ransomware Specialist
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
        role="Script Ransomware Specialist",
        goal="Detect bulk file encryption, shadow copy deletion, or ransomware notes in scripts",
        backstory="Anti-ransomware engineer, expert in identifying bulk file locking commands and shadow copy deletion (vssadmin).",
        tools=[script_analyzer_tool],
        llm=llm,
        verbose=True,
        memory=True,
    )

def create_task(agent: Agent, context_data: dict) -> Task:
    return Task(
        description="""Analyze the script for bulk file access, callouts to crypto libraries (AES/RSA), deletion of backups/shadow copies, or embedded ransom notes. Context: {context_data}""",
        expected_output="A summary of ransomware indicators and encryption intents.",
        agent=agent,
    )
