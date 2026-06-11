"""
ViGil Agent — String & NLP Intelligence Analyst
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
        role="String & NLP Intelligence Analyst",
        goal="Extract semantic meaning from embedded strings to classify malware intent",
        backstory="NLP specialist in malware forensics, expert in extracting semantic intent from plain text and obfuscated string blobs in binaries.",
        tools=[pe_analyzer_tool],
        llm=llm,
        verbose=True,
        memory=False,
    )

def create_task(agent: Agent, context_data: dict) -> Task:
    return Task(
        description="""Process all extracted ASCII/Unicode strings. Search for base64 blobs, ransomware indicators (ransom note keywords, onion links), persistence paths, or command executions. Context data: {context_data}""",
        expected_output="A semantic string analysis detailing base64 decoding results, malware intent markers, and text-based findings.",
        agent=agent,
    )
