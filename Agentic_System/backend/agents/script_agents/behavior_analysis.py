"""
ViGil Agent — Script Behavioral Analyst
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
        role="Script Behavioral Analyst",
        goal="Predict runtime actions of the script from static source code analysis",
        backstory="Static code analyst specializing in pattern matching and abstract syntax tree heuristics to predict script execution patterns.",
        tools=[script_analyzer_tool],
        llm=llm,
        verbose=True,
        memory=True,
    )

def create_task(agent: Agent, context_data: dict) -> Task:
    return Task(
        description="""Analyze the script behavior, such as file drops, process creation, registry modifications, or execution of other commands. Context: {context_data}""",
        expected_output="A list of predicted behavioral actions with severity ratings.",
        agent=agent,
    )
