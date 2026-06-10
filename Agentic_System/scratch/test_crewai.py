import sys
from pathlib import Path
from crewai import Agent, Task, Crew

# Configure dummy LLM or just run task initialization/interpolation test
agent = Agent(
    role="Test Analyst",
    goal="Test description formatting",
    backstory="Tester",
    allow_delegation=False,
    verbose=True
)

task = Task(
    description="This contains curly braces: {foo} and {bar}.",
    expected_output="Test output",
    agent=agent
)

crew = Crew(
    agents=[agent],
    tasks=[task],
    verbose=True
)

print("Kicking off with empty/no inputs...")
try:
    crew.kickoff()
    print("Success without inputs!")
except Exception as e:
    print(f"Failed without inputs: {type(e).__name__}: {e}")
