import operator
import os
import json
from typing import Annotated, TypedDict
from dotenv import load_dotenv
from langchain_core.messages import HumanMessage
from langgraph.graph import StateGraph, START, END
from langgraph.checkpoint.memory import MemorySaver

# Load environment variables from .env
load_dotenv()

from agents import get_planner_agent, get_coder_agent, get_checker_agent

# Define the State for the main graph
class GraphState(TypedDict):
    resume_text: str
    plan: str
    final_code: str
    output_dir: str
    provider: str
    model: str
    error_feedback: str
    retry_count: int
    verification_status: str

def planner_node(state: GraphState):
    """Invokes the planner agent to generate a website plan."""
    print("\n==================== PLANNER NODE ====================")
    resume_text = state.get("resume_text", "")
    provider = state.get("provider")
    model = state.get("model")
    
    input_message = HumanMessage(content=f"Please analyze this resume and create a detailed website plan:\n\n{resume_text}")
    
    planner_agent = get_planner_agent(use_tools=True, provider=provider, model_name=model)
    final_message = ""
    for event in planner_agent.stream({"messages": [input_message]}, {"recursion_limit": 100}):
        for node_name, update in event.items():
            if "messages" in update:
                for msg in update["messages"]:
                    if node_name == "agent":
                        if msg.content:
                            print(msg.content)
                        if msg.tool_calls:
                            for tc in msg.tool_calls:
                                print(f"\n🔧 [Calling Tool] {tc['name']} -> Args: {tc['args']}")
                    elif node_name == "tools":
                        print(f"📥 [Tool Response] {msg.content}\n")
                    
                    if node_name == "agent" and msg.content:
                        final_message = msg.content
                        
    return {"plan": final_message}

def coder_node(state: GraphState):
    """Invokes the coder agent to generate website code based on the plan."""
    print("\n==================== CODER NODE ====================")
    resume_text = state.get("resume_text", "")
    plan = state.get("plan", "")
    output_dir = state.get("output_dir", "output")
    provider = state.get("provider")
    model = state.get("model")
    error_feedback = state.get("error_feedback")
    
    coder_agent = get_coder_agent(output_dir=output_dir, use_tools=True, provider=provider, model_name=model)
    required_files = ["index.html"]
    final_message = ""
    
    # Run the coder in a loop until all files exist and any errors are addressed
    for attempt in range(4):
        # Check missing files
        missing_files = []
        for f in required_files:
            if not os.path.exists(os.path.join(output_dir, f)):
                missing_files.append(f)
                
        # Only break if all files exist AND we have no pending build errors to fix in this coder node entry
        if not missing_files and not error_feedback:
            print(f"✅ All required files {required_files} exist in '{output_dir}' and no error feedback to address.")
            break
            
        # Build prompt focusing on missing files or build errors
        if error_feedback:
            print(f"⚠️ Checker reported issues: {error_feedback}. Invoking coder agent to fix them (Attempt {attempt+1}/4)...")
            prompt = (
                f"Resume Data:\n{resume_text}\n\nWebsite Plan:\n{plan}\n\n"
                f"⚠️ CRITICAL: The previous code generation failed verification with the following error:\n{error_feedback}\n\n"
                "Please read the generated index.html file (using read_file), find the syntax errors or incomplete sections (like unclosed tags, missing styles, etc.), and fix them using the edit_file or write_file tool."
            )
            # Clear error feedback for subsequent iterations of this node run loop
            error_feedback = ""
        elif attempt == 0:
            print(f"⚠️ Missing required files in '{output_dir}': {missing_files}. Invoking coder agent (Attempt {attempt+1}/4)...")
            prompt = f"Resume Data:\n{resume_text}\n\nWebsite Plan:\n{plan}\n\nPlease generate and write the production-ready code for this portfolio website to the disk. You MUST write a single self-contained `index.html` file containing the HTML structure, CSS styling in a <style> block, and JS logic in a <script> block."
        else:
            print(f"⚠️ Missing required files in '{output_dir}': {missing_files}. Invoking coder agent (Attempt {attempt+1}/4)...")
            prompt = (
                f"Resume Data:\n{resume_text}\n\nWebsite Plan:\n{plan}\n\n"
                f"Currently, the output folder is missing the required file: {missing_files}.\n"
                "Please generate the index.html file containing all HTML, CSS, and JS, and write it to the disk using your write_file tool.\n"
                "Do NOT explain your code or write plans. Output only the necessary tool call/code and proceed."
            )
            
        input_message = HumanMessage(content=prompt)
        
        final_message = ""
        for event in coder_agent.stream({"messages": [input_message]}, {"recursion_limit": 100}):
            for node_name, update in event.items():
                if "messages" in update:
                    for msg in update["messages"]:
                        if node_name == "agent":
                            if msg.content:
                                print(msg.content)
                            if msg.tool_calls:
                                for tc in msg.tool_calls:
                                    print(f"\n🔧 [Calling Tool] {tc['name']} -> Args: {tc['args']}")
                        elif node_name == "tools":
                            print(f"📥 [Tool Response] {msg.content}\n")
                        
                        if node_name == "agent" and msg.content:
                            final_message = msg.content
                            
        # Always run the fallback parser on the final code output to ensure any output files are written
        if final_message:
            print("\n✏️ Parsing output for files to write to disk...")
            from tools import parse_and_write_files
            parsed_files = parse_and_write_files(final_message, output_dir)
            if parsed_files:
                print(f"✅ Successfully extracted and wrote {len(parsed_files)} file(s) to output directory '{output_dir}':")
                for pf in parsed_files:
                    print(f"  - {pf}")
                    
    return {"final_code": final_message}

def checker_node(state: GraphState):
    """Invokes the checker agent to test the project in the sandbox."""
    print("\n==================== CHECKER NODE ====================")
    plan = state.get("plan", "")
    output_dir = state.get("output_dir", "output")
    provider = state.get("provider")
    model = state.get("model")
    retry_count = state.get("retry_count", 0)
    
    # We pass instructions to the checker agent to run verification
    prompt = (
        f"Website Plan:\n{plan}\n\n"
        f"Please inspect the generated portfolio project located in the output directory: '{output_dir}'. "
        "Use your file tools to: "
        "1. List the files in the directory to confirm that 'index.html' is present and that there are no external files like 'styles.css' or 'main.js'. "
        "2. Read the contents of 'index.html' using your read_file tool. "
        "3. Review the code to verify that: "
        "   - It fully implements the planned design direction, layout structures (e.g. Bento grid or responsive flexbox/grid), sections, color palettes, animations, and interactive features (e.g. mobile menu, dark-mode toggle, scroll reveals, active navigation indicators, glassmorphic UI). "
        "   - It is a premium, modern, and production-ready website, not a basic or generic placeholder page. "
        "   - It is complete (no placeholders or TODOs), contains all CSS in a <style> block and JS in a <script> block, and is free of syntax errors (e.g. missing brackets, unclosed HTML tags, unclosed parenthesis, or incorrect syntax). "
        "Analyze all outputs. If there are any errors, missing features, generic designs, or issues, produce a detailed report of the issues. "
        "If everything is complete, correct, and matches the plan, respond with 'VERIFICATION SUCCESSFUL'."
    )
    
    input_message = HumanMessage(content=prompt)
    
    checker_agent = get_checker_agent(output_dir=output_dir, use_tools=True, provider=provider, model_name=model)
    final_message = ""
    for event in checker_agent.stream({"messages": [input_message]}, {"recursion_limit": 100}):
        for node_name, update in event.items():
            if "messages" in update:
                for msg in update["messages"]:
                    if node_name == "agent":
                        if msg.content:
                            print(msg.content)
                        if msg.tool_calls:
                            for tc in msg.tool_calls:
                                print(f"\n🔧 [Calling Tool] {tc['name']} -> Args: {tc['args']}")
                    elif node_name == "tools":
                        print(f"📥 [Tool Response] {msg.content}\n")
                    
                    if node_name == "agent" and msg.content:
                        final_message = msg.content

    # Determine status based on checker agent output
    if "VERIFICATION SUCCESSFUL" in final_message:
        print("\n✅ Checker Agent: Project starts and runs successfully!")
        return {
            "error_feedback": "",
            "verification_status": "success",
            "retry_count": retry_count
        }
    else:
        print("\n❌ Checker Agent: Project validation failed.")
        return {
            "error_feedback": final_message,
            "verification_status": "fail",
            "retry_count": retry_count + 1
        }

def should_continue(state: GraphState):
    """Determines whether the graph should continue running or finish."""
    if state.get("verification_status") == "success":
        print("\n✅ Verification succeeded! Code compiles and builds without errors.")
        return END
    
    retries = state.get("retry_count", 0)
    if retries >= 3:
        print("\n❌ Verification failed after 3 retries. Terminating workflow.")
        return END
        
    print(f"\n🔄 Build validation failed. Retrying code generation (Attempt {retries + 1}/3)...")
    return "coder"


# Build the Graph
workflow = StateGraph(GraphState)

workflow.add_node("planner", planner_node)
workflow.add_node("coder", coder_node)
workflow.add_node("checker", checker_node)

workflow.add_edge(START, "planner")
workflow.add_edge("planner", "coder")
workflow.add_edge("coder", "checker")

# Add conditional edge from checker
workflow.add_conditional_edges(
    "checker",
    should_continue,
    {
        "coder": "coder",
        END: END
    }
)

# Compile
app = workflow.compile()

