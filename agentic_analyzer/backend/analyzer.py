import os
import json
import logging
from pathlib import Path
from typing import Dict, Any, List, Callable, Optional
from datetime import datetime

from crewai import Agent, Task, Crew
from crewai.agents.parser import AgentAction, AgentFinish

from .config import Config

logger = logging.getLogger(__name__)

class RunLogger:
    """
    Handles persisting agent steps, thoughts, tool inputs, and tool outputs
    to unique run directories for testing, debugging, and audit logging.
    """
    def __init__(self, analysis_id: str):
        self.analysis_id = analysis_id
        self.run_dir = Path(__file__).resolve().parent.parent / "runs" / analysis_id
        self.run_dir.mkdir(parents=True, exist_ok=True)
        self.steps_file = self.run_dir / "steps.json"
        self.steps: List[Dict[str, Any]] = []
        
        # Write initial empty array
        self._save()

    def _save(self):
        with open(self.steps_file, "w", encoding="utf-8") as f:
            json.dump(self.steps, f, indent=2)

    def log_agent_step(self, agent_name: str, step_output: Any):
        """Called by CrewAI step_callback to capture live thoughts."""
        timestamp = datetime.utcnow().isoformat()
        
        step_data = {
            "timestamp": timestamp,
            "agent": agent_name,
            "type": "step",
            "content": ""
        }
        
        # Extract fields from CrewAI AgentAction / AgentFinish or string representations
        if hasattr(step_output, "thought"):
            step_data["thought"] = getattr(step_output, "thought")
        if hasattr(step_output, "tool"):
            step_data["tool"] = getattr(step_output, "tool")
        if hasattr(step_output, "tool_input"):
            step_data["tool_input"] = getattr(step_output, "tool_input")
        if hasattr(step_output, "result"):
            step_data["tool_result"] = getattr(step_output, "result")
        if hasattr(step_output, "output"):
            step_data["content"] = getattr(step_output, "output")
        else:
            step_data["content"] = str(step_output)
            
        # Format a gorgeous console notification matching standard logging
        print(f"\n[{timestamp}] 🤖 {agent_name} Thought/Action:")
        if "thought" in step_data and step_data["thought"]:
            print(f"  Thought: {step_data['thought']}")
        if "tool" in step_data and step_data["tool"]:
            print(f"  Tool Used: {step_data['tool']} | Input: {step_data.get('tool_input')}")
        if "tool_result" in step_data and step_data["tool_result"]:
            print(f"  Tool Result: {step_data['tool_result']}")
        if step_data["content"]:
            print(f"  Output: {step_data['content'][:500]}...")
        print("-" * 60)

        self.steps.append(step_data)
        self._save()
        
    def save_final_report(self, report: str):
        """Persists the final analyst report."""
        report_file = self.run_dir / "report.md"
        with open(report_file, "w", encoding="utf-8") as f:
            f.write(report)
        print(f"\n[✓] Final report persisted to: {report_file}\n")


class AgenticMalwareAnalyzer:
    """
    Agentic Malware Analyzer
    Initializes 15 specialized agents and orchestrates the CrewAI crew
    to perform verified deep static threat analysis.
    """
    def __init__(self, analysis_id: str, web_callback: Optional[Callable[[str, Dict[str, Any]], None]] = None):
        self.analysis_id = analysis_id
        self.web_callback = web_callback
        self.run_logger = RunLogger(analysis_id)
        self.llm = Config.get_llm()
        
        # Configure search tool if Tavily is set up
        self.tools = []
        if Config.TAVILY_API_KEY:
            from crewai_tools import TavilySearchResults
            os.environ["TAVILY_API_KEY"] = Config.TAVILY_API_KEY
            self.tools.append(TavilySearchResults())

    def _create_step_callback(self, agent_name: str):
        """Creates a localized callback for each agent to capture and stream steps."""
        def callback(step_output):
            # Log to local run files
            self.run_logger.log_agent_step(agent_name, step_output)
            
            # Extract basic data
            thought = ""
            tool = ""
            tool_input = ""
            output = ""
            
            if hasattr(step_output, "thought"):
                thought = getattr(step_output, "thought")
            if hasattr(step_output, "tool"):
                tool = getattr(step_output, "tool")
            if hasattr(step_output, "tool_input"):
                tool_input = getattr(step_output, "tool_input")
            if hasattr(step_output, "output"):
                output = getattr(step_output, "output")
            else:
                output = str(step_output)
                
            # If Web UI callback exists, stream it live via WebSocket
            if self.web_callback:
                self.web_callback("agent_step", {
                    "agent": agent_name,
                    "thought": thought,
                    "tool": tool,
                    "tool_input": tool_input,
                    "output": output
                })
        return callback

    def analyze(self, chunks: Dict[str, Any]) -> str:
        """Executes CrewAI collaborative reasoning over chunked CPGs."""
        
        # Serialize chunks cleanly so agents can reference the exact structures
        metadata_str = json.dumps(chunks["metadata"], indent=2)
        strings_str = json.dumps(chunks["strings"][:100], indent=2) # limit strings size for prompt safety
        call_graph_str = json.dumps(chunks["call_graph"][:150], indent=2) # limit call graph size
        
        # Format subgraphs overview
        subgraphs_summary = []
        for sg in chunks["behavioral_subgraphs"][:20]: # inspect first 20 methods
            subgraphs_summary.append({
                "method_name": sg["method_name"],
                "nodes_count": len(sg["nodes"]),
                "edges_count": len(sg["edges"]),
                "nodes": [{ "id": n["id"], "type": n["type"], "name": n["name"], "code": n.get("code", "") } for n in sg["nodes"][:15]]
            })
        subgraphs_str = json.dumps(subgraphs_summary, indent=2)

        # ----------------- Define Agents -----------------
        
        # 1. Graph Pattern Specialist
        agent_graph = Agent(
            role="Graph Pattern Specialist",
            goal="Identify known malicious graph motifs and sequence calls in AST/CFG representations.",
            backstory="An expert in graph theory and abstract syntax tree (AST) signatures. You spot processes injection, downloaders, and ransomware workflows directly from structural method trees.",
            verbose=True,
            allow_delegation=False,
            llm=self.llm,
            step_callback=self._create_step_callback("Graph Pattern Specialist")
        )

        # 2. Data Flow Specialist
        agent_df = Agent(
            role="Data Flow / Taint Analysis Specialist",
            goal="Track sensitive variable propagation and inputs flowing into sinks.",
            backstory="A compiler-level analyst tracking data dependencies. You follow network payloads decryption flows, memory staging, and exfiltration pathways.",
            verbose=True,
            allow_delegation=False,
            llm=self.llm,
            step_callback=self._create_step_callback("Data Flow Specialist")
        )

        # 3. Memory Specialist
        agent_mem = Agent(
            role="Memory Manipulation Specialist",
            goal="Scan for low-level memory allocation, write, and injection patterns.",
            backstory="A kernel-level operating systems engineer. You focus strictly on memory APIs (VirtualAllocEx, WriteProcessMemory, MapViewOfFile) to flag hollowed or injected shellcode.",
            verbose=True,
            allow_delegation=False,
            llm=self.llm,
            step_callback=self._create_step_callback("Memory Specialist")
        )

        # 4. Anti-Analysis Specialist
        agent_anti = Agent(
            role="Anti-Analysis Specialist",
            goal="Flag debugger, VM, sandbox, and emulation check hooks.",
            backstory="A reverse engineering specialist. You analyze binary traits specifically designed to break debuggers, trigger execution timing delays, and check for sandbox guest environments.",
            verbose=True,
            allow_delegation=False,
            llm=self.llm,
            step_callback=self._create_step_callback("Anti-Analysis Specialist")
        )

        # 5. Cryptography Specialist
        agent_crypto = Agent(
            role="Cryptography Specialist",
            goal="Identify encryption algorithms, standard ciphers, and XOR encoders.",
            backstory="A cryptographer expert. You detect AES, RC4, ChaCha20, string decryption logic, and custom file traversal loops characteristic of ransomware families.",
            verbose=True,
            allow_delegation=False,
            llm=self.llm,
            step_callback=self._create_step_callback("Cryptography Specialist")
        )

        # 6. Persistence Specialist
        agent_persist = Agent(
            role="Persistence Specialist",
            goal="Identify scheduled tasks, startup folder entries, and service hooks.",
            backstory="An expert in persistence mechanisms. You map how programs survive OS reboots using registry Run keys, scheduled tasks, WMI events, or COM hijacking.",
            verbose=True,
            allow_delegation=False,
            llm=self.llm,
            step_callback=self._create_step_callback("Persistence Specialist")
        )

        # 7. Privilege Escalation Specialist
        agent_priv = Agent(
            role="Privilege Escalation Specialist",
            goal="Detect privilege adjustments, token manipulation, and driver loads.",
            backstory="A threat hunter. You look for administrative elevation attempts, UAC bypass sequences, SeDebugPrivilege tokens, and BYOVD (Bring Your Own Vulnerable Driver) routines.",
            verbose=True,
            allow_delegation=False,
            llm=self.llm,
            step_callback=self._create_step_callback("Privilege Escalation Specialist")
        )

        # 8. Network Specialist
        agent_net = Agent(
            role="Network Behavior Specialist",
            goal="Analyze web socket, DNS, WinINet, and C2 communication mechanisms.",
            backstory="A network forensics analyst. You scrutinize socket setups, DNS requests, HTTP beacons, downloader endpoints, and C2 exfiltration routes.",
            verbose=True,
            allow_delegation=False,
            llm=self.llm,
            step_callback=self._create_step_callback("Network Specialist")
        )

        # 9. ATT&CK Mapping Specialist
        agent_mitre = Agent(
            role="ATT&CK Mapping Specialist",
            goal="Translate actions to precise MITRE ATT&CK techniques.",
            backstory="A threat intelligence expert specialized in framework mappings. You translate findings to standard MITRE IDs with corresponding confidence ratings.",
            verbose=True,
            allow_delegation=False,
            llm=self.llm,
            step_callback=self._create_step_callback("ATT&CK Mapping Specialist")
        )

        # 10. Malware Family Similarity Specialist
        agent_sim = Agent(
            role="Malware Family Similarity Specialist",
            goal="Determine percentage match against Emotet, Qakbot, Lumma, RedLine, and DarkGate.",
            backstory="A malware clustering analyst. You cross-reference imports, behavior trends, and unique indicator strings against established signatures of prominent malware families.",
            verbose=True,
            allow_delegation=False,
            llm=self.llm,
            step_callback=self._create_step_callback("Malware Similarity Specialist")
        )

        # 11. Vulnerability Exploitation Specialist
        agent_exploit = Agent(
            role="Vulnerability Exploitation Specialist",
            goal="Detect stack pivots, ROP structures, shellcode loaders, and exploit kits.",
            backstory="A vulnerability research engineer. You review method layouts looking for memory exploitation routines and assembly payload injection primitives.",
            verbose=True,
            allow_delegation=False,
            llm=self.llm,
            step_callback=self._create_step_callback("Exploitation Specialist")
        )

        # 12. Obfuscation & Packing Specialist
        agent_obfusc = Agent(
            role="Obfuscation & Packing Specialist",
            goal="Highlight Control Flow Flattening, opaque predicates, UPX, and VMProtect features.",
            backstory="A code protection researcher. You spot packing layers, compression wrappers, and control structures designed to obfuscate natural call graphs.",
            verbose=True,
            allow_delegation=False,
            llm=self.llm,
            step_callback=self._create_step_callback("Obfuscation/Packing Specialist")
        )

        # 13. Behavioral Capability Specialist
        agent_cap = Agent(
            role="Behavioral Capability Specialist",
            goal="Infer sequential functional capabilities (e.g. Credential Theft) over basic API lists.",
            backstory="A behavioral intelligence analyst. You abstract simple sequence actions into high-level capabilities, mapping out operational steps like data harvesting.",
            verbose=True,
            allow_delegation=False,
            llm=self.llm,
            step_callback=self._create_step_callback("Behavioral Capability Specialist")
        )

        # 14. Embedded Artifact Specialist
        agent_embed = Agent(
            role="Embedded Artifact Specialist",
            goal="Identify resources, certificates, nested binaries, and metadata.",
            backstory="A structure analyst. You dissect resource blocks, searching for nested executables, hidden payloads, custom icons, or untrusted digital certificates.",
            verbose=True,
            allow_delegation=False,
            llm=self.llm,
            step_callback=self._create_step_callback("Embedded Artifact Specialist")
        )

        # 15. LLM Evidence Verification Specialist
        agent_verifier = Agent(
            role="LLM Evidence Verification Specialist",
            goal="Audit draft findings to prevent hallucination, verifying each claim to a literal CPG node.",
            backstory="A rigorous academic investigator. Your sole responsibility is to audit draft assertions and verify them against actual nodes in the CPG to ensure bulletproof report accuracy.",
            verbose=True,
            allow_delegation=False,
            llm=self.llm,
            step_callback=self._create_step_callback("Evidence Verification Specialist")
        )

        # 16. Lead Malware Analyst
        agent_lead = Agent(
            role="Lead Malware Analyst",
            goal="Synthesize all specialist and audited findings into a premium executive report.",
            backstory="A principal threat analyst. You coordinate the specialist reports, verify claims with the auditor, and structure the definitive malware analysis brief.",
            verbose=True,
            allow_delegation=False,
            llm=self.llm,
            step_callback=self._create_step_callback("Lead Malware Analyst")
        )

        # ----------------- Define Tasks -----------------
        
        # Step 1: Broad specialist inspection
        task_specialists = Task(
            description=f"""
            Examine the CPG structure, imports, and strings:
            
            IMPORTS METADATA:
            {metadata_str}
            
            STRINGS METADATA:
            {strings_str}
            
            CALLS & METHODS:
            {call_graph_str}
            
            SUBGRAPHS SAMPLES:
            {subgraphs_str}
            
            Specialists must identify threats matching their roles:
            - Graph Pattern Specialist: malicious motifs (OpenProcess -> VirtualAllocEx -> WriteProcessMemory -> CreateRemoteThread)
            - Data Flow Specialist: taint tracking, decrypt loops
            - Memory Specialist: suspicious memory APIs (WriteProcessMemory, VirtualAlloc, etc.)
            - Anti-Analysis Specialist: sandbox/VM/debugger triggers (IsDebuggerPresent, CPUID, VBox)
            - Cryptography Specialist: crypto routines, XOR loops, ransomware behavior
            - Persistence Specialist: Run Keys, Scheduled Tasks, DLL Search Order Hijacking
            - Privilege Escalation Specialist: UAC bypass, debug privileges
            - Network Specialist: sockets, exfiltration, DNS C2 beacons
            - Exploitation Specialist: stack pivots, shellcode, ROP chains
            - Obfuscation Specialist: flattening, indirect calls, UPX/Themida packing indicators
            - Behavioral Specialist: sequence abstractions (Credential Theft, etc.)
            - Embedded Specialist: PE resources, certificates, nested binaries
            
            Synthesize your findings inside a draft report.
            """,
            expected_output="A structured draft report aggregating findings from all analysis specialists.",
            agents=[agent_graph, agent_df, agent_mem, agent_anti, agent_crypto, agent_persist, agent_priv, agent_net, agent_exploit, agent_obfusc, agent_cap, agent_embed],
            llm=self.llm
        )

        # Step 2: MITRE mapping & Malware similarity classification
        task_intel = Task(
            description="""
            Review the drafted reports. Apply advanced context mapping:
            - ATT&CK Mapping Specialist: Map verified behaviors to MITRE tactics (e.g. T1055, T1027) with individual confidence scores.
            - Malware Similarity Specialist: Evaluate similarity ratios to Lumma, Emotet, Qakbot, RedLine, and DarkGate.
            
            Incorporate these mappings and indicators directly into the draft report.
            """,
            expected_output="An expanded draft report with MITRE ATT&CK techniques mapped and malware family similarity ratios configured.",
            agents=[agent_mitre, agent_sim],
            llm=self.llm
        )

        # Step 3: Strict verification to prevent hallucinations
        task_verify = Task(
            description="""
            Audit the expanded draft report.
            LLM Evidence Verification Specialist: Check every single claim made by the specialists.
            Verify that any API call, sequence, or structural pattern correlates directly to actual structures (e.g., specific library calls or node definitions) present in the call graph chunk, metadata chunk, or subgraphs data.
            Generate a JSON-verifiable trace table mapping claims to node names/imports and mark them as verified. Remove or modify any claim that cannot be validated.
            """,
            expected_output="An audited findings draft containing a JSON trace table mapping each behavior claim to verified node targets.",
            agent=agent_verifier,
            llm=self.llm
        )

        # Step 4: Executive synthesis
        task_synthesis = Task(
            description="""
            Synthesize all validated details into a premium technical brief.
            Lead Malware Analyst: Compose the final malware report in standard Markdown formatting.
            The report must explicitly provide:
            1. **VERDICT**: [MALWARE or BENIGN] with absolute confidence metrics.
            2. **THREAT SCORE**: A rating from 0 (Benign) to 10 (Critical Threat).
            3. **KEY BEHAVIORS**: Clear logical highlights of what the program is built to do (evasion, network, credential theft).
            4. **EVIDENCES**: Specific node lists, strings, or library imports verified by the verification audit.
            5. **MITRE ATT&CK MATRIX**: Standard technique grid.
            6. **MALWARE SIMILARITY SCORE**: Matching percentages.
            
            Keep the styling clean and authoritative. Do not make claims that were not verified.
            """,
            expected_output="The final executive markdown malware analysis report.",
            agent=agent_lead,
            llm=self.llm
        )

        # Build Crew
        crew = Crew(
            agents=[
                agent_graph, agent_df, agent_mem, agent_anti, agent_crypto, 
                agent_persist, agent_priv, agent_net, agent_mitre, agent_sim, 
                agent_exploit, agent_obfusc, agent_cap, agent_embed, agent_verifier, agent_lead
            ],
            tasks=[task_specialists, task_intel, task_verify, task_synthesis],
            verbose=True
        )

        # Execute
        print(f"\n[!] CrewAI launched with 15 specialized agents. Processing analysis: {self.analysis_id}...")
        result = crew.kickoff()
        
        # Save output
        final_report = str(result)
        self.run_logger.save_final_report(final_report)
        
        return final_report
