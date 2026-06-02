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
        """Called by CrewAI step_callback or task_callback to capture live thoughts/outputs."""
        timestamp = datetime.utcnow().isoformat()
        
        step_data = {
            "timestamp": timestamp,
            "agent": agent_name,
            "type": "step",
            "content": ""
        }
        
        # Extract fields from CrewAI AgentAction / AgentFinish or TaskOutput or string representations
        if hasattr(step_output, "raw"):
            step_data["content"] = getattr(step_output, "raw")
        elif hasattr(step_output, "thought"):
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

    def _on_task_completed(self, task_output):
        """Called by CrewAI when any task in the sequential crew completes."""
        agent_role = "Unknown Specialist"
        if hasattr(task_output, "agent") and task_output.agent:
            agent_role = getattr(task_output.agent, "role", str(task_output.agent))
            
        # Get raw output
        output_str = getattr(task_output, "raw", "") or str(task_output)
        
        # Log to local run files
        self.run_logger.log_agent_step(agent_role, task_output)
        
        # Stream via WebSocket as an agent step with final output populated
        if self.web_callback:
            self.web_callback("agent_step", {
                "agent": agent_role,
                "thought": "",
                "tool": "",
                "tool_input": "",
                "output": output_str
            })

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
        
        cpg_context_str = f"""
        IMPORTS METADATA:
        {metadata_str}
        
        STRINGS METADATA:
        {strings_str}
        
        CALLS & METHODS:
        {call_graph_str}
        
        SUBGRAPHS SAMPLES:
        {subgraphs_str}
        """

        # 1. Graph Pattern Task
        task_graph = Task(
            description=f"Examine call graph structure, imports, and strings, and identify known malicious graph motifs and sequence calls (e.g. OpenProcess -> VirtualAllocEx -> WriteProcessMemory -> CreateRemoteThread).\n\nCPG DATA:\n{cpg_context_str}",
            expected_output="Detailed graph pattern motifs found matching process injection or downloaders.",
            agent=agent_graph,
            context=[],
            llm=self.llm
        )

        # 2. Data Flow Task
        task_df = Task(
            description=f"Trace sensitive variable propagation, network-to-buffer decrypt logic, or registry-to-shellcode execution routes in the method subgraphs.\n\nCPG DATA:\n{cpg_context_str}",
            expected_output="Detailed data flow taint paths found.",
            agent=agent_df,
            context=[],
            llm=self.llm
        )

        # 3. Memory Manipulation Task
        task_mem = Task(
            description=f"Scan strictly for virtual memory manipulation APIs and indicators of process hollowing, reflective DLL loading, or APC injection.\n\nCPG DATA:\n{cpg_context_str}",
            expected_output="Highlights of virtual memory allocations and injection vectors.",
            agent=agent_mem,
            context=[],
            llm=self.llm
        )

        # 4. Anti-Analysis Task
        task_anti = Task(
            description=f"Scrutinize debugger evasion APIs, VM artifacts (CPUID, VMWare, VirtualBox), VBox indicators, and automated sandbox guest checks.\n\nCPG DATA:\n{cpg_context_str}",
            expected_output="Detailed anti-debugging, anti-VM, and anti-sandbox traits.",
            agent=agent_anti,
            context=[],
            llm=self.llm
        )

        # 5. Cryptography Task
        task_crypto = Task(
            description=f"Search for cryptographic library imports (AES, RC4, ChaCha20), classic XOR decryption loops, or custom ransomware file-traversal schemes.\n\nCPG DATA:\n{cpg_context_str}",
            expected_output="Identified string decryption routines or payload encryption ciphers.",
            agent=agent_crypto,
            context=[],
            llm=self.llm
        )

        # 6. Persistence Task
        task_persist = Task(
            description=f"Analyze persistent installation hooks including Run Keys, Scheduled Tasks, Windows Services, WMI hooks, COM hijacking, or DLL search order hijacking.\n\nCPG DATA:\n{cpg_context_str}",
            expected_output="Mapped boot-level persistence methods.",
            agent=agent_persist,
            context=[],
            llm=self.llm
        )

        # 7. Privilege Escalation Task
        task_priv = Task(
            description=f"Analyze credential token manipulation, SeDebugPrivilege token requests, driver loading (BYOVD), or UAC bypass flows.\n\nCPG DATA:\n{cpg_context_str}",
            expected_output="Discovered privilege escalation techniques.",
            agent=agent_priv,
            context=[],
            llm=self.llm
        )

        # 8. Network Behavior Task
        task_net = Task(
            description=f"Analyze socket imports, WinINet/WinHTTP traffic endpoints, C2 beaconing strings, and data exfiltration patterns.\n\nCPG DATA:\n{cpg_context_str}",
            expected_output="Identified socket setups, downloader URLs, and HTTP C2 channels.",
            agent=agent_net,
            context=[],
            llm=self.llm
        )

        # 9. Exploitation Task
        task_exploit = Task(
            description=f"Analyze ROP chains, stack pivots, shellcode, and exploit primitives in instruction subgraphs.\n\nCPG DATA:\n{cpg_context_str}",
            expected_output="Discovered exploitation behaviors.",
            agent=agent_exploit,
            context=[],
            llm=self.llm
        )

        # 10. Obfuscation & Packing Task
        task_obfusc = Task(
            description=f"Examine control flow flattening, opaque predicates, indirect call graphs, and packers (UPX, Themida, VMProtect).\n\nCPG DATA:\n{cpg_context_str}",
            expected_output="Detailed unpacking and de-obfuscation assessment.",
            agent=agent_obfusc,
            context=[],
            llm=self.llm
        )

        # 11. Behavioral Capability Task
        task_cap = Task(
            description=f"Infer dynamic sequential capabilities (e.g. Credential Theft) by mapping the program flow actions instead of raw API listings.\n\nCPG DATA:\n{cpg_context_str}",
            expected_output="Logical capabilities map.",
            agent=agent_cap,
            context=[],
            llm=self.llm
        )

        # 12. Embedded Artifact Task
        task_embed = Task(
            description=f"Dissect nested PE binaries, resource blocks, embedded certificates, and version metadata info.\n\nCPG DATA:\n{cpg_context_str}",
            expected_output="Embedded resources summary.",
            agent=agent_embed,
            context=[],
            llm=self.llm
        )

        # 13. MITRE Mapping Task
        task_mitre = Task(
            description=f"Review the specialists findings and map all identified behaviors to standard MITRE ATT&CK technique IDs with individual confidence scores.\n\nCPG DATA:\n{cpg_context_str}",
            expected_output="MITRE ATT&CK technique mapping summary.",
            agent=agent_mitre,
            context=[task_graph, task_df, task_mem, task_anti, task_crypto, task_persist, task_priv, task_net, task_exploit, task_obfusc, task_cap, task_embed],
            llm=self.llm
        )

        # 14. Similarity Task
        task_sim = Task(
            description=f"Review the specialists findings and compute similarity metrics against known malware family signatures (Lumma, Emotet, Qakbot, RedLine, DarkGate).\n\nCPG DATA:\n{cpg_context_str}",
            expected_output="Malware family similarity percentages.",
            agent=agent_sim,
            context=[task_graph, task_df, task_mem, task_anti, task_crypto, task_persist, task_priv, task_net, task_exploit, task_obfusc, task_cap, task_embed],
            llm=self.llm
        )

        # 15. Audit and Verification Task
        task_verify = Task(
            description=f"Audit every single claim made by the previous specialists. Cross-check each API call, sequence, and string behavior against literal imports, string logs, and CPG node definitions in the raw data. Remove or modify any claim that cannot be validated. Generate a verified claims trace table mapping claims to CPG Node IDs. Consolidate all verified findings, the MITRE mappings, and the malware family similarity scores into a single unified summary document.\n\nCPG DATA:\n{cpg_context_str}",
            expected_output="A fully audited and verified specialist findings summary containing the verified claims trace table, verified MITRE mappings, and verified malware family similarity scores.",
            agent=agent_verifier,
            context=[task_graph, task_df, task_mem, task_anti, task_crypto, task_persist, task_priv, task_net, task_exploit, task_obfusc, task_cap, task_embed, task_mitre, task_sim],
            llm=self.llm
        )

        # 16. Synthesis and Reporting Task
        task_synthesis = Task(
            description=f"""
            Synthesize all validated details into a premium technical brief.
            Compose the final report in standard Markdown formatting.
            The report must explicitly provide:
            1. **VERDICT**: [MALWARE or BENIGN] with absolute confidence metrics.
            2. **THREAT SCORE**: A rating from 0 (Benign) to 10 (Critical Threat).
            3. **KEY BEHAVIORS**: Clear logical highlights of what the program is built to do (evasion, network, credential theft).
            4. **EVIDENCES**: Specific node lists, strings, or library imports verified by the verification audit.
            5. **MITRE ATT&CK MATRIX**: Standard technique grid.
            6. **MALWARE SIMILARITY SCORE**: Matching percentages.
            
            IMPORTANT: For EVIDENCES, MITRE ATT&CK MATRIX, and MALWARE SIMILARITY SCORE, you MUST present the data as standard markdown tables with the following headers:
            - Evidence Table:
            | Claim | CPG Node ID / API / String | Status |
            | --- | --- | --- |
            | [Claim] | [Node/API/String] | Verified |
            
            - MITRE Table:
            | Technique ID | Technique Name | Confidence |
            | --- | --- | --- |
            | [ID like T1055] | [Name] | [Confidence like 90%] |
            
            - Similarity Table:
            | Family | Similarity Percentage |
            | --- | --- |
            | [Malware Family Name] | [Percentage like 85%] |
            
            Keep the styling clean and authoritative. Do not make claims that were not verified by the auditor.
            \n\nCPG DATA:\n{cpg_context_str}
            """,
            expected_output="The final executive markdown malware analysis report.",
            agent=agent_lead,
            context=[task_verify],
            llm=self.llm
        )

        # Build Crew
        crew = Crew(
            agents=[
                agent_graph, agent_df, agent_mem, agent_anti, agent_crypto, 
                agent_persist, agent_priv, agent_net, agent_mitre, agent_sim, 
                agent_exploit, agent_obfusc, agent_cap, agent_embed, agent_verifier, agent_lead
            ],
            tasks=[
                task_graph, task_df, task_mem, task_anti, task_crypto, 
                task_persist, task_priv, task_net, task_exploit, task_obfusc, 
                task_cap, task_embed, task_mitre, task_sim, task_verify, task_synthesis
            ],
            verbose=True,
            task_callback=self._on_task_completed
        )

        # Execute
        print(f"\n[!] CrewAI launched with 15 specialized agents. Processing analysis: {self.analysis_id}...")
        result = crew.kickoff()
        
        # Save output
        final_report = str(result)
        self.run_logger.save_final_report(final_report)
        
        return final_report
