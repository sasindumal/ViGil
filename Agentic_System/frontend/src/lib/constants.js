export const PIPELINE_STEPS = [
  { id: 'initialization', label: 'Initialization', icon: 'ShieldAlert' },
  { id: 'routing', label: 'Identification', icon: 'FileSearch' },
  { id: 'extraction', label: 'Extraction', icon: 'FolderArchive' },
  { id: 'pe_analysis', label: 'Deep PE Parsing', icon: 'Cpu' },
  { id: 'ml_prediction', label: 'ML Prediction', icon: 'Binary' },
  { id: 'agents_analysis', label: 'Agent Consensus', icon: 'Users' },
  { id: 'complete', label: 'Report Ready', icon: 'FileSpreadsheet' }
];

export const AGENT_ROLES = {
  // PE Agents
  "Senior PE Structural Analyst": { color: "#00d4ff", number: 1, type: "pe" },
  "API Import Behavior Analyst": { color: "#8b5cf6", number: 2, type: "pe" },
  "Network Intelligence Analyst": { color: "#00ff88", number: 3, type: "pe" },
  "Evasion & Obfuscation Specialist": { color: "#ffb800", number: 4, type: "pe" },
  "String & NLP Intelligence Analyst": { color: "#ff3366", number: 5, type: "pe" },
  "Results Analysis Coordinator": { color: "#a855f7", number: 6, type: "pe" },
  "ML Model & Agent Consensus Analyst": { color: "#3b82f6", number: 7, type: "pe" },
  "Senior Threat Intelligence Report Writer": { color: "#10b981", number: 8, type: "shared" },
  "Universal Script Threat Analyst": { color: "#10b981", number: 9, type: "script" },

  // Script Agents
  "Script Language Identifier": { color: "#00d4ff", number: 9, type: "script" },
  "Script Deobfuscator": { color: "#8b5cf6", number: 10, type: "script" },
  "Script Behavioral Analyst": { color: "#00ff88", number: 11, type: "script" },
  "Script Network Analyst": { color: "#ffb800", number: 12, type: "script" },
  "Script Credential Theft Specialist": { color: "#ff3366", number: 13, type: "script" },
  "Script Persistence Analyst": { color: "#f59e0b", number: 14, type: "script" },
  "Script Privilege Escalation Specialist": { color: "#ec4899", number: 15, type: "script" },
  "Script LOLBin Abuse Analyst": { color: "#06b6d4", number: 16, type: "script" },
  "Script Vulnerability Discovery Specialist": { color: "#f43f5e", number: 17, type: "script" },
  "Script Secret Exposure Analyst": { color: "#14b8a6", number: 18, type: "script" },
  "Script Ransomware Specialist": { color: "#ef4444", number: 19, type: "script" },
  "Script Supply Chain Inspector": { color: "#84cc16", number: 20, type: "script" },
  "Script MITRE ATT&CK Mapper": { color: "#a855f7", number: 21, type: "script" },
  "Script Threat Intel Analyst": { color: "#6366f1", number: 22, type: "script" },
  "Script Risk Scoring Specialist": { color: "#3b82f6", number: 23, type: "script" },
  "Script Knowledge Writer": { color: "#10b981", number: 24, type: "script" }
};
