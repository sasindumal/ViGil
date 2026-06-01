import { useState, useEffect, useRef } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { motion, AnimatePresence } from 'framer-motion'
import { CheckCircle, XCircle, Loader, Shield, Clock, ChevronRight, Brain, Cpu } from 'lucide-react'
import api from '../api'
import './Analysis.css'

// ─── Agent pipeline definition (matches backend AGENTS list) ────────────────
const ALL_AGENTS = [
  // Phase 1 — Deterministic tools
  { name: 'Sample Intake',         desc: 'PE validation, hashes, metadata',              phase: 1 },
  { name: 'Static Analysis',       desc: 'Imports, sections, strings, entropy',          phase: 1 },
  { name: 'Unpacking',             desc: 'Packer detection, multi-stage unpacking',      phase: 1 },
  { name: 'Capability Detection',  desc: 'CAPA — credential theft, injection, ransomware', phase: 1 },
  { name: 'CFG Extraction',        desc: 'Control flow graph, call graph',               phase: 1 },
  { name: 'Threat Intelligence',   desc: 'VirusTotal, MalwareBazaar, OTX',              phase: 1 },
  { name: 'Evasion Detection',     desc: 'Anti-VM, anti-debug, API obfuscation',         phase: 1 },
  { name: 'Emulation Analysis',    desc: 'Speakeasy behavioral emulation (60s limit)',   phase: 1 },
  { name: 'Similarity Analysis',   desc: 'Family similarity embeddings (FAISS)',          phase: 1 },
  { name: 'Family Clustering',     desc: 'HDBSCAN cluster assignment',                  phase: 1 },
  { name: 'MITRE ATT&CK Mapping', desc: 'Technique coverage mapping',                  phase: 1 },
  { name: 'YARA Generation',       desc: 'Auto-generated hunting rules',                phase: 1 },
  { name: 'ATT&CK Navigator Export', desc: 'Navigator layer JSON',                     phase: 1 },
  { name: 'STIX Export',           desc: 'STIX 2.1 bundle generation',                  phase: 1 },
  // Phase 2 — CrewAI agentic reasoning
  { name: '[AI] Static PE Analyst',    desc: 'LLM reasons over PE structure & entropy', phase: 2 },
  { name: '[AI] Behavioral Analyst',   desc: 'LLM interprets emulation & evasion',      phase: 2 },
  { name: '[AI] Threat Intel Analyst', desc: 'LLM attributes family & threat actor',    phase: 2 },
  { name: '[AI] Verdict Analyst',      desc: 'LLM synthesizes evidence → verdict',      phase: 2 },
  { name: '[AI] Report Writer',        desc: 'LLM produces executive summary',          phase: 2 },
  // Phase 3 — Final assembly
  { name: 'Report Generation',    desc: 'Final report assembly',                        phase: 3 },
]

const STATUS_ICON = {
  pending:   <div className="agent-pending-dot" />,
  started:   <Loader size={16} className="agent-spinner" />,
  completed: <CheckCircle size={16} className="text-success" />,
  failed:    <XCircle size={16} className="text-danger" />,
}

const PHASE_LABELS = {
  1: { label: 'Phase 1 — Evidence Collection', icon: <Cpu size={12} /> },
  2: { label: 'Phase 2 — AI Reasoning (CrewAI)', icon: <Brain size={12} /> },
  3: { label: 'Phase 3 — Report Assembly', icon: <CheckCircle size={12} /> },
}

export default function AnalysisPage() {
  const { jobId } = useParams()
  const navigate = useNavigate()
  const wsRef = useRef(null)

  const [agentStatuses, setAgentStatuses] = useState(
    ALL_AGENTS.reduce((acc, a, i) => ({ ...acc, [i]: { status: 'pending', message: '', result: null } }), {})
  )
  const [currentAgent, setCurrentAgent] = useState(-1)
  const [jobStatus, setJobStatus] = useState('running')
  const [filename, setFilename] = useState('')
  const [startTime] = useState(Date.now())
  const [elapsed, setElapsed] = useState(0)
  const [logs, setLogs] = useState([])
  const [currentPhase, setCurrentPhase] = useState(1)
  const logsEndRef = useRef(null)

  // Elapsed timer
  useEffect(() => {
    const t = setInterval(() => setElapsed(Math.floor((Date.now() - startTime) / 1000)), 1000)
    return () => clearInterval(t)
  }, [startTime])

  // Load job info
  useEffect(() => {
    api.getJob(jobId)
      .then(job => {
        setFilename(job.filename)
        if (job.status === 'completed') navigate(`/report/${jobId}`)
      })
      .catch(console.error)
  }, [jobId, navigate])

  // WebSocket connection
  useEffect(() => {
    const ws = api.createWebSocket(jobId)
    wsRef.current = ws

    ws.onmessage = (event) => {
      const data = JSON.parse(event.data)

      if (data.type === 'job_status') {
        if (data.status === 'completed') {
          setTimeout(() => navigate(`/report/${jobId}`), 1200)
        } else if (data.status === 'failed') {
          setJobStatus('failed')
        }
        return
      }

      const { agent_index, status, message, result_summary, agent_name } = data

      setAgentStatuses(prev => ({
        ...prev,
        [agent_index]: { status, message, result: result_summary }
      }))

      // Track current phase
      const agent = ALL_AGENTS[agent_index]
      if (agent) setCurrentPhase(agent.phase)

      if (status === 'started') {
        setCurrentAgent(agent_index)
        addLog(`[${agent_name}] Started`)
      } else if (status === 'completed') {
        addLog(`[${agent_name}] ✓ ${message}`)
        if (agent_index === ALL_AGENTS.length - 1) {
          setJobStatus('completed')
          setTimeout(() => navigate(`/report/${jobId}`), 1500)
        }
      } else if (status === 'failed') {
        addLog(`[${agent_name}] ✗ FAILED: ${message}`)
        setJobStatus('failed')
      }
    }

    ws.onerror = () => {
      addLog('[WebSocket] Connection error — polling for status...')
      startPolling()
    }

    ws.onclose = () => addLog('[WebSocket] Connection closed')

    return () => ws.close()
  }, [jobId, navigate])

  function addLog(msg) {
    setLogs(prev => [...prev.slice(-200), { time: new Date().toISOString(), msg }])
  }

  function startPolling() {
    const interval = setInterval(async () => {
      try {
        const job = await api.getJob(jobId)
        if (job.status === 'completed') { clearInterval(interval); navigate(`/report/${jobId}`) }
        else if (job.status === 'failed') { clearInterval(interval); setJobStatus('failed') }
      } catch { clearInterval(interval) }
    }, 3000)
  }

  useEffect(() => { logsEndRef.current?.scrollIntoView({ behavior: 'smooth' }) }, [logs])

  const completedCount = Object.values(agentStatuses).filter(s => s.status === 'completed').length
  const progress = Math.round((completedCount / ALL_AGENTS.length) * 100)
  const formatTime = (s) => `${Math.floor(s / 60)}:${String(s % 60).padStart(2, '0')}`

  // Group agents by phase for rendering
  const agentsByPhase = ALL_AGENTS.reduce((acc, agent, i) => {
    const p = agent.phase
    if (!acc[p]) acc[p] = []
    acc[p].push({ ...agent, index: i })
    return acc
  }, {})

  return (
    <div className="analysis-page">
      {/* Header */}
      <header className="analysis-header">
        <div className="container">
          <div className="analysis-nav">
            <div className="logo">
              <ShieldIcon />
              <span className="logo-text">ViGiL</span>
              <span className="logo-version">v2.0</span>
            </div>
            <div className="analysis-meta">
              <div className="meta-item">
                <Clock size={14} />
                {formatTime(elapsed)}
              </div>
              <div className="meta-item phase-badge">
                <Brain size={14} />
                Phase {currentPhase}
              </div>
              <div className="meta-item">
                <div className={`status-dot ${jobStatus === 'running' ? 'running' : jobStatus === 'completed' ? 'completed' : 'failed'}`} />
                {jobStatus === 'running' ? 'Analyzing' : jobStatus === 'completed' ? 'Complete' : 'Failed'}
              </div>
            </div>
          </div>
        </div>
      </header>

      <main className="analysis-main">
        <div className="container">
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            className="analysis-title-block"
          >
            <h1 className="analysis-title">
              {jobStatus === 'completed' ? 'Analysis Complete'
                : jobStatus === 'failed' ? 'Analysis Failed'
                : 'Analyzing Sample'}
            </h1>
            {filename && (
              <p className="analysis-filename">
                <span className="text-secondary">Sample:</span>{' '}
                <span className="text-mono text-accent">{filename}</span>
              </p>
            )}
            {/* Phase progress pills */}
            <div className="phase-pills">
              {[1, 2, 3].map(p => (
                <div key={p} className={`phase-pill ${currentPhase === p ? 'active' : currentPhase > p ? 'done' : ''}`}>
                  {p === 2 ? <Brain size={11} /> : p === 3 ? <CheckCircle size={11} /> : <Cpu size={11} />}
                  {PHASE_LABELS[p].label}
                </div>
              ))}
            </div>
          </motion.div>

          {/* Progress bar */}
          <div className="progress-bar" style={{ marginBottom: '32px' }}>
            <motion.div
              className="progress-bar-fill"
              initial={{ width: 0 }}
              animate={{ width: `${progress}%` }}
              transition={{ duration: 0.5 }}
            />
          </div>

          <div className="analysis-grid">
            {/* Agent Pipeline — grouped by phase */}
            <div className="pipeline-panel glass-card">
              <div className="section-title">Agent Pipeline</div>
              <div className="pipeline-list">
                {Object.entries(agentsByPhase).map(([phase, agents]) => (
                  <div key={phase}>
                    <div className={`phase-separator phase-${phase}`}>
                      {PHASE_LABELS[phase].icon}
                      {PHASE_LABELS[phase].label}
                    </div>
                    {agents.map(agent => {
                      const s = agentStatuses[agent.index]
                      const isActive = agent.index === currentAgent && s.status === 'started'
                      const isDone = s.status === 'completed'
                      const isFailed = s.status === 'failed'
                      const isAI = agent.phase === 2

                      return (
                        <motion.div
                          key={agent.name}
                          className={`pipeline-item ${isActive ? 'active' : ''} ${isDone ? 'done' : ''} ${isFailed ? 'failed-item' : ''} ${isAI ? 'ai-agent' : ''}`}
                          initial={{ opacity: 0, x: -10 }}
                          animate={{ opacity: 1, x: 0 }}
                          transition={{ delay: agent.index * 0.02 }}
                        >
                          <div className="pipeline-index">
                            {isAI ? <Brain size={10} /> : String(agent.index + 1).padStart(2, '0')}
                          </div>
                          <div className="pipeline-info">
                            <div className="pipeline-name">{agent.name}</div>
                            <div className="pipeline-desc">
                              {s.status !== 'pending' ? s.message || agent.desc : agent.desc}
                            </div>
                          </div>
                          <div className="pipeline-status">
                            {STATUS_ICON[s.status]}
                          </div>
                        </motion.div>
                      )
                    })}
                  </div>
                ))}
              </div>

              {/* Stats */}
              <div className="pipeline-stats">
                <div className="pipeline-stat">
                  <span className="stat-number text-success">{completedCount}</span>
                  <span className="stat-label">Done</span>
                </div>
                <div className="pipeline-stat">
                  <span className="stat-number text-accent">{ALL_AGENTS.length - completedCount}</span>
                  <span className="stat-label">Remaining</span>
                </div>
                <div className="pipeline-stat">
                  <span className="stat-number">{progress}%</span>
                  <span className="stat-label">Progress</span>
                </div>
              </div>
            </div>

            {/* Live Log */}
            <div className="log-panel glass-card">
              <div className="section-title">Live Analysis Log</div>
              <div className="log-output">
                {logs.length === 0 ? (
                  <div className="log-waiting">
                    <Loader size={16} className="agent-spinner" />
                    <span>Waiting for agents to start...</span>
                  </div>
                ) : (
                  logs.map((entry, i) => (
                    <div key={i} className={`log-entry ${entry.msg.includes('[AI]') ? 'log-ai' : ''}`}>
                      <span className="log-time">{entry.time.slice(11, 19)}</span>
                      <span className={`log-msg ${entry.msg.includes('✗') ? 'text-danger' : entry.msg.includes('✓') ? 'text-success' : entry.msg.includes('[AI]') ? 'text-ai' : ''}`}>
                        {entry.msg}
                      </span>
                    </div>
                  ))
                )}
                <div ref={logsEndRef} />
              </div>

              {/* AI phase notice */}
              <AnimatePresence>
                {currentPhase === 2 && (
                  <motion.div
                    initial={{ opacity: 0, y: 8 }}
                    animate={{ opacity: 1, y: 0 }}
                    exit={{ opacity: 0 }}
                    className="ai-phase-notice"
                  >
                    <Brain size={16} />
                    <div>
                      <div className="ai-notice-title">CrewAI Hierarchical Reasoning Active</div>
                      <div className="ai-notice-sub">5 specialized LLM agents are collaborating to produce a final verdict</div>
                    </div>
                  </motion.div>
                )}
              </AnimatePresence>

              {/* Current agent result */}
              <AnimatePresence>
                {currentAgent >= 0 && agentStatuses[currentAgent]?.result && (
                  <motion.div
                    key={currentAgent}
                    initial={{ opacity: 0, y: 10 }}
                    animate={{ opacity: 1, y: 0 }}
                    exit={{ opacity: 0 }}
                    className="current-result"
                  >
                    <div className="section-title" style={{ fontSize: '0.65rem', marginBottom: '8px' }}>
                      Latest Result
                    </div>
                    <pre className="result-json">
                      {JSON.stringify(agentStatuses[currentAgent].result, null, 2)}
                    </pre>
                  </motion.div>
                )}
              </AnimatePresence>
            </div>
          </div>

          {/* Completed notice */}
          <AnimatePresence>
            {jobStatus === 'completed' && (
              <motion.div
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                className="completed-banner"
              >
                <CheckCircle size={24} />
                <div>
                  <div className="completed-title">Analysis Complete!</div>
                  <div className="completed-sub">Redirecting to report...</div>
                </div>
                <button className="btn btn-primary" onClick={() => navigate(`/report/${jobId}`)}>
                  View Report <ChevronRight size={16} />
                </button>
              </motion.div>
            )}
          </AnimatePresence>

          {/* Failed notice */}
          <AnimatePresence>
            {jobStatus === 'failed' && (
              <motion.div
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                className="failed-banner"
              >
                <XCircle size={24} />
                <div>
                  <div className="failed-title">Analysis Failed</div>
                  <div className="failed-sub">Check the log for details. Some tools may not be installed.</div>
                </div>
                <button className="btn btn-ghost" onClick={() => navigate('/')}>Try Again</button>
              </motion.div>
            )}
          </AnimatePresence>
        </div>
      </main>
    </div>
  )
}

function ShieldIcon() {
  return (
    <svg width="24" height="24" viewBox="0 0 24 24" fill="none">
      <path d="M12 2L3 7v5c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V7L12 2z"
        stroke="#00e5ff" strokeWidth="1.5" fill="rgba(0,229,255,0.1)" />
      <path d="M9 12l2 2 4-4" stroke="#00e5ff" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  )
}
