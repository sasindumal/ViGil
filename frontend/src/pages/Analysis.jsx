import { useState, useEffect, useRef } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { motion, AnimatePresence } from 'framer-motion'
import { CheckCircle, XCircle, Loader, Shield, Clock, ChevronRight } from 'lucide-react'
import api from '../api'
import './Analysis.css'

const ALL_AGENTS = [
  { name: 'Sample Intake', desc: 'PE validation, hashes, metadata' },
  { name: 'Static Analysis', desc: 'Imports, sections, strings, entropy' },
  { name: 'Unpacking', desc: 'Packer detection, multi-stage unpacking' },
  { name: 'Capability Detection', desc: 'CAPA — credential theft, injection, ransomware' },
  { name: 'CFG Extraction', desc: 'Control flow graph, call graph' },
  { name: 'Threat Intelligence', desc: 'VirusTotal, MalwareBazaar, OTX' },
  { name: 'Evasion Detection', desc: 'Anti-VM, anti-debug, API obfuscation' },
  { name: 'Emulation Analysis', desc: 'Speakeasy behavioral emulation' },
  { name: 'Similarity Analysis', desc: 'Family similarity embeddings (FAISS)' },
  { name: 'Family Clustering', desc: 'HDBSCAN cluster assignment' },
  { name: 'MITRE ATT&CK Mapping', desc: 'Technique coverage mapping' },
  { name: 'RAG Intelligence', desc: 'Evidence-backed LLM explanation' },
  { name: 'LLM Decompilation', desc: 'Function decompilation with LLM summaries' },
  { name: 'YARA Generation', desc: 'Auto-generated hunting rules' },
  { name: 'ATT&CK Navigator Export', desc: 'Navigator layer JSON' },
  { name: 'STIX Export', desc: 'STIX 2.1 bundle generation' },
  { name: 'Report Generation', desc: 'Final report assembly' },
]

const STATUS_ICON = {
  pending: <div className="agent-pending-dot" />,
  started: <Loader size={16} className="agent-spinner" />,
  completed: <CheckCircle size={16} className="text-success" />,
  failed: <XCircle size={16} className="text-danger" />,
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
        if (job.status === 'completed') {
          navigate(`/report/${jobId}`)
        }
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

      // Agent progress event
      const { agent_index, status, message, result_summary, agent_name } = data

      setAgentStatuses(prev => ({
        ...prev,
        [agent_index]: { status, message, result: result_summary }
      }))

      if (status === 'started') {
        setCurrentAgent(agent_index)
        addLog(`[${agent_name}] Started`)
      } else if (status === 'completed') {
        addLog(`[${agent_name}] ✓ ${message}`)
        // Auto-navigate when last agent completes
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
      // Fallback polling
      startPolling()
    }

    ws.onclose = () => {
      addLog('[WebSocket] Connection closed')
    }

    return () => {
      ws.close()
    }
  }, [jobId, navigate])

  function addLog(msg) {
    setLogs(prev => [...prev.slice(-200), { time: new Date().toISOString(), msg }])
  }

  function startPolling() {
    const interval = setInterval(async () => {
      try {
        const job = await api.getJob(jobId)
        if (job.status === 'completed') {
          clearInterval(interval)
          navigate(`/report/${jobId}`)
        } else if (job.status === 'failed') {
          clearInterval(interval)
          setJobStatus('failed')
        }
      } catch {
        clearInterval(interval)
      }
    }, 3000)
  }

  // Auto-scroll logs
  useEffect(() => {
    logsEndRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [logs])

  const completedCount = Object.values(agentStatuses).filter(s => s.status === 'completed').length
  const progress = Math.round((completedCount / ALL_AGENTS.length) * 100)

  const formatTime = (s) => `${Math.floor(s / 60)}:${String(s % 60).padStart(2, '0')}`

  return (
    <div className="analysis-page">
      {/* Header */}
      <header className="analysis-header">
        <div className="container">
          <div className="analysis-nav">
            <div className="logo">
              <ShieldIcon />
              <span className="logo-text">ViGiL</span>
            </div>
            <div className="analysis-meta">
              <div className="meta-item">
                <Clock size={14} />
                {formatTime(elapsed)}
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
          {/* Page title */}
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            className="analysis-title-block"
          >
            <h1 className="analysis-title">
              {jobStatus === 'completed'
                ? 'Analysis Complete'
                : jobStatus === 'failed'
                ? 'Analysis Failed'
                : 'Analyzing Sample'}
            </h1>
            {filename && (
              <p className="analysis-filename">
                <span className="text-secondary">Sample:</span>{' '}
                <span className="text-mono text-accent">{filename}</span>
              </p>
            )}
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
            {/* Agent Pipeline */}
            <div className="pipeline-panel glass-card">
              <div className="section-title">Agent Pipeline</div>
              <div className="pipeline-list">
                {ALL_AGENTS.map((agent, i) => {
                  const s = agentStatuses[i]
                  const isActive = i === currentAgent && s.status === 'started'
                  const isDone = s.status === 'completed'
                  const isFailed = s.status === 'failed'

                  return (
                    <motion.div
                      key={agent.name}
                      className={`pipeline-item ${isActive ? 'active' : ''} ${isDone ? 'done' : ''} ${isFailed ? 'failed-item' : ''}`}
                      initial={{ opacity: 0, x: -10 }}
                      animate={{ opacity: 1, x: 0 }}
                      transition={{ delay: i * 0.02 }}
                    >
                      <div className="pipeline-index">{String(i + 1).padStart(2, '0')}</div>
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
                    <div key={i} className="log-entry">
                      <span className="log-time">{entry.time.slice(11, 19)}</span>
                      <span className={`log-msg ${entry.msg.includes('✗') ? 'text-danger' : entry.msg.includes('✓') ? 'text-success' : ''}`}>
                        {entry.msg}
                      </span>
                    </div>
                  ))
                )}
                <div ref={logsEndRef} />
              </div>

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
                <button
                  className="btn btn-primary"
                  onClick={() => navigate(`/report/${jobId}`)}
                >
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
                <button className="btn btn-ghost" onClick={() => navigate('/')}>
                  Try Again
                </button>
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
