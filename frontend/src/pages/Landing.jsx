import { useState, useCallback, useRef } from 'react'
import { useNavigate } from 'react-router-dom'
import { motion, AnimatePresence } from 'framer-motion'
import {
  Shield, Upload, Zap, Eye, AlertTriangle, Database,
  ChevronRight, Terminal, Lock, Globe, Cpu
} from 'lucide-react'
import api from '../api'
import './Landing.css'

const FEATURES = [
  { icon: <Shield size={20} />, title: 'Static Analysis', desc: 'PE sections, imports, entropy, string extraction' },
  { icon: <Lock size={20} />, title: 'Evasion Detection', desc: 'Anti-VM, anti-debug, API obfuscation, sandbox evasion' },
  { icon: <Cpu size={20} />, title: 'Emulation', desc: 'Behavioral analysis via Speakeasy — no real execution' },
  { icon: <Database size={20} />, title: 'CAPA Capabilities', desc: 'Credential theft, injection, ransomware, keylogging' },
  { icon: <Globe size={20} />, title: 'Threat Intelligence', desc: 'VirusTotal, MalwareBazaar, AbuseIPDB, OTX' },
  { icon: <Eye size={20} />, title: 'Similarity Analysis', desc: 'Vector similarity against known malware families' },
  { icon: <Zap size={20} />, title: 'MITRE ATT&CK', desc: 'Automatic technique mapping with confidence scores' },
  { icon: <Terminal size={20} />, title: 'YARA Generation', desc: 'Auto-generated hunting rules for generic, family, sample' },
]

const AGENTS = [
  'Sample Intake', 'Static Analysis', 'Unpacking', 'CAPA Capabilities',
  'CFG Extraction', 'Threat Intel', 'Evasion Detection', 'Emulation',
  'Similarity', 'Family Clustering', 'MITRE ATT&CK', 'RAG Intelligence',
  'Decompilation', 'YARA Generation', 'ATT&CK Navigator', 'STIX Export', 'Report'
]

export default function LandingPage() {
  const navigate = useNavigate()
  const [dragOver, setDragOver] = useState(false)
  const [uploading, setUploading] = useState(false)
  const [error, setError] = useState(null)
  const fileInputRef = useRef(null)

  const handleFile = useCallback(async (file) => {
    if (!file) return
    setError(null)
    setUploading(true)

    try {
      const job = await api.submitAnalysis(file)
      navigate(`/analysis/${job.job_id}`)
    } catch (err) {
      setError(err.message)
      setUploading(false)
    }
  }, [navigate])

  const handleDrop = useCallback((e) => {
    e.preventDefault()
    setDragOver(false)
    const file = e.dataTransfer.files[0]
    if (file) handleFile(file)
  }, [handleFile])

  const handleDragOver = useCallback((e) => {
    e.preventDefault()
    setDragOver(true)
  }, [])

  const handleDragLeave = useCallback(() => {
    setDragOver(false)
  }, [])

  const handleInputChange = useCallback((e) => {
    const file = e.target.files[0]
    if (file) handleFile(file)
  }, [handleFile])

  return (
    <div className="landing">
      {/* Animated background orbs */}
      <div className="bg-orbs">
        <div className="orb orb-1" />
        <div className="orb orb-2" />
        <div className="orb orb-3" />
      </div>

      {/* Header */}
      <header className="landing-header">
        <div className="container">
          <nav className="landing-nav">
            <div className="logo">
              <ShieldIcon />
              <span className="logo-text">ViGiL</span>
              <span className="logo-version">v1.0</span>
            </div>
            <div className="nav-links">
              <a href="#features" className="nav-link">Features</a>
              <a href="#agents" className="nav-link">Agents</a>
              <a href="http://localhost:8000/api/docs" target="_blank" rel="noopener" className="nav-link">API Docs</a>
              <a href="https://github.com" target="_blank" rel="noopener" className="btn btn-ghost">
                GitHub
              </a>
            </div>
          </nav>
        </div>
      </header>

      {/* Hero */}
      <section className="hero">
        <div className="container">
          <motion.div
            initial={{ opacity: 0, y: 40 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.7, ease: 'easeOut' }}
            className="hero-content"
          >
            <div className="hero-badge">
              <span className="status-dot running" />
              17 Specialized Agents &mdash; Evidence-Based Verdicts
            </div>

            <h1 className="hero-title">
              <span className="gradient-text">Multi-Agent</span>
              <br />
              Malware Analysis
              <br />
              <span className="glow-text">Platform</span>
            </h1>

            <p className="hero-subtitle">
              Every verdict is backed by static evidence, emulation results, evasion indicators,
              CAPA capabilities, threat intelligence, similarity scores, and ATT&CK technique coverage.
              No ML black boxes — pure forensic evidence.
            </p>

            {/* Upload Zone */}
            <motion.div
              className={`upload-zone ${dragOver ? 'drag-over' : ''} ${uploading ? 'uploading' : ''}`}
              onDrop={handleDrop}
              onDragOver={handleDragOver}
              onDragLeave={handleDragLeave}
              onClick={() => !uploading && fileInputRef.current?.click()}
              whileHover={{ scale: 1.01 }}
              whileTap={{ scale: 0.99 }}
            >
              <input
                ref={fileInputRef}
                type="file"
                accept=".exe,.dll,.bin,.sys"
                onChange={handleInputChange}
                hidden
                id="file-upload-input"
              />

              <AnimatePresence mode="wait">
                {uploading ? (
                  <motion.div
                    key="uploading"
                    initial={{ opacity: 0 }}
                    animate={{ opacity: 1 }}
                    exit={{ opacity: 0 }}
                    className="upload-state"
                  >
                    <div className="upload-spinner" />
                    <p className="upload-text">Submitting sample for analysis...</p>
                    <div className="upload-progress">
                      <div className="upload-progress-bar" />
                    </div>
                  </motion.div>
                ) : (
                  <motion.div
                    key="idle"
                    initial={{ opacity: 0 }}
                    animate={{ opacity: 1 }}
                    exit={{ opacity: 0 }}
                    className="upload-state"
                  >
                    <div className={`upload-icon ${dragOver ? 'drop-ready' : ''}`}>
                      <Upload size={32} />
                    </div>
                    <p className="upload-title">
                      {dragOver ? 'Drop to analyze' : 'Drop PE file here'}
                    </p>
                    <p className="upload-subtitle">
                      .exe, .dll, .sys — up to 100MB
                    </p>
                    <div className="upload-cta">
                      <span className="btn btn-primary">
                        <Upload size={16} />
                        Choose File
                      </span>
                    </div>
                  </motion.div>
                )}
              </AnimatePresence>

              {/* Scanning animation */}
              {(dragOver || uploading) && <div className="scan-line" />}
            </motion.div>

            {/* Error */}
            <AnimatePresence>
              {error && (
                <motion.div
                  initial={{ opacity: 0, y: -10 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0 }}
                  className="upload-error"
                >
                  <AlertTriangle size={16} />
                  {error}
                </motion.div>
              )}
            </AnimatePresence>

            {/* Stats row */}
            <div className="hero-stats">
              <div className="hero-stat">
                <span className="stat-number">17</span>
                <span className="stat-label">Specialized Agents</span>
              </div>
              <div className="hero-stat-divider" />
              <div className="hero-stat">
                <span className="stat-number">16</span>
                <span className="stat-label">ATT&CK Techniques Mapped</span>
              </div>
              <div className="hero-stat-divider" />
              <div className="hero-stat">
                <span className="stat-number">4</span>
                <span className="stat-label">Export Formats</span>
              </div>
              <div className="hero-stat-divider" />
              <div className="hero-stat">
                <span className="stat-number">100%</span>
                <span className="stat-label">Evidence-Backed</span>
              </div>
            </div>
          </motion.div>
        </div>
      </section>

      {/* Agent Pipeline Visualization */}
      <section id="agents" className="agents-section">
        <div className="container">
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            transition={{ duration: 0.5 }}
          >
            <div className="section-title">Analysis Pipeline</div>
            <h2 className="agents-title">17-Agent Sequential Pipeline</h2>
            <div className="agents-grid">
              {AGENTS.map((agent, i) => (
                <motion.div
                  key={agent}
                  className="agent-chip"
                  initial={{ opacity: 0, x: -10 }}
                  whileInView={{ opacity: 1, x: 0 }}
                  viewport={{ once: true }}
                  transition={{ delay: i * 0.04 }}
                >
                  <span className="agent-number">{String(i + 1).padStart(2, '0')}</span>
                  <span className="agent-name">{agent}</span>
                  {i < AGENTS.length - 1 && <ChevronRight size={12} className="agent-arrow" />}
                </motion.div>
              ))}
            </div>
          </motion.div>
        </div>
      </section>

      {/* Features Grid */}
      <section id="features" className="features-section">
        <div className="container">
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
          >
            <div className="section-title">Capabilities</div>
            <h2 className="features-title">Enterprise-Grade Analysis</h2>
          </motion.div>
          <div className="features-grid">
            {FEATURES.map((f, i) => (
              <motion.div
                key={f.title}
                className="glass-card feature-card"
                initial={{ opacity: 0, y: 20 }}
                whileInView={{ opacity: 1, y: 0 }}
                viewport={{ once: true }}
                transition={{ delay: i * 0.08 }}
                whileHover={{ y: -4 }}
              >
                <div className="feature-icon">{f.icon}</div>
                <h3 className="feature-title">{f.title}</h3>
                <p className="feature-desc">{f.desc}</p>
              </motion.div>
            ))}
          </div>
        </div>
      </section>

      {/* Report formats */}
      <section className="exports-section">
        <div className="container">
          <motion.div
            className="glass-card exports-card"
            initial={{ opacity: 0, y: 20 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
          >
            <div className="section-title">Export Formats</div>
            <h2 className="exports-title">Compatible with Your Workflow</h2>
            <div className="exports-grid">
              {[
                { label: 'PDF Report', desc: 'Full forensic report, downloadable', color: '#ff3366' },
                { label: 'JSON Report', desc: 'Machine-readable structured data', color: '#00e5ff' },
                { label: 'STIX 2.1', desc: 'OpenCTI / MISP / TAXII compatible', color: '#7c3aed' },
                { label: 'YARA Rules', desc: 'Auto-generated hunting signatures', color: '#00ff88' },
                { label: 'ATT&CK Layer', desc: 'MITRE Navigator import-ready', color: '#ffd700' },
                { label: 'CFG / Call Graph', desc: 'SVG + JSON program structure', color: '#ff8c00' },
              ].map((exp, i) => (
                <motion.div
                  key={exp.label}
                  className="export-chip"
                  initial={{ opacity: 0, scale: 0.9 }}
                  whileInView={{ opacity: 1, scale: 1 }}
                  viewport={{ once: true }}
                  transition={{ delay: i * 0.06 }}
                  style={{ '--chip-color': exp.color }}
                >
                  <div className="export-dot" />
                  <div>
                    <div className="export-label">{exp.label}</div>
                    <div className="export-desc">{exp.desc}</div>
                  </div>
                </motion.div>
              ))}
            </div>
          </motion.div>
        </div>
      </section>

      {/* Footer */}
      <footer className="landing-footer">
        <div className="container">
          <div className="footer-content">
            <div className="logo">
              <ShieldIcon />
              <span className="logo-text">ViGiL</span>
            </div>
            <p className="footer-text">
              Multi-Agent Malware Analysis Platform &mdash; Evidence-based verdicts, not ML black boxes.
            </p>
            <p className="footer-copy">Built with CrewAI, FastAPI, React &amp; Vite</p>
          </div>
        </div>
      </footer>
    </div>
  )
}

function ShieldIcon() {
  return (
    <svg width="28" height="28" viewBox="0 0 24 24" fill="none">
      <path
        d="M12 2L3 7v5c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V7L12 2z"
        stroke="#00e5ff"
        strokeWidth="1.5"
        fill="rgba(0,229,255,0.1)"
      />
      <path d="M9 12l2 2 4-4" stroke="#00e5ff" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  )
}
