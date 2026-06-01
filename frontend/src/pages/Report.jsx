import { useState, useEffect, useRef } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { motion } from 'framer-motion'
import {
  Shield, Download, ChevronLeft, AlertTriangle, CheckCircle,
  XCircle, Copy, ExternalLink, Terminal, Cpu, Globe, Lock,
  Database, Eye, Zap, FileText, BarChart2, Code
} from 'lucide-react'
import {
  RadarChart, Radar, PolarGrid, PolarAngleAxis, PolarRadiusAxis,
  ResponsiveContainer, BarChart, Bar, XAxis, YAxis, Tooltip, Cell
} from 'recharts'
import api from '../api'
import './Report.css'

// ─── PDF Export ──────────────────────────────────────────────────────────────
async function exportPDF(reportRef, filename) {
  const jsPDF = (await import('jspdf')).default
  const html2canvas = (await import('html2canvas')).default

  const canvas = await html2canvas(reportRef.current, {
    scale: 1.5,
    backgroundColor: '#040810',
    useCORS: true,
    logging: false,
  })

  const imgData = canvas.toDataURL('image/png')
  const pdf = new jsPDF({ orientation: 'portrait', unit: 'mm', format: 'a4' })
  const pdfWidth = pdf.internal.pageSize.getWidth()
  const pdfHeight = (canvas.height * pdfWidth) / canvas.width
  const pageHeight = pdf.internal.pageSize.getHeight()

  let position = 0
  while (position < pdfHeight) {
    pdf.addImage(imgData, 'PNG', 0, -position, pdfWidth, pdfHeight)
    position += pageHeight
    if (position < pdfHeight) pdf.addPage()
  }

  pdf.save(`vigil-report-${filename}.pdf`)
}

// ─── Helpers ─────────────────────────────────────────────────────────────────
const TACTIC_COLORS = {
  'Discovery': '#7c3aed',
  'Execution': '#ff8c00',
  'Persistence': '#ffd700',
  'Defense Evasion': '#ff3366',
  'Credential Access': '#00e5ff',
  'Command and Control': '#00ff88',
  'Collection': '#f97316',
  'Impact': '#ec4899',
}

function ThreatBadge({ level }) {
  const cls = `badge badge-${level}`
  const icons = { malicious: '🔴', suspicious: '🟠', clean: '🟢', unknown: '⚪' }
  return <span className={cls}>{icons[level] || '⚪'} {level?.toUpperCase()}</span>
}

function SectionCard({ title, icon, children, id }) {
  return (
    <motion.div
      className="glass-card report-section"
      initial={{ opacity: 0, y: 16 }}
      animate={{ opacity: 1, y: 0 }}
      id={id}
    >
      <div className="report-section-header">
        <div className="section-title">
          {icon}
          {title}
        </div>
      </div>
      {children}
    </motion.div>
  )
}

// ─── Main Report Page ─────────────────────────────────────────────────────────
export default function ReportPage() {
  const { jobId } = useParams()
  const navigate = useNavigate()
  const reportRef = useRef(null)

  const [report, setReport] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [pdfExporting, setPdfExporting] = useState(false)
  const [copied, setCopied] = useState(false)

  useEffect(() => {
    async function load() {
      try {
        const data = await api.getReport(jobId)
        setReport(data)
      } catch (err) {
        setError(err.message)
      } finally {
        setLoading(false)
      }
    }
    load()
  }, [jobId])

  const handlePDFExport = async () => {
    setPdfExporting(true)
    try {
      await exportPDF(reportRef, report?.filename || jobId)
    } catch (e) {
      console.error(e)
    } finally {
      setPdfExporting(false)
    }
  }

  const handleCopy = () => {
    navigator.clipboard.writeText(JSON.stringify(report, null, 2))
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  if (loading) return <LoadingScreen />
  if (error) return <ErrorScreen error={error} onBack={() => navigate('/')} />
  if (!report) return null

  const { threat_level, confidence_score, verdict_reasoning, sample_intake, static_analysis,
    unpacking, capabilities, evasion, emulation, similarity, clustering, threat_intel,
    mitre, rag_explanation, decompilation, yara, attack_navigator, stix, filename,
    analysis_timestamp, analysis_duration_seconds } = report

  return (
    <div className="report-page">
      {/* Header */}
      <header className="report-header">
        <div className="container">
          <div className="report-nav">
            <button className="btn btn-ghost btn-back" onClick={() => navigate('/')}>
              <ChevronLeft size={16} /> New Analysis
            </button>
            <div className="logo">
              <ShieldIcon />
              <span className="logo-text">ViGiL</span>
              <span className="logo-version">Report</span>
            </div>
            <div className="report-actions">
              <button className="btn btn-ghost" onClick={handleCopy}>
                {copied ? <CheckCircle size={16} /> : <Copy size={16} />}
                {copied ? 'Copied!' : 'Copy JSON'}
              </button>
              <button className="btn btn-primary" onClick={handlePDFExport} disabled={pdfExporting} id="export-pdf-btn">
                <Download size={16} />
                {pdfExporting ? 'Generating...' : 'Export PDF'}
              </button>
            </div>
          </div>
        </div>
      </header>

      {/* Download bar */}
      <div className="download-bar">
        <div className="container">
          <div className="download-bar-inner">
            <span className="text-secondary text-xs">Download Artifacts:</span>
            {[
              { key: 'report_json', label: 'JSON Report', color: '#00e5ff' },
              { key: 'report_stix', label: 'STIX 2.1', color: '#7c3aed' },
              { key: 'yara', label: 'YARA Rules', color: '#00ff88' },
              { key: 'attack_navigator', label: 'ATT&CK Layer', color: '#ffd700' },
            ].map(a => (
              <a
                key={a.key}
                href={api.getDownloadUrl(jobId, a.key)}
                className="download-chip"
                style={{ '--chip-color': a.color }}
                download
                target="_blank"
                rel="noopener"
              >
                <Download size={12} />
                {a.label}
              </a>
            ))}
          </div>
        </div>
      </div>

      {/* Main Report */}
      <main className="report-main" ref={reportRef}>
        <div className="container">
          <div className="report-grid">
            {/* Left sidebar nav */}
            <aside className="report-sidebar">
              <div className="sidebar-nav">
                {[
                  { id: 'verdict', label: 'Verdict' },
                  { id: 'file-info', label: 'File Info' },
                  { id: 'static', label: 'Static Analysis' },
                  { id: 'unpacking', label: 'Unpacking' },
                  { id: 'capabilities', label: 'Capabilities' },
                  { id: 'evasion', label: 'Evasion' },
                  { id: 'emulation', label: 'Emulation' },
                  { id: 'similarity', label: 'Similarity' },
                  { id: 'mitre', label: 'ATT&CK' },
                  { id: 'threat-intel', label: 'Threat Intel' },
                  { id: 'rag', label: 'AI Analysis' },
                  { id: 'decompilation', label: 'Decompilation' },
                  { id: 'yara', label: 'YARA Rules' },
                ].map(item => (
                  <a key={item.id} href={`#${item.id}`} className="sidebar-link">{item.label}</a>
                ))}
              </div>
            </aside>

            {/* Report Content */}
            <div className="report-content">

              {/* ── Verdict Card ─────────────────────────────────── */}
              <motion.div
                className={`verdict-card glass-card verdict-${threat_level}`}
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                id="verdict"
              >
                <div className="verdict-header">
                  <div>
                    <div className="verdict-label">VERDICT</div>
                    <div className={`verdict-level threat-${threat_level}`}>
                      {threat_level?.toUpperCase()}
                    </div>
                    <div className="verdict-confidence">
                      Confidence: <strong>{Math.round(confidence_score * 100)}%</strong>
                    </div>
                    <div className="verdict-file">{filename}</div>
                  </div>
                  <VerdictIcon level={threat_level} />
                </div>

                {/* Confidence bar */}
                <div className="verdict-bar-label">
                  Evidence Confidence
                </div>
                <div className="progress-bar">
                  <motion.div
                    className="progress-bar-fill"
                    initial={{ width: 0 }}
                    animate={{ width: `${confidence_score * 100}%` }}
                    transition={{ duration: 1, delay: 0.3 }}
                    style={{
                      background: threat_level === 'malicious'
                        ? 'linear-gradient(90deg, #ff3366, #ff0044)'
                        : threat_level === 'suspicious'
                        ? 'linear-gradient(90deg, #ff8c00, #ffd700)'
                        : 'linear-gradient(90deg, #00ff88, #00e5ff)'
                    }}
                  />
                </div>

                {/* Evidence reasoning */}
                <div className="verdict-evidence">
                  <div className="evidence-title">Evidence</div>
                  {verdict_reasoning?.map((r, i) => (
                    <div key={i} className="evidence-item">
                      <AlertTriangle size={12} className="text-warning" />
                      <span>{r}</span>
                    </div>
                  ))}
                </div>

                {/* Summary meta */}
                <div className="verdict-meta">
                  <div className="verdict-meta-item">
                    <span className="text-secondary">Analyzed</span>
                    <span className="text-mono">{new Date(analysis_timestamp).toLocaleString()}</span>
                  </div>
                  <div className="verdict-meta-item">
                    <span className="text-secondary">Duration</span>
                    <span className="text-mono">{analysis_duration_seconds?.toFixed(1)}s</span>
                  </div>
                  {clustering && (
                    <div className="verdict-meta-item">
                      <span className="text-secondary">Family Cluster</span>
                      <span className="text-mono">{clustering.cluster_label}</span>
                    </div>
                  )}
                </div>
              </motion.div>

              {/* ── File Info ────────────────────────────────────── */}
              {sample_intake && (
                <SectionCard title="File Information" icon={<FileText size={14} />} id="file-info">
                  <div className="info-grid">
                    {[
                      { label: 'SHA256', value: sample_intake.sha256, mono: true },
                      { label: 'MD5', value: sample_intake.md5, mono: true },
                      { label: 'SHA1', value: sample_intake.sha1, mono: true },
                      { label: 'File Type', value: sample_intake.file_type },
                      { label: 'Architecture', value: sample_intake.arch },
                      { label: 'File Size', value: `${(sample_intake.file_size / 1024).toFixed(1)} KB` },
                      { label: 'Compile Time', value: sample_intake.compile_timestamp || 'Unknown' },
                      { label: 'Is PE', value: sample_intake.is_pe ? 'Yes' : 'No' },
                      { label: 'Is DLL', value: sample_intake.is_dll ? 'Yes' : 'No' },
                      { label: '.NET', value: sample_intake.is_dotnet ? 'Yes' : 'No' },
                    ].map(item => (
                      <div key={item.label} className="info-row">
                        <span className="info-label">{item.label}</span>
                        <span className={`info-value ${item.mono ? 'text-mono' : ''}`}>
                          {item.value || 'N/A'}
                        </span>
                      </div>
                    ))}
                  </div>
                </SectionCard>
              )}

              {/* ── Static Analysis ──────────────────────────────── */}
              {static_analysis && (
                <SectionCard title="Static Analysis" icon={<Code size={14} />} id="static">
                  {/* Sections */}
                  {static_analysis.sections?.length > 0 && (
                    <div className="sub-section">
                      <div className="sub-section-title">PE Sections</div>
                      <table className="vigil-table">
                        <thead>
                          <tr>
                            <th>Name</th>
                            <th>Virtual Size</th>
                            <th>Raw Size</th>
                            <th>Entropy</th>
                            <th>Status</th>
                          </tr>
                        </thead>
                        <tbody>
                          {static_analysis.sections.map(s => (
                            <tr key={s.name}>
                              <td className="text-accent">{s.name}</td>
                              <td>{s.virtual_size?.toLocaleString()}</td>
                              <td>{s.raw_size?.toLocaleString()}</td>
                              <td>
                                <EntropyBar value={s.entropy} />
                              </td>
                              <td>
                                {s.entropy > 7 ? (
                                  <span className="badge badge-malicious">High Entropy</span>
                                ) : (
                                  <span className="badge badge-clean">Normal</span>
                                )}
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  )}

                  {/* String indicators */}
                  <div className="indicators-grid">
                    {[
                      { label: 'URLs', items: static_analysis.urls, color: 'info' },
                      { label: 'IPs', items: static_analysis.ips, color: 'suspicious' },
                      { label: 'Domains', items: static_analysis.domains, color: 'info' },
                      { label: 'Registry Keys', items: static_analysis.registry_keys, color: 'suspicious' },
                      { label: 'Suspicious APIs', items: static_analysis.suspicious_strings, color: 'malicious' },
                      { label: 'Commands', items: static_analysis.commands, color: 'malicious' },
                    ].filter(g => g.items?.length > 0).map(group => (
                      <div key={group.label} className="indicator-group">
                        <div className="indicator-group-title">{group.label} ({group.items.length})</div>
                        <div className="indicator-list">
                          {group.items.slice(0, 5).map((item, i) => (
                            <span key={i} className={`badge badge-${group.color} indicator-badge`}>
                              {item.length > 50 ? item.slice(0, 50) + '...' : item}
                            </span>
                          ))}
                          {group.items.length > 5 && (
                            <span className="badge badge-unknown">+{group.items.length - 5} more</span>
                          )}
                        </div>
                      </div>
                    ))}
                  </div>
                </SectionCard>
              )}

              {/* ── Unpacking ────────────────────────────────────── */}
              {unpacking && (
                <SectionCard title="Packing Analysis" icon={<Lock size={14} />} id="unpacking">
                  <div className="unpack-grid">
                    <div className="unpack-stat">
                      <div className={`unpack-icon ${unpacking.is_packed ? 'packed' : 'clean'}`}>
                        {unpacking.is_packed ? <Lock size={24} /> : <CheckCircle size={24} />}
                      </div>
                      <div className="unpack-label">
                        {unpacking.is_packed ? 'PACKED' : 'NOT PACKED'}
                      </div>
                    </div>
                    {[
                      { label: 'Packer Detected', value: unpacking.packer || 'None' },
                      { label: 'Layers', value: String(unpacking.layers) },
                      { label: 'Payload Recovered', value: unpacking.payload_recovered ? 'Yes' : 'No' },
                      { label: 'RWX Sections', value: unpacking.rwx_sections ? 'Yes' : 'No' },
                    ].map(item => (
                      <div key={item.label} className="info-row">
                        <span className="info-label">{item.label}</span>
                        <span className="info-value text-mono">{item.value}</span>
                      </div>
                    ))}
                  </div>
                </SectionCard>
              )}

              {/* ── Capabilities ─────────────────────────────────── */}
              {capabilities && (
                <SectionCard title="Malware Capabilities (CAPA)" icon={<Cpu size={14} />} id="capabilities">
                  <div className="capabilities-grid">
                    {[
                      { key: 'has_injection', label: 'Process Injection', icon: '💉' },
                      { key: 'has_credential_theft', label: 'Credential Theft', icon: '🔑' },
                      { key: 'has_keylogging', label: 'Keylogging', icon: '⌨️' },
                      { key: 'has_persistence', label: 'Persistence', icon: '🔒' },
                      { key: 'has_ransomware', label: 'Ransomware', icon: '💰' },
                      { key: 'has_network_beaconing', label: 'Network Beaconing', icon: '📡' },
                      { key: 'has_discovery', label: 'System Discovery', icon: '🔍' },
                    ].map(cap => (
                      <div
                        key={cap.key}
                        className={`capability-chip ${capabilities[cap.key] ? 'detected' : 'not-detected'}`}
                      >
                        <span className="cap-icon">{cap.icon}</span>
                        <span className="cap-label">{cap.label}</span>
                        {capabilities[cap.key]
                          ? <CheckCircle size={14} className="text-danger" />
                          : <XCircle size={14} className="text-dim" />}
                      </div>
                    ))}
                  </div>

                  {capabilities.capabilities?.length > 0 && (
                    <div className="sub-section">
                      <div className="sub-section-title">Detected Capabilities</div>
                      <div className="tag-cloud">
                        {capabilities.capabilities.map((c, i) => (
                          <span key={i} className="badge badge-suspicious">{c}</span>
                        ))}
                      </div>
                    </div>
                  )}
                </SectionCard>
              )}

              {/* ── Evasion ──────────────────────────────────────── */}
              {evasion && (
                <SectionCard title="Evasion Techniques" icon={<Eye size={14} />} id="evasion">
                  {/* Score */}
                  <div className="evasion-score-bar">
                    <div className="evasion-score-label">
                      Evasion Score: <strong>{evasion.evasion_score}/100</strong>
                    </div>
                    <div className="progress-bar">
                      <motion.div
                        className="progress-bar-fill"
                        initial={{ width: 0 }}
                        animate={{ width: `${evasion.evasion_score}%` }}
                        style={{ background: `linear-gradient(90deg, #ff8c00, #ff3366)` }}
                      />
                    </div>
                  </div>

                  <div className="evasion-grid">
                    {[
                      { key: 'anti_vm', label: 'Anti-VM', techniques: evasion.anti_vm_techniques },
                      { key: 'anti_sandbox', label: 'Anti-Sandbox', techniques: evasion.anti_sandbox_techniques },
                      { key: 'anti_debug', label: 'Anti-Debug', techniques: evasion.anti_debug_techniques },
                      { key: 'anti_disassembly', label: 'Anti-Disassembly', techniques: evasion.anti_disassembly_techniques },
                      { key: 'api_obfuscation', label: 'API Obfuscation', techniques: evasion.api_obfuscation_techniques },
                    ].map(cat => (
                      <div key={cat.key} className={`evasion-cat ${evasion[cat.key] ? 'detected' : ''}`}>
                        <div className="evasion-cat-header">
                          {evasion[cat.key]
                            ? <CheckCircle size={14} className="text-danger" />
                            : <XCircle size={14} className="text-dim" />}
                          <span className="evasion-cat-label">{cat.label}</span>
                        </div>
                        {evasion[cat.key] && cat.techniques?.length > 0 && (
                          <div className="evasion-techniques">
                            {cat.techniques.slice(0, 3).map((t, i) => (
                              <span key={i} className="evasion-tech">{t}</span>
                            ))}
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                </SectionCard>
              )}

              {/* ── Emulation ────────────────────────────────────── */}
              {emulation && (
                <SectionCard title="Behavioral Emulation" icon={<Terminal size={14} />} id="emulation">
                  <div className="emulation-grid">
                    {[
                      { label: 'Files Created', items: emulation.files_created, icon: '📄' },
                      { label: 'Registry Modified', items: emulation.registry_keys_modified, icon: '🔧' },
                      { label: 'Network Connections', items: emulation.network_connections?.map(n => JSON.stringify(n)), icon: '🌐' },
                      { label: 'Domains Contacted', items: emulation.domains_contacted, icon: '🔗' },
                      { label: 'Processes Created', items: emulation.processes_created, icon: '⚙️' },
                      { label: 'DLLs Loaded', items: emulation.dlls_loaded, icon: '📦' },
                    ].filter(g => g.items?.length > 0).map(group => (
                      <div key={group.label} className="emulation-group">
                        <div className="emulation-group-title">
                          {group.icon} {group.label}
                        </div>
                        {group.items.slice(0, 4).map((item, i) => (
                          <div key={i} className="emulation-item">{item}</div>
                        ))}
                      </div>
                    ))}
                  </div>
                </SectionCard>
              )}

              {/* ── Similarity ───────────────────────────────────── */}
              {similarity && similarity.matches?.length > 0 && (
                <SectionCard title="Family Similarity" icon={<BarChart2 size={14} />} id="similarity">
                  <div className="similarity-chart-wrap">
                    <ResponsiveContainer width="100%" height={220}>
                      <BarChart data={similarity.matches.slice(0, 6)} layout="vertical" margin={{ left: 100 }}>
                        <XAxis type="number" domain={[0, 1]} tickFormatter={v => `${(v * 100).toFixed(0)}%`}
                          tick={{ fill: '#64748b', fontSize: 11 }} />
                        <YAxis type="category" dataKey="family" tick={{ fill: '#94a3b8', fontSize: 12 }} />
                        <Tooltip
                          formatter={(v) => [`${(v * 100).toFixed(1)}%`, 'Similarity']}
                          contentStyle={{ background: '#070e1a', border: '1px solid rgba(0,229,255,0.2)', borderRadius: 8 }}
                          labelStyle={{ color: '#94a3b8' }}
                        />
                        <Bar dataKey="similarity" radius={[0, 4, 4, 0]}>
                          {similarity.matches.slice(0, 6).map((entry, i) => (
                            <Cell key={i} fill={entry.similarity > 0.7 ? '#ff3366' : entry.similarity > 0.5 ? '#ff8c00' : '#00e5ff'} />
                          ))}
                        </Bar>
                      </BarChart>
                    </ResponsiveContainer>
                  </div>
                  {clustering && (
                    <div className="clustering-info">
                      <span className="badge badge-info">Cluster: {clustering.cluster_label}</span>
                      {!clustering.is_novel && (
                        <span className="text-secondary text-sm">
                          ~{clustering.related_samples.toLocaleString()} related samples in corpus
                        </span>
                      )}
                      {clustering.is_novel && (
                        <span className="badge badge-unknown">Novel Sample</span>
                      )}
                    </div>
                  )}
                </SectionCard>
              )}

              {/* ── MITRE ATT&CK ─────────────────────────────────── */}
              {mitre && mitre.techniques?.length > 0 && (
                <SectionCard title="MITRE ATT&CK Coverage" icon={<Shield size={14} />} id="mitre">
                  <div className="mitre-stats">
                    <div className="mitre-stat">
                      <div className="stat-number text-accent">{mitre.technique_count}</div>
                      <div className="stat-label">Techniques</div>
                    </div>
                    <div className="mitre-stat">
                      <div className="stat-number text-accent">{mitre.tactics_covered?.length}</div>
                      <div className="stat-label">Tactics</div>
                    </div>
                  </div>

                  <div className="mitre-table-wrap">
                    <table className="vigil-table">
                      <thead>
                        <tr>
                          <th>ID</th>
                          <th>Technique</th>
                          <th>Tactic</th>
                          <th>Confidence</th>
                        </tr>
                      </thead>
                      <tbody>
                        {mitre.techniques.map(tech => (
                          <tr key={tech.technique_id}>
                            <td>
                              <a
                                href={`https://attack.mitre.org/techniques/${tech.technique_id}`}
                                target="_blank" rel="noopener"
                                className="tech-link"
                              >
                                {tech.technique_id} <ExternalLink size={10} />
                              </a>
                            </td>
                            <td>{tech.technique_name}</td>
                            <td>
                              <span
                                className="badge"
                                style={{
                                  background: `${TACTIC_COLORS[tech.tactic] || '#7c3aed'}20`,
                                  color: TACTIC_COLORS[tech.tactic] || '#7c3aed',
                                  border: `1px solid ${TACTIC_COLORS[tech.tactic] || '#7c3aed'}40`,
                                }}
                              >
                                {tech.tactic}
                              </span>
                            </td>
                            <td>
                              <ConfidenceBar value={tech.confidence} />
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </SectionCard>
              )}

              {/* ── Threat Intel ─────────────────────────────────── */}
              {threat_intel && (
                <SectionCard title="Threat Intelligence" icon={<Globe size={14} />} id="threat-intel">
                  {threat_intel.demo_mode && (
                    <div className="demo-notice">
                      ⚠️ Running in demo mode — configure API keys in .env for real threat intel
                    </div>
                  )}
                  <div className="info-grid">
                    <div className="info-row">
                      <span className="info-label">VirusTotal</span>
                      <span className="info-value">
                        <span className="text-danger">{threat_intel.virustotal_detections}</span>
                        <span className="text-secondary"> / {threat_intel.virustotal_total} engines</span>
                      </span>
                    </div>
                    <div className="info-row">
                      <span className="info-label">Verdict</span>
                      <span className="info-value text-mono">{threat_intel.virustotal_verdict || 'N/A'}</span>
                    </div>
                    <div className="info-row">
                      <span className="info-label">Known Family</span>
                      <span className="info-value text-accent">{threat_intel.known_family || 'Unknown'}</span>
                    </div>
                    <div className="info-row">
                      <span className="info-label">Campaign</span>
                      <span className="info-value">{threat_intel.campaign || 'Unknown'}</span>
                    </div>
                    <div className="info-row">
                      <span className="info-label">MalwareBazaar Tags</span>
                      <div className="tag-cloud">
                        {threat_intel.malwarebazaar_tags?.map((t, i) => (
                          <span key={i} className="badge badge-suspicious">{t}</span>
                        ))}
                      </div>
                    </div>
                  </div>
                </SectionCard>
              )}

              {/* ── RAG Intelligence ─────────────────────────────── */}
              {rag_explanation && (
                <SectionCard title="AI Analysis (RAG)" icon={<Zap size={14} />} id="rag">
                  <div className="rag-summary">
                    <p className="rag-text">{rag_explanation.summary}</p>
                  </div>
                  {rag_explanation.risk_explanation && (
                    <div className="rag-risk">
                      <div className="rag-risk-label">Risk Assessment</div>
                      <p className="text-secondary text-sm">{rag_explanation.risk_explanation}</p>
                    </div>
                  )}
                  {rag_explanation.analyst_notes && (
                    <div className="rag-risk">
                      <div className="rag-risk-label">Analyst Notes</div>
                      <p className="text-secondary text-sm">{rag_explanation.analyst_notes}</p>
                    </div>
                  )}
                  {rag_explanation.evidence_sources?.length > 0 && (
                    <div className="rag-sources">
                      <div className="rag-risk-label">Intelligence Sources</div>
                      <div className="tag-cloud">
                        {rag_explanation.evidence_sources.map((s, i) => (
                          <span key={i} className="badge badge-info">{s}</span>
                        ))}
                      </div>
                    </div>
                  )}
                </SectionCard>
              )}

              {/* ── Decompilation ────────────────────────────────── */}
              {decompilation && decompilation.functions_analyzed?.length > 0 && (
                <SectionCard title="LLM Decompilation Analysis" icon={<Code size={14} />} id="decompilation">
                  {decompilation.functions_analyzed.map((fn, i) => (
                    <div key={i} className="decompile-block">
                      <div className="decompile-header">
                        <div>
                          <span className="decompile-name">{fn.function_name}</span>
                          <span className="decompile-addr text-mono text-dim">{fn.address}</span>
                        </div>
                        <span className={`badge badge-${fn.category === 'injection' ? 'malicious' : fn.category === 'crypto' ? 'suspicious' : 'info'}`}>
                          {fn.category}
                        </span>
                      </div>
                      <div className="decompile-summary">
                        <div className="decompile-summary-label">LLM Summary</div>
                        <p className="decompile-summary-text">{fn.llm_summary}</p>
                      </div>
                      <details className="decompile-code-details">
                        <summary className="decompile-code-toggle">View decompiled code</summary>
                        <pre className="decompile-code">{fn.decompiled_code}</pre>
                      </details>
                    </div>
                  ))}
                </SectionCard>
              )}

              {/* ── YARA Rules ───────────────────────────────────── */}
              {yara && yara.rules?.length > 0 && (
                <SectionCard title="Generated YARA Rules" icon={<Database size={14} />} id="yara">
                  {yara.rules.map((rule, i) => (
                    <div key={i} className="yara-rule">
                      <div className="yara-rule-header">
                        <span className="yara-rule-name">{rule.rule_name}</span>
                        <span className={`badge badge-${rule.rule_type === 'sample' ? 'malicious' : rule.rule_type === 'family' ? 'suspicious' : 'info'}`}>
                          {rule.rule_type}
                        </span>
                      </div>
                      <pre className="yara-rule-content">{rule.rule_content}</pre>
                    </div>
                  ))}
                </SectionCard>
              )}

            </div>
          </div>
        </div>
      </main>
    </div>
  )
}

// ─── Sub-components ───────────────────────────────────────────────────────────

function VerdictIcon({ level }) {
  const size = 64
  if (level === 'malicious') return <XCircle size={size} className="verdict-icon text-danger" />
  if (level === 'suspicious') return <AlertTriangle size={size} className="verdict-icon text-warning" />
  return <CheckCircle size={size} className="verdict-icon text-success" />
}

function EntropyBar({ value }) {
  const pct = Math.min((value / 8) * 100, 100)
  const color = value > 7 ? '#ff3366' : value > 6 ? '#ff8c00' : '#00e5ff'
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
      <div style={{ width: 60, height: 4, background: 'rgba(255,255,255,0.1)', borderRadius: 2 }}>
        <div style={{ width: `${pct}%`, height: '100%', background: color, borderRadius: 2 }} />
      </div>
      <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.75rem', color }}>{value?.toFixed(2)}</span>
    </div>
  )
}

function ConfidenceBar({ value }) {
  const pct = Math.round(value * 100)
  const color = pct > 70 ? '#ff3366' : pct > 40 ? '#ff8c00' : '#00e5ff'
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
      <div style={{ width: 50, height: 4, background: 'rgba(255,255,255,0.1)', borderRadius: 2 }}>
        <div style={{ width: `${pct}%`, height: '100%', background: color, borderRadius: 2 }} />
      </div>
      <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.75rem', color }}>{pct}%</span>
    </div>
  )
}

function LoadingScreen() {
  return (
    <div style={{ minHeight: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center', flexDirection: 'column', gap: 16 }}>
      <div className="upload-spinner" style={{ width: 48, height: 48, borderWidth: 3 }} />
      <p className="text-secondary">Loading report...</p>
    </div>
  )
}

function ErrorScreen({ error, onBack }) {
  return (
    <div style={{ minHeight: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center', flexDirection: 'column', gap: 16 }}>
      <XCircle size={48} className="text-danger" />
      <h2>Failed to load report</h2>
      <p className="text-secondary">{error}</p>
      <button className="btn btn-primary" onClick={onBack}>Back to Home</button>
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
