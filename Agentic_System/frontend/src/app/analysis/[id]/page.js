'use client';

import React, { useState } from 'react';
import { useParams } from 'next/navigation';
import { useAnalysis } from '../../../hooks/useAnalysis';
import AnalysisProgress from '../../../components/AnalysisProgress';
import AgentActivity from '../../../components/AgentActivity';
import RiskGauge from '../../../components/RiskGauge';
import EntropyChart from '../../../components/EntropyChart';
import ReportViewer from '../../../components/ReportViewer';
import { Eye, FileText, Cpu, ListCollapse, BookOpen, Layers, UserCheck } from 'lucide-react';

export default function AnalysisView() {
  const params = useParams();
  const { id } = params;

  const {
    status,
    progress,
    fileInfo,
    results,
    report,
    error,
    agentActivity,
  } = useAnalysis(id);

  const [activeTab, setActiveTab] = useState('overview'); // overview, details, agents, report
  const [activeAccordion, setActiveAccordion] = useState('headers');

  if (error) {
    return (
      <div className="glass-panel animate-fade" style={{ padding: '24px', border: '1px solid var(--color-danger)', background: 'var(--color-danger-glow)', color: 'var(--color-danger)' }}>
        <h2 style={{ fontSize: '18px', fontWeight: '700', marginBottom: '8px' }}>Analysis Failed</h2>
        <p>{error}</p>
      </div>
    );
  }

  const isComplete = status === 'completed';
  const showResults = isComplete && results;

  // Extract variables
  const isMal = fileInfo?.verdict === 'MALWARE';
  const riskScore = fileInfo?.risk_score || 0.0;
  const confidence = fileInfo?.confidence || 0.0;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '32px', width: '100%' }}>
      {/* Header Info */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }} className="animate-fade">
        <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
          <h1 style={{ fontSize: '24px', fontWeight: '800', color: '#fff' }}>
            {fileInfo?.file_name || 'Analyzing sample...'}
          </h1>
          <span style={{ fontSize: '13px', color: 'var(--text-muted)' }}>
            Session ID: {id} {fileInfo?.file_size ? `• Size: ${fileInfo.file_size} bytes` : ''}
          </span>
        </div>
        {showResults && (
          <span className={isMal ? "badge badge-malware" : "badge badge-benign"} style={{ padding: '6px 12px', fontSize: '13px' }}>
            {fileInfo.verdict}
          </span>
        )}
      </div>

      {/* Stepper progress */}
      <AnalysisProgress currentStep={status} progress={progress} />

      {/* Live agent activity grid */}
      {!isComplete && (
        <AgentActivity route={fileInfo?.route || 'pe'} agentActivity={agentActivity} />
      )}

      {/* Results Tab interface */}
      {showResults && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }} className="animate-slide">
          {/* Tabs */}
          <div style={{
            display: 'flex',
            gap: '8px',
            borderBottom: '1px solid var(--border-color)',
            paddingBottom: '8px'
          }}>
            {[
              { id: 'overview', label: 'Overview', icon: Eye },
              { id: 'details', label: 'Deep Static Details', icon: Layers },
              { id: 'agents', label: 'Agent Findings', icon: UserCheck },
              { id: 'report', label: 'Threat Report', icon: FileText }
            ].map((tab) => {
              const Icon = tab.icon;
              const isActive = activeTab === tab.id;
              return (
                <button
                  key={tab.id}
                  onClick={() => setActiveTab(tab.id)}
                  style={{
                    background: isActive ? 'rgba(0, 212, 255, 0.08)' : 'transparent',
                    border: '1px solid ' + (isActive ? 'var(--color-primary)' : 'transparent'),
                    color: isActive ? 'var(--color-primary)' : 'var(--text-muted)',
                    padding: '8px 16px',
                    borderRadius: '6px',
                    cursor: 'pointer',
                    fontSize: '13px',
                    fontWeight: '600',
                    display: 'flex',
                    alignItems: 'center',
                    gap: '8px',
                    transition: 'all 0.2s ease',
                  }}
                >
                  <Icon size={14} />
                  {tab.label}
                </button>
              );
            })}
          </div>

          {/* Tab Content: Overview */}
          {activeTab === 'overview' && (
            <div style={{ display: 'grid', gridTemplateColumns: '320px 1fr', gap: '24px' }}>
              <div className="glass-panel" style={{ padding: '24px', background: 'rgba(16, 22, 42, 0.4)', height: 'fit-content' }}>
                <RiskGauge score={riskScore} />
              </div>

              <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
                {/* Stats panel */}
                <div className="glass-panel" style={{ padding: '24px', background: 'rgba(16, 22, 42, 0.3)', display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '24px' }}>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
                    <span style={{ fontSize: '11px', fontWeight: '700', color: 'var(--text-muted)', letterSpacing: '0.05em' }}>VERDICT CONFIDENCE</span>
                    <span style={{ fontSize: '20px', fontWeight: '800', color: '#fff', fontFamily: 'var(--font-mono)' }}>{confidence}%</span>
                  </div>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
                    <span style={{ fontSize: '11px', fontWeight: '700', color: 'var(--text-muted)', letterSpacing: '0.05em' }}>PIPELINE ROUTE</span>
                    <span style={{ fontSize: '20px', fontWeight: '800', color: 'var(--color-primary)', fontFamily: 'var(--font-mono)' }}>{results.route.toUpperCase()}</span>
                  </div>
                </div>

                {/* Heuristic indicators */}
                <div className="glass-panel" style={{ padding: '24px', background: 'rgba(16, 22, 42, 0.3)', display: 'flex', flexDirection: 'column', gap: '12px' }}>
                  <span style={{ fontSize: '12px', fontWeight: '700', color: 'var(--text-muted)', letterSpacing: '0.05em' }}>THREAT MATRIX HIGH THREAT INDICATORS</span>
                  
                  {results.pe_results && results.pe_results.length > 0 ? (
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
                      {results.pe_results[0].static_analysis.sections?.red_flags?.map((flag, idx) => (
                        <div key={idx} style={{
                          padding: '10px 14px',
                          borderRadius: '6px',
                          background: 'rgba(255, 51, 102, 0.04)',
                          border: '1px solid rgba(255, 51, 102, 0.1)',
                          fontSize: '13px',
                          color: 'var(--color-danger)'
                        }}>
                          <strong>[{flag.type.toUpperCase()}]</strong> {flag.detail}
                        </div>
                      ))}
                    </div>
                  ) : (
                    <p style={{ fontSize: '13px', color: 'var(--text-muted)' }}>No static PE anomalies flagged.</p>
                  )}
                </div>
              </div>
            </div>
          )}

          {/* Tab Content: Details Accordion */}
          {activeTab === 'details' && (
            <div style={{ display: 'grid', gridTemplateColumns: '240px 1fr', gap: '24px' }}>
              {/* Accordion Left selectors */}
              <div className="glass-panel" style={{ padding: '16px 8px', display: 'flex', flexDirection: 'column', gap: '4px', height: 'fit-content' }}>
                {[
                  { id: 'headers', label: 'Headers & Flags' },
                  { id: 'sections', label: 'Section Details' },
                  { id: 'imports', label: 'Import API Table' },
                  { id: 'exports', label: 'Export Table' },
                  { id: 'entropy', label: 'Entropy Matrix' },
                  { id: 'debug', label: 'Evasion & Anti-Debug' },
                  { id: 'resources', label: 'Resources' },
                  { id: 'overlay', label: 'Overlay Data' },
                  { id: 'memory', label: 'Memory Layout' },
                ].map((item) => {
                  const isActive = activeAccordion === item.id;
                  return (
                    <button
                      key={item.id}
                      onClick={() => setActiveAccordion(item.id)}
                      style={{
                        background: isActive ? 'rgba(255,255,255,0.03)' : 'transparent',
                        color: isActive ? '#fff' : 'var(--text-muted)',
                        padding: '10px 14px',
                        border: 'none',
                        borderRadius: '6px',
                        cursor: 'pointer',
                        textAlign: 'left',
                        fontSize: '13px',
                        fontWeight: '600',
                        transition: 'all 0.2s ease',
                      }}
                    >
                      {item.label}
                    </button>
                  );
                })}
              </div>

              {/* Accordion Right details panels */}
              <div className="glass-panel" style={{ padding: '24px', background: 'rgba(16, 22, 42, 0.3)' }}>
                {results.pe_results && results.pe_results.length > 0 ? (
                  <>
                    {/* Headers details */}
                    {activeAccordion === 'headers' && (
                      <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
                        <h3>DOS / NT / Optional Headers</h3>
                        <pre>
                          {JSON.stringify(results.pe_results[0].static_analysis.headers, null, 2)}
                        </pre>
                      </div>
                    )}

                    {/* Section details */}
                    {activeAccordion === 'sections' && (
                      <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
                        <h3>Sections Enumeration</h3>
                        <table>
                          <thead>
                            <tr>
                              <th>Name</th>
                              <th>RVA</th>
                              <th>Size</th>
                              <th>Entropy</th>
                              <th>Writable</th>
                              <th>Executable</th>
                            </tr>
                          </thead>
                          <tbody>
                            {results.pe_results[0].static_analysis.sections?.sections?.map((s, idx) => (
                              <tr key={idx}>
                                <td style={{ fontFamily: 'var(--font-mono)' }}>{s.name}</td>
                                <td style={{ fontFamily: 'var(--font-mono)' }}>{s.virtual_address}</td>
                                <td>{s.virtual_size} bytes</td>
                                <td style={{ fontFamily: 'var(--font-mono)' }}>{s.entropy}</td>
                                <td>{s.flags?.writable ? 'YES' : 'NO'}</td>
                                <td>{s.flags?.executable ? 'YES' : 'NO'}</td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    )}

                    {/* Imports details */}
                    {activeAccordion === 'imports' && (
                      <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
                        <h3>Import Address Table</h3>
                        <div style={{ maxHeight: '400px', overflowY: 'auto' }}>
                          <table>
                            <thead>
                              <tr>
                                <th>DLL</th>
                                <th>Function</th>
                                <th>Categories</th>
                              </tr>
                            </thead>
                            <tbody>
                              {results.pe_results[0].static_analysis.imports?.suspicious_apis?.map((imp, idx) => (
                                <tr key={idx}>
                                  <td style={{ fontFamily: 'var(--font-mono)' }}>{imp.dll}</td>
                                  <td style={{ fontFamily: 'var(--font-mono)' }}>{imp.function}</td>
                                  <td>{imp.categories?.join(', ')}</td>
                                </tr>
                              ))}
                            </tbody>
                          </table>
                        </div>
                      </div>
                    )}

                    {/* Exports details */}
                    {activeAccordion === 'exports' && (
                      <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
                        <h3>Export Table</h3>
                        <pre>
                          {JSON.stringify(results.pe_results[0].static_analysis.exports, null, 2)}
                        </pre>
                      </div>
                    )}

                    {/* Entropy details */}
                    {activeAccordion === 'entropy' && (
                      <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
                        <EntropyChart sectionEntropies={results.pe_results[0].static_analysis.entropy?.section_entropies} />
                        <div>
                          <strong>File-Level Entropy: </strong>
                          {results.pe_results[0].static_analysis.entropy?.file_entropy} ({results.pe_results[0].static_analysis.entropy?.entropy_class})
                        </div>
                      </div>
                    )}

                    {/* Evasion details */}
                    {activeAccordion === 'debug' && (
                      <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
                        <h3>Evasion & Debug Features</h3>
                        <pre>
                          {JSON.stringify(results.pe_results[0].static_analysis.debug_features, null, 2)}
                        </pre>
                      </div>
                    )}

                    {/* Resources details */}
                    {activeAccordion === 'resources' && (
                      <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
                        <h3>Resource Tree</h3>
                        <pre>
                          {JSON.stringify(results.pe_results[0].static_analysis.resources, null, 2)}
                        </pre>
                      </div>
                    )}

                    {/* Overlay details */}
                    {activeAccordion === 'overlay' && (
                      <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
                        <h3>Overlay Appended Data</h3>
                        <pre>
                          {JSON.stringify(results.pe_results[0].static_analysis.overlay, null, 2)}
                        </pre>
                      </div>
                    )}

                    {/* Memory details */}
                    {activeAccordion === 'memory' && (
                      <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
                        <h3>Memory Load Map Simulation</h3>
                        <pre>
                          {JSON.stringify(results.pe_results[0].static_analysis.memory_layout, null, 2)}
                        </pre>
                      </div>
                    )}
                  </>
                ) : (
                  <div>No PE Static details available (analyzed sample is a Script).</div>
                )}
              </div>
            </div>
          )}

          {/* Tab Content: Agent Consensus */}
          {activeTab === 'agents' && (
            <AgentActivity route={fileInfo?.route} agentActivity={agentActivity} />
          )}

          {/* Tab Content: Report */}
          {activeTab === 'report' && (
            <ReportViewer analysisId={id} markdown={report} />
          )}
        </div>
      )}
    </div>
  );
}
