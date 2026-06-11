'use client';

import React, { useState, useEffect } from 'react';
import { useRouter } from 'next/navigation';
import FileUpload from '../components/FileUpload';
import { useAnalysis } from '../hooks/useAnalysis';
import { api } from '../lib/api';
import { Info, Play, ShieldCheck, Cpu, Database, AlertTriangle } from 'lucide-react';
import Link from 'next/link';

export default function Dashboard() {
  const router = useRouter();
  const [systemStatus, setSystemStatus] = useState(null);
  const [history, setHistory] = useState([]);
  
  const { uploadFile, uploadProgress, status, error } = useAnalysis();

  useEffect(() => {
    async function loadStats() {
      try {
        const stats = await fetch('http://localhost:8000/').then(r => r.json());
        setSystemStatus(stats);
        
        const past = await api.getAnalysisHistory();
        setHistory(past || []);
      } catch (e) {
        console.error("Failed to load status metrics:", e);
      }
    }
    loadStats();
  }, []);

  const handleUploadSuccess = (analysisId) => {
    router.push(`/analysis/${analysisId}`);
  };

  const recentItems = history.slice(0, 4);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '32px', width: '100%' }} className="animate-slide">
      {/* Hero Header */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '40px', flexWrap: 'wrap' }}>
        <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', flex: '1', minWidth: '300px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '4px' }}>
            <span style={{ 
              padding: '4px 10px', 
              fontSize: '10px', 
              fontWeight: '700', 
              letterSpacing: '0.1em',
              background: 'rgba(0, 242, 254, 0.08)',
              border: '1px solid rgba(0, 242, 254, 0.2)',
              borderRadius: '20px',
              color: 'var(--color-primary)'
            }}>
              VIGIL SECURITY v1.0.0
            </span>
          </div>
          <h1 style={{
            fontSize: '36px',
            fontWeight: '900',
            letterSpacing: '-0.03em',
            background: 'linear-gradient(90deg, #ffffff, #8b5cf6, var(--color-primary))',
            WebkitBackgroundClip: 'text',
            WebkitTextFillColor: 'transparent',
            lineHeight: '1.2'
          }}>
            Agentic Malware Analysis &amp; Forensics
          </h1>
          <p style={{ color: 'var(--text-muted)', fontSize: '15px', lineHeight: '1.6', maxWidth: '720px' }}>
            Deconstruct payloads dynamically. ViGil combines a joint multi-modal deep learning model
            with a parallelized CrewAI security agent swarm to analyze malware structural characteristics,
            API import behaviors, strings, obfuscation patterns, and evasion techniques.
          </p>
        </div>
        
        {/* Large Brand Icon Showcase */}
        <div style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          width: '120px',
          height: '120px',
          borderRadius: '24px',
          background: 'rgba(255, 255, 255, 0.01)',
          border: '1px solid rgba(255, 255, 255, 0.05)',
          padding: '16px',
          boxShadow: '0 8px 32px 0 rgba(0, 242, 254, 0.05), inset 0 0 24px rgba(139, 92, 246, 0.05)',
          backdropFilter: 'blur(8px)',
          userSelect: 'none'
        }} className="glass-card">
          <img 
            src="/vigil-icon.svg" 
            alt="ViGil Logo Symbol" 
            style={{ 
              width: '100%', 
              height: '100%', 
              filter: 'drop-shadow(0 0 10px rgba(0, 242, 254, 0.2))'
            }} 
          />
        </div>
      </div>

      {/* Upload zone */}
      <div className="glass-panel" style={{ padding: '32px', background: 'rgba(12, 17, 34, 0.4)' }}>
        <FileUpload
          onUploadSuccess={handleUploadSuccess}
          uploadFile={uploadFile}
          uploadProgress={uploadProgress}
          status={status}
        />
        {error && (
          <div style={{
            display: 'flex',
            alignItems: 'center',
            gap: '10px',
            padding: '12px 16px',
            borderRadius: '8px',
            background: 'var(--color-danger-glow)',
            border: '1px solid rgba(255, 51, 102, 0.2)',
            color: 'var(--color-danger)',
            fontSize: '13px',
            marginTop: '16px'
          }}>
            <AlertTriangle size={18} />
            {error}
          </div>
        )}
      </div>

      {/* Grid: Recent Analyses & System Status */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 340px', gap: '24px' }}>
        {/* Recent reports list */}
        <div className="glass-panel" style={{ padding: '24px', background: 'rgba(16, 22, 42, 0.3)', display: 'flex', flexDirection: 'column', gap: '16px' }}>
          <span style={{ fontSize: '12px', fontWeight: '700', color: 'var(--text-muted)', letterSpacing: '0.05em' }}>
            RECENTLY PROCESSED SAMPLES
          </span>

          {recentItems.length === 0 ? (
            <div style={{ padding: '40px 0', textAlign: 'center', color: 'var(--text-muted)', fontSize: '13px' }}>
              No samples analyzed yet. Upload a file above to begin.
            </div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
              {recentItems.map((item) => {
                const isMal = item.verdict === 'MALWARE';
                return (
                  <div key={item.id} style={{
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                    padding: '14px 18px',
                    borderRadius: '8px',
                    background: 'rgba(255, 255, 255, 0.02)',
                    border: '1px solid var(--border-color)',
                  }}>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
                      <span style={{ fontSize: '14px', fontWeight: '600', color: '#fff' }}>{item.file_name}</span>
                      <span style={{ fontSize: '11px', color: 'var(--text-muted)' }}>SHA256: {item.file_hash.substring(0, 12)}...</span>
                    </div>

                    <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
                      <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-end', gap: '2px' }}>
                        <span className={isMal ? "badge badge-malware" : "badge badge-benign"}>
                          {item.verdict}
                        </span>
                        <span style={{ fontSize: '11px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
                          Score: {item.risk_score}
                        </span>
                      </div>

                      <Link href={`/analysis/${item.id}`} className="btn-secondary" style={{ padding: '6px 12px', fontSize: '12px', gap: '4px' }}>
                        <Play size={12} />
                        View
                      </Link>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>

        {/* System parameters panel */}
        <div className="glass-panel" style={{ padding: '24px', background: 'rgba(16, 22, 42, 0.3)', display: 'flex', flexDirection: 'column', gap: '16px' }}>
          <span style={{ fontSize: '12px', fontWeight: '700', color: 'var(--text-muted)', letterSpacing: '0.05em' }}>
            ENGINE STATUS METRICS
          </span>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px', color: 'var(--text-muted)', fontSize: '13px' }}>
                <ShieldCheck size={16} />
                <span>Backend Status</span>
              </div>
              <span className="badge badge-benign" style={{ padding: '2px 8px' }}>
                {systemStatus?.status || 'OFFLINE'}
              </span>
            </div>

            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px', color: 'var(--text-muted)', fontSize: '13px' }}>
                <Cpu size={16} />
                <span>ML Model Predictor</span>
              </div>
              <span className={systemStatus?.ml_model_loaded ? "badge badge-benign" : "badge badge-warning"}>
                {systemStatus?.ml_model_loaded ? 'LOADED' : 'UNLOADED'}
              </span>
            </div>

            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px', color: 'var(--text-muted)', fontSize: '13px' }}>
                <Database size={16} />
                <span>Active Provider</span>
              </div>
              <span style={{ fontSize: '12px', fontWeight: '700', fontFamily: 'var(--font-mono)' }}>
                {systemStatus?.active_llm_provider?.toUpperCase() || 'NONE'}
              </span>
            </div>
            
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px', color: 'var(--text-muted)', fontSize: '13px' }}>
                <Info size={16} />
                <span>Compute Target</span>
              </div>
              <span style={{ fontSize: '12px', fontWeight: '700', fontFamily: 'var(--font-mono)', color: 'var(--color-primary)' }}>
                {systemStatus?.device?.toUpperCase() || 'CPU'}
              </span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
