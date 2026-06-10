'use client';

import React from 'react';
import Link from 'next/link';
import { Home, History, Shield, Settings, Info } from 'lucide-react';

export default function Sidebar({ history = [] }) {
  return (
    <aside className="glass-panel" style={{
      position: 'fixed',
      top: '80px',
      left: '24px',
      width: '260px',
      height: 'calc(100vh - 104px)',
      padding: '24px 16px',
      display: 'flex',
      flexDirection: 'column',
      gap: '24px',
      background: 'rgba(10, 14, 26, 0.4)',
      zIndex: 90,
    }}>
      <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
        <span style={{ fontSize: '11px', fontWeight: '700', color: 'var(--text-dark)', letterSpacing: '0.1em', paddingLeft: '8px' }}>
          NAVIGATION
        </span>
        <Link href="/" className="btn-ghost" style={{ display: 'flex', alignItems: 'center', gap: '10px', justifyContent: 'flex-start', padding: '10px 12px', fontSize: '14px', width: '100%' }}>
          <Home size={18} />
          Dashboard
        </Link>
        <Link href="/settings" className="btn-ghost" style={{ display: 'flex', alignItems: 'center', gap: '10px', justifyContent: 'flex-start', padding: '10px 12px', fontSize: '14px', width: '100%' }}>
          <Settings size={18} />
          LLM Providers
        </Link>
      </div>

      <div style={{ display: 'flex', flexDirection: 'column', gap: '12px', flexGrow: 1, overflowY: 'auto' }}>
        <span style={{ fontSize: '11px', fontWeight: '700', color: 'var(--text-dark)', letterSpacing: '0.1em', paddingLeft: '8px' }}>
          RECENT ANALYSES
        </span>
        
        {history.length === 0 ? (
          <div style={{ padding: '20px 8px', textAlign: 'center', color: 'var(--text-muted)', fontSize: '12px', display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '8px' }}>
            <Info size={16} />
            No past records found
          </div>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
            {history.map((item) => {
              const isMal = item.verdict === 'MALWARE';
              return (
                <Link key={item.id} href={`/analysis/${item.id}`} style={{
                  display: 'flex',
                  flexDirection: 'column',
                  gap: '4px',
                  padding: '10px',
                  borderRadius: '8px',
                  background: 'rgba(255, 255, 255, 0.02)',
                  border: '1px solid var(--border-color)',
                  transition: 'all 0.2s ease',
                }} className="glass-card-sm">
                  <span style={{ fontSize: '13px', fontWeight: '600', color: 'var(--text-main)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                    {item.file_name}
                  </span>
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', fontSize: '10px' }}>
                    <span style={{
                      color: isMal ? 'var(--color-danger)' : 'var(--color-success)',
                      fontWeight: '700'
                    }}>
                      {item.verdict}
                    </span>
                    <span style={{ color: 'var(--text-muted)' }}>
                      Score: {item.risk_score}
                    </span>
                  </div>
                </Link>
              );
            })}
          </div>
        )}
      </div>
    </aside>
  );
}
