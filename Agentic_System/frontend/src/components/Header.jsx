'use client';

import React from 'react';
import Link from 'next/link';
import { Shield, Settings, LayoutDashboard, Radio } from 'lucide-react';

export default function Header({ isWsConnected = false }) {
  return (
    <header className="glass-panel" style={{
      position: 'fixed',
      top: 0,
      left: 0,
      width: '100%',
      height: '64px',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'space-between',
      padding: '0 24px',
      zIndex: 100,
      borderRadius: '0 0 12px 12px',
      borderTop: 'none',
      borderLeft: 'none',
      borderRight: 'none',
      background: 'rgba(10, 14, 26, 0.7)'
    }}>
      <Link href="/" style={{ display: 'flex', alignItems: 'center', textDecoration: 'none' }}>
        <img 
          src="/vigil-logo.svg" 
          alt="ViGil Logo" 
          style={{ 
            height: '32px', 
            display: 'block',
            userSelect: 'none',
            pointerEvents: 'none'
          }} 
        />
      </Link>

      <nav style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
        <Link href="/" className="btn-ghost" style={{ display: 'flex', alignItems: 'center', gap: '8px', padding: '8px 12px', fontSize: '14px' }}>
          <LayoutDashboard size={16} />
          Dashboard
        </Link>
        <Link href="/settings" className="btn-ghost" style={{ display: 'flex', alignItems: 'center', gap: '8px', padding: '8px 12px', fontSize: '14px' }}>
          <Settings size={16} />
          Settings
        </Link>
        
        {/* Status indicator */}
        <div style={{
          display: 'flex',
          alignItems: 'center',
          gap: '6px',
          padding: '4px 10px',
          borderRadius: '20px',
          background: isWsConnected ? 'rgba(0, 255, 136, 0.08)' : 'rgba(255, 51, 102, 0.08)',
          border: `1px solid ${isWsConnected ? 'rgba(0, 255, 136, 0.2)' : 'rgba(255, 51, 102, 0.2)'}`,
          fontSize: '11px',
          fontWeight: '600',
          color: isWsConnected ? 'var(--color-success)' : 'var(--color-danger)',
          marginLeft: '12px'
        }}>
          <Radio size={12} className={isWsConnected ? 'animate-pulse-glow' : ''} />
          {isWsConnected ? 'LIVE' : 'DISCONNECTED'}
        </div>
      </nav>
    </header>
  );
}
