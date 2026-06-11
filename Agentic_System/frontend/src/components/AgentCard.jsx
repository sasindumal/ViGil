'use client';

import React, { useState } from 'react';
import { Play, CheckCircle, XCircle, Loader, ChevronDown, ChevronUp } from 'lucide-react';
import { AGENT_ROLES } from '../lib/constants';

export default function AgentCard({ roleName = '', activity = null }) {
  const [expanded, setExpanded] = useState(false);
  const meta = AGENT_ROLES[roleName] || { color: '#6b7280', number: 0, type: 'unknown' };

  // Status mapping
  const actStatus = activity?.status || 'idle'; // idle, thinking, completed, failed
  const outputText = activity?.output || '';
  const errorText = activity?.error || '';
  const statusMsg = activity?.message || 'Idle';

  let statusColor = 'var(--text-dark)';
  let bgGlow = 'rgba(255, 255, 255, 0.01)';
  let border = '1px solid var(--border-color)';
  let StatusIcon = Play;

  if (actStatus === 'thinking') {
    statusColor = 'var(--color-warning)';
    bgGlow = 'rgba(255, 184, 0, 0.05)';
    border = '1px solid var(--color-warning)';
    StatusIcon = Loader;
  } else if (actStatus === 'completed') {
    statusColor = 'var(--color-success)';
    bgGlow = 'rgba(0, 255, 136, 0.05)';
    border = '1px solid var(--color-success)';
    StatusIcon = CheckCircle;
  } else if (actStatus === 'failed') {
    statusColor = 'var(--color-danger)';
    bgGlow = 'rgba(255, 51, 102, 0.05)';
    border = '1px solid var(--color-danger)';
    StatusIcon = XCircle;
  }

  const toggleExpand = () => {
    if (outputText || errorText) {
      setExpanded(prev => !prev);
    }
  };

  return (
    <div className="glass-panel" style={{
      background: bgGlow,
      border: border,
      borderRadius: '12px',
      padding: '16px',
      display: 'flex',
      flexDirection: 'column',
      gap: '12px',
      transition: 'all 0.3s ease',
      boxShadow: actStatus === 'thinking' ? '0 0 15px rgba(255, 184, 0, 0.1)' : 'none',
      opacity: actStatus === 'idle' ? 0.5 : 1,
    }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          <div style={{
            width: '24px',
            height: '24px',
            borderRadius: '50%',
            background: meta.color,
            color: '#000',
            fontWeight: '700',
            fontSize: '11px',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center'
          }}>
            {meta.number}
          </div>
          <div style={{ display: 'flex', flexDirection: 'column' }}>
            <span style={{ fontSize: '14px', fontWeight: '700', color: 'var(--text-main)' }}>
              {roleName.replace('Analyst', '').replace('Specialist', '').replace('Coordinator', '').trim()}
            </span>
            <span style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
              Agent {meta.number} • {meta.type.toUpperCase()}
            </span>
          </div>
        </div>

        <div style={{
          display: 'flex',
          alignItems: 'center',
          gap: '6px',
          color: statusColor,
          fontSize: '12px',
          fontWeight: '600'
        }}>
          <StatusIcon size={14} className={actStatus === 'thinking' ? 'animate-pulse-glow' : ''} />
          {statusMsg}
        </div>
      </div>

      {(actStatus === 'completed' && outputText) && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
          <div style={{
            background: 'rgba(0, 0, 0, 0.2)',
            padding: '10px',
            borderRadius: '6px',
            fontSize: '12px',
            color: 'var(--text-muted)',
            maxHeight: expanded ? '300px' : '44px',
            overflowY: 'auto',
            whiteSpace: 'pre-wrap',
            fontFamily: var_font_mono,
            transition: 'max-height 0.3s ease',
            border: '1px solid rgba(255, 255, 255, 0.03)'
          }}>
            {outputText}
          </div>
          
          <button onClick={toggleExpand} style={{
            display: 'flex',
            alignItems: 'center',
            gap: '4px',
            alignSelf: 'flex-end',
            background: 'none',
            border: 'none',
            color: 'var(--color-primary)',
            fontSize: '11px',
            cursor: 'pointer',
            fontWeight: '600'
          }}>
            {expanded ? (
              <>Collapse <ChevronUp size={12} /></>
            ) : (
              <>Expand findings <ChevronDown size={12} /></>
            )}
          </button>
        </div>
      )}

      {actStatus === 'failed' && (
        <div style={{
          background: 'rgba(255, 51, 102, 0.04)',
          border: '1px solid rgba(255, 51, 102, 0.15)',
          padding: '10px',
          borderRadius: '6px',
          fontSize: '12px',
          color: 'var(--color-danger)'
        }}>
          Error: {errorText}
        </div>
      )}
    </div>
  );
}

const var_font_mono = 'var(--font-mono)';
