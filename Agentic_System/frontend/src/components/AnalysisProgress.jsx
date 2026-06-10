'use client';

import React from 'react';
import { PIPELINE_STEPS } from '../lib/constants';
import * as Icons from 'lucide-react';

export default function AnalysisProgress({ currentStep = 'initialization', progress = 0 }) {
  // Map step key to progress indexes
  const stepOrder = PIPELINE_STEPS.map(s => s.id);
  const currentIndex = stepOrder.indexOf(currentStep);

  return (
    <div className="glass-panel" style={{
      padding: '24px',
      background: 'rgba(16, 22, 42, 0.4)',
      width: '100%',
      display: 'flex',
      flexDirection: 'column',
      gap: '20px'
    }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <span style={{ fontSize: '15px', fontWeight: '700', letterSpacing: '0.05em' }}>
          ANALYSIS PIPELINE
        </span>
        <span style={{ fontSize: '14px', fontFamily: 'var(--font-mono)', color: 'var(--color-primary)' }}>
          {Math.round(progress * 100)}%
        </span>
      </div>

      <div className="progress-container">
        <div className="progress-bar" style={{ width: `${progress * 100}%` }} />
      </div>

      <div style={{
        display: 'flex',
        justifyContent: 'space-between',
        position: 'relative',
        paddingTop: '10px'
      }}>
        {PIPELINE_STEPS.map((step, idx) => {
          const StepIcon = Icons[step.icon] || Icons.HelpCircle;
          
          let status = 'pending'; // pending, active, completed
          if (idx < currentIndex) {
            status = 'completed';
          } else if (idx === currentIndex) {
            status = 'active';
          }

          let color = 'var(--text-dark)';
          let bg = 'rgba(255, 255, 255, 0.02)';
          let border = '1px solid var(--border-color)';

          if (status === 'completed') {
            color = 'var(--color-success)';
            bg = 'var(--color-success-glow)';
            border = '1px solid var(--color-success)';
          } else if (status === 'active') {
            color = 'var(--color-primary)';
            bg = 'var(--color-primary-glow)';
            border = '1px solid var(--color-primary)';
          }

          return (
            <div key={step.id} style={{
              display: 'flex',
              flexDirection: 'column',
              alignItems: 'center',
              gap: '8px',
              width: '80px',
              textAlign: 'center'
            }}>
              <div style={{
                width: '36px',
                height: '36px',
                borderRadius: '50%',
                background: bg,
                border: border,
                color: color,
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                transition: 'all 0.3s ease',
                boxShadow: status === 'active' ? '0 0 10px rgba(0, 212, 255, 0.2)' : 'none',
              }} className={status === 'active' ? 'animate-pulse-glow' : ''}>
                <StepIcon size={16} />
              </div>
              <span style={{
                fontSize: '11px',
                fontWeight: '600',
                color: status === 'pending' ? 'var(--text-muted)' : 'var(--text-main)',
                transition: 'color 0.3s ease'
              }}>
                {step.label}
              </span>
            </div>
          );
        })}
      </div>
    </div>
  );
}
