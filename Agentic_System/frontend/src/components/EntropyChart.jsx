'use client';

import React from 'react';

export default function EntropyChart({ sectionEntropies = {} }) {
  const entries = Object.entries(sectionEntropies);

  if (entries.length === 0) {
    return (
      <div style={{ padding: '24px', textAlign: 'center', color: 'var(--text-muted)', fontSize: '13px' }}>
        No section entropy data available.
      </div>
    );
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '16px', width: '100%' }}>
      <span style={{ fontSize: '12px', fontWeight: '700', color: 'var(--text-muted)', letterSpacing: '0.05em' }}>
        PE SECTION ENTROPY (0.0 - 8.0)
      </span>

      <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
        {entries.map(([name, val]) => {
          // Color based on entropy (above 7.2 is high, above 5.0 is compressed)
          let barColor = 'var(--color-success)';
          if (val >= 7.2) {
            barColor = 'var(--color-danger)';
          } else if (val >= 5.0) {
            barColor = 'var(--color-warning)';
          }

          const pct = (val / 8.0) * 100;

          return (
            <div key={name} style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '13px' }}>
                <span style={{ fontFamily: 'var(--font-mono)', fontWeight: '600' }}>{name}</span>
                <span style={{ fontFamily: 'var(--font-mono)', color: barColor, fontWeight: '700' }}>{val}</span>
              </div>
              <div style={{
                width: '100%',
                height: '8px',
                background: 'rgba(255,255,255,0.03)',
                borderRadius: '4px',
                overflow: 'hidden',
                border: '1px solid var(--border-color)'
              }}>
                <div style={{
                  width: `${pct}%`,
                  height: '100%',
                  background: barColor,
                  borderRadius: '4px',
                  boxShadow: `0 0 8px ${barColor}`,
                  transition: 'width 0.8s cubic-bezier(0.4, 0, 0.2, 1)'
                }} />
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
