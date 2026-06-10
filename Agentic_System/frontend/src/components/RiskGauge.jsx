'use client';

import React from 'react';

export default function RiskGauge({ score = 0, size = 160 }) {
  const strokeWidth = 14;
  const radius = (size - strokeWidth) / 2;
  const circumference = radius * 2 * Math.PI;
  const strokeDashoffset = circumference - (score / 100) * circumference;

  // Determine threat level color
  let color = 'var(--color-success)';
  let label = 'Low Risk';
  if (score >= 80) {
    color = 'var(--color-danger)';
    label = 'Critical Threat';
  } else if (score >= 60) {
    color = 'var(--color-danger)';
    label = 'High Risk';
  } else if (score >= 35) {
    color = 'var(--color-warning)';
    label = 'Medium Risk';
  }

  return (
    <div style={{
      display: 'flex',
      flexDirection: 'column',
      alignItems: 'center',
      gap: '12px',
      justifyContent: 'center',
      height: '100%'
    }}>
      <div style={{ position: 'relative', width: size, height: size }}>
        <svg width={size} height={size} style={{ transform: 'rotate(-90deg)' }}>
          {/* Background circle */}
          <circle
            cx={size / 2}
            cy={size / 2}
            r={radius}
            fill="transparent"
            stroke="rgba(255, 255, 255, 0.04)"
            strokeWidth={strokeWidth}
          />
          {/* Active progress arc */}
          <circle
            cx={size / 2}
            cy={size / 2}
            r={radius}
            fill="transparent"
            stroke={color}
            strokeWidth={strokeWidth}
            strokeDasharray={circumference}
            strokeDashoffset={strokeDashoffset}
            strokeLinecap="round"
            style={{
              transition: 'stroke-dashoffset 0.8s cubic-bezier(0.4, 0, 0.2, 1)',
              filter: `drop-shadow(0 0 6px ${color})`
            }}
          />
        </svg>

        {/* Center Text */}
        <div style={{
          position: 'absolute',
          top: 0,
          left: 0,
          width: '100%',
          height: '100%',
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
          justifyContent: 'center'
        }}>
          <span style={{
            fontSize: '32px',
            fontWeight: '800',
            fontFamily: 'var(--font-mono)',
            color: '#fff'
          }}>
            {Math.round(score)}
          </span>
          <span style={{
            fontSize: '11px',
            color: 'var(--text-muted)',
            fontWeight: '600',
            textTransform: 'uppercase',
            letterSpacing: '0.05em'
          }}>
            Score
          </span>
        </div>
      </div>

      <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '2px' }}>
        <span style={{
          fontSize: '14px',
          fontWeight: '700',
          color: color,
        }}>
          {label}
        </span>
        <span style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
          ViGil Threat Matrix Score
        </span>
      </div>
    </div>
  );
}
