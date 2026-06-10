'use client';

import React from 'react';
import SettingsPanel from '../../components/SettingsPanel';

export default function SettingsPage() {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '24px', width: '100%' }} className="animate-fade">
      <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
        <h1 style={{ fontSize: '28px', fontWeight: '800', color: '#fff' }}>
          System Settings
        </h1>
        <p style={{ color: 'var(--text-muted)', fontSize: '14px' }}>
          Configure API credentials, choose LLM orchestration models, adjust Monte Carlo BNN samples,
          and verify provider integrations.
        </p>
      </div>

      <SettingsPanel />
    </div>
  );
}
