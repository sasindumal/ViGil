'use client';

import React from 'react';
import AgentCard from './AgentCard';
import { AGENT_ROLES } from '../lib/constants';

export default function AgentActivity({ route = 'pe', agentActivity = {} }) {
  // Filter agent roles based on route
  const relevantRoles = Object.keys(AGENT_ROLES).filter((roleName) => {
    const roleMeta = AGENT_ROLES[roleName];
    if (route === 'pe') {
      return roleMeta.type === 'pe' || roleMeta.type === 'shared';
    } else {
      return roleMeta.type === 'script' || roleMeta.type === 'shared';
    }
  });

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '20px', width: '100%' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <span style={{ fontSize: '15px', fontWeight: '700', letterSpacing: '0.05em' }}>
          MULTI-AGENT ACTIVITY CONSENSUS ({route.toUpperCase()})
        </span>
        <span style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
          {Object.values(agentActivity).filter(a => a.status === 'completed').length} / {relevantRoles.length} completed
        </span>
      </div>

      <div style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(auto-fill, minmax(320px, 1fr))',
        gap: '16px'
      }}>
        {relevantRoles.map((roleName) => (
          <AgentCard
            key={roleName}
            roleName={roleName}
            activity={agentActivity[roleName]}
          />
        ))}
      </div>
    </div>
  );
}
