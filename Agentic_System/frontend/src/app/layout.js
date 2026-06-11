'use client';

import React, { useEffect, useState } from 'react';
import './globals.css';
import Header from '../components/Header';
import Sidebar from '../components/Sidebar';
import { api } from '../lib/api';
import { usePathname } from 'next/navigation';

export default function RootLayout({ children }) {
  const [history, setHistory] = useState([]);
  const [wsConnected, setWsConnected] = useState(false);
  const pathname = usePathname();

  useEffect(() => {
    async function loadHistory() {
      try {
        const data = await api.getAnalysisHistory();
        setHistory(data || []);
      } catch (e) {
        console.error("Failed to load history:", e);
      }
    }
    loadHistory();

    // Establish global WS connection to listen for finished analyses
    let globalWs;
    try {
      globalWs = new WebSocket(api.getGlobalWsUrl());
      globalWs.onopen = () => setWsConnected(true);
      
      globalWs.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data);
          if (data.event_type === 'analysis_completed') {
            loadHistory(); // reload history
          }
        } catch (_) {}
      };

      globalWs.onclose = () => setWsConnected(false);
      globalWs.onerror = () => setWsConnected(false);
    } catch (_) {}

    return () => {
      if (globalWs) globalWs.close();
    };
  }, [pathname]);

  return (
    <html lang="en" data-theme="dark">
      <head>
        <title>ViGil — Agentic Malware Vulnerability Analysis</title>
        <meta name="description" content="AI-powered malware threat forensics, neural network predictions, and multi-agent consensus reporting." />
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        <link rel="icon" href="/vigil-icon.svg" type="image/svg+xml" />
      </head>
      <body>
        <Header isWsConnected={wsConnected} />
        <Sidebar history={history} />
        
        {/* Main Content Area */}
        <main style={{
          marginLeft: '308px',
          marginTop: '88px',
          padding: '24px 24px 48px 0',
          minHeight: 'calc(100vh - 88px)',
          maxWidth: '1200px',
        }}>
          {children}
        </main>
      </body>
    </html>
  );
}
