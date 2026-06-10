'use client';

import React from 'react';
import { Download, Copy, Check, Printer } from 'lucide-react';
import { api } from '../lib/api';

export default function ReportViewer({ analysisId = '', markdown = '' }) {
  const [copied, setCopied] = React.useState(false);

  const handleCopy = () => {
    navigator.clipboard.writeText(markdown);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handlePrint = () => {
    window.print();
  };

  const parseMarkdown = (md) => {
    if (!md) return <p style={{ color: 'var(--text-muted)' }}>No report generated yet.</p>;

    const lines = md.split('\n');
    let inTable = false;
    let tableHeaders = [];
    let tableRows = [];
    const htmlElements = [];

    const flushTable = (key) => {
      if (tableHeaders.length > 0 || tableRows.length > 0) {
        htmlElements.push(
          <div key={`table-${key}`} style={{ overflowX: 'auto', margin: '16px 0' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse' }}>
              <thead>
                <tr>
                  {tableHeaders.map((h, idx) => (
                    <th key={`th-${idx}`} style={{ borderBottom: '2px solid var(--border-color)', padding: '10px', textAlign: 'left', fontSize: '12px', color: 'var(--text-muted)' }}>{h.trim()}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {tableRows.map((row, rowIdx) => (
                  <tr key={`tr-${rowIdx}`} style={{ borderBottom: '1px solid var(--border-color)' }}>
                    {row.map((cell, cellIdx) => (
                      <td key={`td-${cellIdx}`} style={{ padding: '10px', fontSize: '13px', fontFamily: cell.includes('.') && !cell.includes(' ') ? 'var(--font-mono)' : 'inherit' }}>{cell.trim()}</td>
                    ))}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        );
        tableHeaders = [];
        tableRows = [];
        inTable = false;
      }
    };

    let listItems = [];
    const flushList = (key) => {
      if (listItems.length > 0) {
        htmlElements.push(
          <ul key={`list-${key}`} style={{ marginLeft: '24px', marginBottom: '16px', display: 'flex', flexDirection: 'column', gap: '6px' }}>
            {listItems}
          </ul>
        );
        listItems = [];
      }
    };

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];

      // Handle Tables
      if (line.trim().startsWith('|')) {
        flushList(i);
        const parts = line.split('|').filter((_, idx, arr) => idx > 0 && idx < arr.length - 1);
        if (line.includes('---')) {
          // Divider row, skip
          inTable = true;
          continue;
        }
        if (!inTable) {
          tableHeaders = parts;
          inTable = true;
        } else {
          tableRows.push(parts);
        }
        continue;
      } else if (inTable) {
        flushTable(i);
      }

      // Handle Bullet points
      if (line.trim().startsWith('- ') || line.trim().startsWith('* ')) {
        const txt = line.replace(/^[-*]\s+/, '');
        listItems.push(
          <li key={`li-${i}`} style={{ fontSize: '14px', color: 'var(--text-main)' }}>
            {renderInlineMarkdown(txt)}
          </li>
        );
        continue;
      } else {
        flushList(i);
      }

      // Headers
      if (line.startsWith('# ')) {
        htmlElements.push(
          <h1 key={i} style={{ fontSize: '24px', fontWeight: '800', margin: '24px 0 12px 0', borderBottom: '1px solid var(--border-color)', paddingBottom: '8px', background: 'linear-gradient(90deg, #fff, var(--text-muted))', WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent' }}>
            {line.substring(2)}
          </h1>
        );
      } else if (line.startsWith('## ')) {
        htmlElements.push(
          <h2 key={i} style={{ fontSize: '18px', fontWeight: '700', margin: '20px 0 10px 0', color: 'var(--color-primary)' }}>
            {line.substring(3)}
          </h2>
        );
      } else if (line.startsWith('### ')) {
        htmlElements.push(
          <h3 key={i} style={{ fontSize: '15px', fontWeight: '600', margin: '16px 0 8px 0', color: '#fff' }}>
            {line.substring(4)}
          </h3>
        );
      }
      // Blockquotes / Alerts
      else if (line.startsWith('> ')) {
        let alertType = 'info'; // info, warning, danger, success
        let alertText = line.substring(2);
        
        // Scan next lines for alert tags
        if (alertText.includes('[!IMPORTANT]') || alertText.includes('[!NOTE]')) {
          alertType = 'info';
          alertText = alertText.replace(/\[!(IMPORTANT|NOTE)\]/, '');
        } else if (alertText.includes('[!WARNING]')) {
          alertType = 'warning';
          alertText = alertText.replace(/\[!WARNING\]/, '');
        } else if (alertText.includes('[!CAUTION]')) {
          alertType = 'danger';
          alertText = alertText.replace(/\[!CAUTION\]/, '');
        }

        let alertColor = 'var(--color-primary)';
        let alertBg = 'var(--color-primary-glow)';
        if (alertType === 'warning') {
          alertColor = 'var(--color-warning)';
          alertBg = 'var(--color-warning-glow)';
        } else if (alertType === 'danger') {
          alertColor = 'var(--color-danger)';
          alertBg = 'var(--color-danger-glow)';
        }

        htmlElements.push(
          <div key={i} style={{
            borderLeft: `4px solid ${alertColor}`,
            background: alertBg,
            padding: '12px 16px',
            borderRadius: '0 8px 8px 0',
            margin: '16px 0',
            fontSize: '13px',
            color: 'var(--text-main)'
          }}>
            {renderInlineMarkdown(alertText)}
          </div>
        );
      } else if (line.trim() === '') {
        // empty line, skip
      } else {
        htmlElements.push(
          <p key={i} style={{ fontSize: '14px', lineHeight: '1.6', color: 'var(--text-main)', marginBottom: '12px' }}>
            {renderInlineMarkdown(line)}
          </p>
        );
      }
    }

    // Final flushes
    flushTable('end');
    flushList('end');

    return htmlElements;
  };

  const renderInlineMarkdown = (text) => {
    // Regex for bold **text**
    const parts = text.split(/(\*\*.*?\*\*|`.*?`)/);
    return parts.map((part, idx) => {
      if (part.startsWith('**') && part.endsWith('**')) {
        return <strong key={idx} style={{ color: '#fff', fontWeight: '700' }}>{part.slice(2, -2)}</strong>;
      }
      if (part.startsWith('`') && part.endsWith('`')) {
        return <code key={idx} style={{ background: 'rgba(0,0,0,0.3)', padding: '2px 6px', borderRadius: '4px', border: '1px solid var(--border-color)', color: 'var(--color-success)', fontSize: '12px' }}>{part.slice(1, -1)}</code>;
      }
      return part;
    });
  };

  return (
    <div className="glass-panel" style={{
      padding: '24px',
      background: 'rgba(12, 17, 34, 0.4)',
      width: '100%',
      display: 'flex',
      flexDirection: 'column',
      gap: '20px'
    }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: '1px solid var(--border-color)', paddingBottom: '16px' }}>
        <span style={{ fontSize: '15px', fontWeight: '700', letterSpacing: '0.05em' }}>
          THREAT FORENSICS REPORT
        </span>

        <div style={{ display: 'flex', gap: '8px' }}>
          <button onClick={handleCopy} className="btn-secondary" style={{ padding: '8px 12px', fontSize: '12px' }}>
            {copied ? <Check size={14} color="var(--color-success)" /> : <Copy size={14} />}
            {copied ? 'Copied' : 'Copy'}
          </button>
          <button onClick={handlePrint} className="btn-secondary" style={{ padding: '8px 12px', fontSize: '12px' }}>
            <Printer size={14} />
            Print
          </button>
          {analysisId && (
            <a href={api.getReportDownloadUrl(analysisId)} download className="btn-primary" style={{ padding: '8px 12px', fontSize: '12px' }}>
              <Download size={14} />
              Download .md
            </a>
          )}
        </div>
      </div>

      <div style={{ overflowY: 'auto', maxHeight: '70vh', paddingRight: '8px' }}>
        {parseMarkdown(markdown)}
      </div>
    </div>
  );
}
