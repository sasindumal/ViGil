'use client';

import React, { useState, useEffect } from 'react';
import { Settings, Save, Check, RefreshCw, Key } from 'lucide-react';
import { api } from '../lib/api';

export default function SettingsPanel() {
  const [providers, setProviders] = useState([]);
  const [activeProvider, setActiveProvider] = useState('openai');
  const [settings, setSettings] = useState(null);
  
  const [key, setKey] = useState('');
  const [model, setModel] = useState('');
  const [url, setUrl] = useState('');
  
  const [testing, setTesting] = useState(false);
  const [testResult, setTestResult] = useState(null);
  const [saving, setSaving] = useState(false);
  const [saveSuccess, setSaveSuccess] = useState(false);

  useEffect(() => {
    async function loadData() {
      try {
        const provData = await api.getProviders();
        setProviders(provData.providers || []);
        
        const currentSettings = await api.getSettings();
        setSettings(currentSettings);
        
        const active = currentSettings.llm.active_provider;
        setActiveProvider(active);
        
        // Populate inputs
        if (currentSettings.llm[active]) {
          setKey(currentSettings.llm[active].api_key || '');
          setModel(currentSettings.llm[active].model || '');
          setUrl(currentSettings.llm[active].base_url || '');
        }
      } catch (e) {
        console.error("Failed to load settings:", e);
      }
    }
    loadData();
  }, []);

  const handleProviderChange = (provId) => {
    setActiveProvider(provId);
    setTestResult(null);
    if (settings && settings.llm[provId]) {
      setKey(settings.llm[provId].api_key || '');
      setModel(settings.llm[provId].model || '');
      setUrl(settings.llm[provId].base_url || '');
    } else {
      setKey('');
      setModel('');
      setUrl('');
    }
  };

  const handleSave = async (e) => {
    e.preventDefault();
    setSaving(true);
    setSaveSuccess(false);

    try {
      const payload = {
        llm: {
          active_provider: activeProvider,
          [activeProvider]: {
            api_key: key,
            model: model,
            base_url: url || undefined
          }
        }
      };

      const res = await api.updateSettings(payload);
      setSettings(res);
      setSaveSuccess(true);
      setTimeout(() => setSaveSuccess(false), 3000);
    } catch (err) {
      alert(`Save failed: ${err.message}`);
    } finally {
      setSaving(false);
    }
  };

  const handleTest = async () => {
    setTesting(true);
    setTestResult(null);

    try {
      const credentials = {
        [activeProvider]: {
          api_key: key,
          model: model,
          base_url: url || undefined
        }
      };

      const res = await api.testConnection(activeProvider, credentials);
      setTestResult(res);
    } catch (err) {
      setTestResult({ success: false, message: err.message });
    } finally {
      setTesting(false);
    }
  };

  if (!settings) {
    return <div style={{ color: 'var(--text-muted)' }}>Loading configurations...</div>;
  }

  const selectedProvider = providers.find(p => p.id === activeProvider);
  const showKey = selectedProvider?.fields.includes('api_key');
  const showUrl = selectedProvider?.fields.includes('base_url');
  const showModel = selectedProvider?.fields.includes('model');

  return (
    <div className="glass-panel" style={{
      padding: '24px',
      background: 'rgba(16, 22, 42, 0.4)',
      width: '100%',
      display: 'flex',
      flexDirection: 'column',
      gap: '24px'
    }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: '10px', borderBottom: '1px solid var(--border-color)', paddingBottom: '16px' }}>
        <Settings size={20} color="var(--color-primary)" />
        <span style={{ fontSize: '15px', fontWeight: '700', letterSpacing: '0.05em' }}>
          LLM CONFIGURATION & CREDENTIALS
        </span>
      </div>

      {/* Tabs */}
      <div style={{
        display: 'flex',
        gap: '6px',
        overflowX: 'auto',
        borderBottom: '1px solid var(--border-color)',
        paddingBottom: '8px'
      }}>
        {providers.map((p) => {
          const isActive = p.id === activeProvider;
          return (
            <button
              key={p.id}
              onClick={() => handleProviderChange(p.id)}
              style={{
                background: isActive ? 'rgba(0, 212, 255, 0.08)' : 'transparent',
                border: '1px solid ' + (isActive ? 'var(--color-primary)' : 'transparent'),
                color: isActive ? 'var(--color-primary)' : 'var(--text-muted)',
                padding: '8px 16px',
                borderRadius: '6px',
                cursor: 'pointer',
                fontSize: '13px',
                fontWeight: '600',
                transition: 'all 0.2s ease',
              }}
            >
              {p.name}
            </button>
          );
        })}
      </div>

      <form onSubmit={handleSave} style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
        <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
          {showUrl && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
              <label style={{ fontSize: '12px', fontWeight: '600', color: 'var(--text-muted)' }}>
                Endpoint URL
              </label>
              <input
                type="text"
                placeholder={activeProvider === 'ollama' ? 'http://localhost:11434' : 'http://localhost:1234/v1'}
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                required
              />
            </div>
          )}

          {showKey && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
              <label style={{ fontSize: '12px', fontWeight: '600', color: 'var(--text-muted)' }}>
                API Key
              </label>
              <div style={{ position: 'relative' }}>
                <input
                  type="password"
                  placeholder="Input API Token"
                  value={key}
                  onChange={(e) => setKey(e.target.value)}
                  style={{ paddingLeft: '38px' }}
                  required
                />
                <Key size={16} style={{ position: 'absolute', left: '12px', top: '12px', color: 'var(--text-dark)' }} />
              </div>
            </div>
          )}

          {showModel && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
              <label style={{ fontSize: '12px', fontWeight: '600', color: 'var(--text-muted)' }}>
                Model Name
              </label>
              <input
                type="text"
                placeholder={selectedProvider?.default_model}
                value={model}
                onChange={(e) => setModel(e.target.value)}
                required
              />
            </div>
          )}
        </div>

        <div style={{ display: 'flex', justifyContent: 'space-between', gap: '12px', borderTop: '1px solid var(--border-color)', paddingTop: '20px' }}>
          <button
            type="button"
            onClick={handleTest}
            disabled={testing}
            className="btn-secondary"
            style={{ width: '160px', justifyContent: 'center' }}
          >
            <RefreshCw size={14} className={testing ? 'animate-pulse-glow' : ''} />
            {testing ? 'Testing...' : 'Test Connection'}
          </button>

          <button
            type="submit"
            disabled={saving}
            className="btn-primary"
            style={{ width: '160px', justifyContent: 'center' }}
          >
            {saveSuccess ? <Check size={14} /> : <Save size={14} />}
            {saving ? 'Saving...' : saveSuccess ? 'Saved' : 'Save Config'}
          </button>
        </div>
      </form>

      {testResult && (
        <div style={{
          display: 'flex',
          flexDirection: 'column',
          gap: '6px',
          padding: '12px 16px',
          borderRadius: '8px',
          background: testResult.success ? 'var(--color-success-glow)' : 'var(--color-danger-glow)',
          border: '1px solid ' + (testResult.success ? 'rgba(0, 255, 136, 0.2)' : 'rgba(255, 51, 102, 0.2)'),
          color: testResult.success ? 'var(--color-success)' : 'var(--color-danger)',
          fontSize: '13px'
        }}>
          <span style={{ fontWeight: '700' }}>{testResult.success ? 'SUCCESS' : 'FAILURE'}</span>
          <span>{testResult.message}</span>
          {testResult.response_time_ms && (
            <span style={{ fontSize: '11px', color: 'var(--text-muted)' }}>Response time: {testResult.response_time_ms}ms</span>
          )}
        </div>
      )}
    </div>
  );
}
