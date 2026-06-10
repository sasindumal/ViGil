import { useState, useEffect, useCallback } from 'react';
import { api } from '../lib/api';
import { useWebSocket } from './useWebSocket';

export function useAnalysis(initialAnalysisId = null) {
  const [analysisId, setAnalysisId] = useState(initialAnalysisId);
  const [status, setStatus] = useState('idle'); // idle, queued, identifying, extracting, analyzing_pe, running_ml, running_agents, generating_report, completed, failed
  const [progress, setProgress] = useState(0.0);
  const [uploadProgress, setUploadProgress] = useState(0);
  const [fileInfo, setFileInfo] = useState(null);
  const [results, setResults] = useState(null);
  const [report, setReport] = useState(null);
  const [error, setError] = useState(null);
  const [agentActivity, setAgentActivity] = useState({});

  // WS Connection url
  const [wsUrl, setWsUrl] = useState(null);
  const { lastMessage, isConnected } = useWebSocket(wsUrl);

  // Sync wsUrl when analysisId changes
  useEffect(() => {
    if (analysisId) {
      setWsUrl(api.getWsUrl(analysisId));
    } else {
      setWsUrl(null);
    }
  }, [analysisId]);

  // Handle incoming WS events
  useEffect(() => {
    if (!lastMessage) return;

    const { event_type, step, data, progress: stepProgress, message, agent } = lastMessage;

    if (event_type === 'analysis_started') {
      setStatus('identifying');
      setProgress(0.0);
    } else if (event_type === 'file_identified') {
      setStatus('identifying');
      setProgress(0.1);
      if (data) setFileInfo(data);
    } else if (event_type === 'step_started') {
      setStatus(step);
      if (stepProgress !== undefined) setProgress(stepProgress);
    } else if (event_type === 'step_progress') {
      if (stepProgress !== undefined) setProgress(stepProgress);
      if (step === 'pe_analysis' && message) {
        // Log deep analyzer modules progress
        logger("PE modules progress:", message);
      }
    } else if (event_type === 'step_completed') {
      if (step === 'pe_analysis') {
        setStatus('ml_prediction');
      } else if (step === 'agents_analysis') {
        setStatus('generating_report');
      }
    } else if (event_type === 'agent_started' || event_type === 'agent_thinking') {
      if (agent) {
        setAgentActivity((prev) => ({
          ...prev,
          [agent]: { status: 'thinking', message: message || 'Thinking...' }
        }));
      }
    } else if (event_type === 'agent_completed') {
      if (agent) {
        setAgentActivity((prev) => ({
          ...prev,
          [agent]: { status: 'completed', output: data?.output, message: 'Done' }
        }));
      }
    } else if (event_type === 'agent_failed') {
      if (agent) {
        setAgentActivity((prev) => ({
          ...prev,
          [agent]: { status: 'failed', error: message || 'Failed' }
        }));
      }
    } else if (event_type === 'analysis_completed') {
      setStatus('completed');
      setProgress(1.0);
      // Re-trigger fetch to pull full completed results
      fetchResults(analysisId);
    } else if (event_type === 'analysis_failed') {
      setStatus('failed');
      setProgress(1.0);
      setError(message || 'Analysis failed.');
    }
  }, [lastMessage, analysisId]);

  const fetchResults = useCallback(async (id) => {
    try {
      const data = await api.getAnalysis(id);
      if (data.results) {
        setResults(data.results);
        setReport(data.report);
        setFileInfo({
          file_name: data.file_name,
          file_size: data.file_size,
          route: data.results.route,
          verdict: data.results.verdict,
          risk_score: data.results.risk_score,
          confidence: data.results.confidence,
        });
        
        // Populate completed agents activity
        const combinedOutputs = {};
        const peRes = data.results.pe_results || [];
        const scRes = data.results.script_results || [];
        
        const processOutputs = (agentOutputs) => {
          if (agentOutputs) {
            Object.entries(agentOutputs).forEach(([role, text]) => {
              combinedOutputs[role] = { status: 'completed', output: text, message: 'Done' };
            });
          }
        };

        peRes.forEach(r => processOutputs(r.agent_analysis?.agent_outputs));
        scRes.forEach(r => processOutputs(r.agent_analysis?.agent_outputs));
        
        setAgentActivity(combinedOutputs);
      }
      setStatus(data.status);
      setProgress(data.progress);
    } catch (err) {
      logger("Error fetching results:", err);
      setError(err.message);
    }
  }, []);

  // Fetch initial results if initialAnalysisId is provided
  useEffect(() => {
    if (initialAnalysisId) {
      fetchResults(initialAnalysisId);
    }
  }, [initialAnalysisId, fetchResults]);

  const uploadFile = useCallback(async (file) => {
    setStatus('uploading');
    setError(null);
    setResults(null);
    setReport(null);
    setAgentActivity({});
    setProgress(0);

    try {
      const res = await api.uploadFile(file, (p) => {
        setUploadProgress(p);
      });
      setAnalysisId(res.analysis_id);
      setStatus('queued');
      logger("File uploaded successfully. Session ID:", res.analysis_id);
      return res.analysis_id;
    } catch (err) {
      setStatus('failed');
      setError(err.message || 'File upload failed');
      logger("Upload error:", err);
      throw err;
    }
  }, []);

  return {
    analysisId,
    status,
    progress,
    uploadProgress,
    fileInfo,
    results,
    report,
    error,
    agentActivity,
    uploadFile,
    refresh: () => fetchResults(analysisId),
    isConnected,
  };
}

function logger(...args) {
  if (process.env.NODE_ENV !== 'production') {
    console.log("[AnalysisHook]", ...args);
  }
}
