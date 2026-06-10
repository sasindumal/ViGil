import { useState, useEffect, useCallback, useRef } from 'react';
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
  const [mlPrediction, setMlPrediction] = useState(null);

  const statusRef = useRef(status);
  useEffect(() => {
    statusRef.current = status;
  }, [status]);

  // WS Connection url
  const [wsUrl, setWsUrl] = useState(null);

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

        // Extract ML prediction if present
        const peRes = data.results.pe_results || [];
        if (peRes.length > 0 && peRes[0].ml_prediction) {
          setMlPrediction(peRes[0].ml_prediction);
        }
        
        // Populate completed agents activity
        const combinedOutputs = {};
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
      } else if (data.file_name) {
        console.log("[useAnalysis] fetchResults polling: results are null but file_name is present:", data.file_name);
        setFileInfo(prev => {
          const updated = {
            ...prev,
            file_name: data.file_name,
            file_size: data.file_size
          };
          console.log("[useAnalysis] updated fileInfo from poll:", updated);
          return updated;
        });
      }
      
      const currentStatus = statusRef.current;
      if (data.status === 'completed' || data.status === 'failed' || currentStatus === 'idle' || currentStatus === 'queued') {
        console.log("[useAnalysis] fetchResults updating status to:", data.status, "progress to:", data.progress);
        setStatus(data.status);
        setProgress(data.progress);
      } else {
        console.log("[useAnalysis] fetchResults ignoring status update from poll. Current active status:", currentStatus);
      }
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

  // Polling fallback when not complete/failed
  useEffect(() => {
    if (!analysisId || status === 'completed' || status === 'failed') return;

    const interval = setInterval(() => {
      fetchResults(analysisId);
    }, 2000);

    return () => clearInterval(interval);
  }, [analysisId, status, fetchResults]);

  // Handle incoming WS events using a stable callback
  const handleWsMessage = useCallback((lastMessage) => {
    if (!lastMessage) return;
    
    console.log("[useAnalysis] handleWsMessage event:", lastMessage.event_type, lastMessage);

    const { event_type, step, data, progress: stepProgress, message, agent } = lastMessage;

    if (event_type === 'analysis_started') {
      setStatus('identifying');
      setProgress(0.0);
    } else if (event_type === 'file_identified') {
      setStatus('identifying');
      setProgress(0.1);
      if (data) {
        console.log("[useAnalysis] file_identified data:", data);
        setFileInfo(prev => {
          const updated = { ...prev, ...data };
          console.log("[useAnalysis] updated fileInfo from WS:", updated);
          return updated;
        });
      }
    } else if (event_type === 'step_started') {
      setStatus(step);
      if (stepProgress !== undefined) setProgress(stepProgress);
    } else if (event_type === 'step_progress') {
      if (stepProgress !== undefined) setProgress(stepProgress);
      if (step === 'pe_analysis' && message) {
        logger("PE modules progress:", message);
      }
    } else if (event_type === 'step_completed') {
      if (step === 'pe_analysis') {
        setStatus('ml_prediction');
      } else if (step === 'agents_analysis') {
        setStatus('generating_report');
      } else if (step === 'ml_prediction') {
        if (data) {
          setMlPrediction(data);
        }
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
      fetchResults(analysisId);
    } else if (event_type === 'analysis_failed') {
      setStatus('failed');
      setProgress(1.0);
      setError(message || 'Analysis failed.');
    }
  }, [analysisId, fetchResults]);

  const { isConnected } = useWebSocket(wsUrl, handleWsMessage);

  // Sync wsUrl when analysisId changes
  useEffect(() => {
    if (analysisId) {
      setWsUrl(api.getWsUrl(analysisId));
    } else {
      setWsUrl(null);
    }
  }, [analysisId]);

  const uploadFile = useCallback(async (file) => {
    setStatus('uploading');
    setError(null);
    setResults(null);
    setReport(null);
    setMlPrediction(null);
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
    mlPrediction,
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
