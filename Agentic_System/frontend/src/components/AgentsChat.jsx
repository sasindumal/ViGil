'use client';

import React, { useState, useEffect, useRef } from 'react';
import { 
  User, Shield, FolderArchive, Cpu, Bot, FileText, 
  Paperclip, Send, CheckCircle2, ChevronDown, ChevronUp, Clock 
} from 'lucide-react';
import { AGENT_ROLES } from '../lib/constants';

export default function AgentsChat({ 
  analysisId, 
  status, 
  progress, 
  fileInfo, 
  results, 
  agentActivity, 
  mlPrediction,
  onComplete 
}) {
  const [messages, setMessages] = useState([]);
  const [typingUser, setTypingUser] = useState(null);
  const [expandedMessageId, setExpandedMessageId] = useState(null);
  const [chatStage, setChatStage] = useState(0); // 0: User Msg, 1: Identificator Typing, 2: Identificator Msg, 3: Extractor Typing, 4: Extractor Msg, 5: Model Typing, 6: Model Msg, 7: Agents Live Updates, 8: Final Wrap up
  const chatEndRef = useRef(null);

  console.log("[AgentsChat] Render - chatStage:", chatStage, "status:", status, "fileInfo:", fileInfo);

  // Scroll to bottom on messages or typing change
  useEffect(() => {
    chatEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages, typingUser]);

  // Stage 0: Initial user message
  useEffect(() => {
    console.log("[AgentsChat] Stage 0 Effect - fileInfo?.file_name:", fileInfo?.file_name);
    if (chatStage === 0 && fileInfo?.file_name) {
      console.log("[AgentsChat] Stage 0 match - sending initial user message");
      const now = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
      setMessages([
        {
          id: 'msg-user',
          sender: 'Me',
          text: 'Hey guys, analyze this sample.',
          isUser: true,
          timestamp: now,
          attachment: {
            name: fileInfo.file_name,
            size: fileInfo.file_size ? `${(fileInfo.file_size / 1024).toFixed(1)} KB` : 'Unknown size'
          }
        }
      ]);
      
      // Short delay before transitioning to Identificator typing state
      const timer = setTimeout(() => {
        console.log("[AgentsChat] Stage 0 timeout complete - transitioning to Stage 1");
        setChatStage(1);
      }, 800);
      return () => clearTimeout(timer);
    }
  }, [chatStage, fileInfo]);

  // Stage 1: Identificator typing (Minimum 2 seconds)
  useEffect(() => {
    if (chatStage === 1) {
      console.log("[AgentsChat] Stage 1 match - Identificator is thinking");
      setTypingUser({ name: 'Identificator', avatar: Shield, color: '#00d4ff' });
      
      const timer = setTimeout(() => {
        console.log("[AgentsChat] Stage 1 timeout complete - transitioning to Stage 2");
        setChatStage(2); // Move to message print stage
      }, 2000);
      
      return () => clearTimeout(timer);
    }
  }, [chatStage]);

  // Stage 2: Identificator Message Print (waits for fileInfo.route if it wasn't populated yet)
  useEffect(() => {
    console.log("[AgentsChat] Stage 2 Effect - route:", fileInfo?.route);
    if (chatStage === 2) {
      if (fileInfo?.route) {
        console.log("[AgentsChat] Stage 2 match - route found:", fileInfo.route);
        const now = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
        setTypingUser(null);
        
        const fileTypeLabel = fileInfo.file_type || fileInfo.route;
        const pipelineRoute = fileInfo.route.toUpperCase();

        setMessages(prev => [
          ...prev,
          {
            id: 'msg-identificator',
            sender: 'Identificator',
            text: `Hello team! I have inspected the uploaded sample. \nFile type is identified as **${fileTypeLabel}**. \nRouting this target to the **${pipelineRoute}** analysis workflow.`,
            isUser: false,
            avatar: Shield,
            color: '#00d4ff',
            timestamp: now
          }
        ]);
        
        // Decide next stage based on file route
        if (fileInfo.route === 'container') {
          console.log("[AgentsChat] Stage 2 routing -> container (Stage 3)");
          setTimeout(() => setChatStage(3), 1000); // Extractor typing next
        } else if (fileInfo.route === 'pe') {
          console.log("[AgentsChat] Stage 2 routing -> PE (Stage 5)");
          setTimeout(() => setChatStage(5), 1000); // Model typing next
        } else {
          console.log("[AgentsChat] Stage 2 routing -> other (Stage 7)");
          setTimeout(() => setChatStage(7), 1000); // Agents live updates next
        }
      } else {
        console.log("[AgentsChat] Stage 2 else - route not found yet, showing Identificator typing");
        // Keeps showing typing state while we wait for the backend to identify route
        setTypingUser({ name: 'Identificator', avatar: Shield, color: '#00d4ff' });
      }
    }
  }, [chatStage, fileInfo?.route]);

  // Stage 3: Extractor typing (Minimum 2 seconds)
  useEffect(() => {
    if (chatStage === 3) {
      setTypingUser({ name: 'Extractor', avatar: FolderArchive, color: '#ffb800' });
      
      const timer = setTimeout(() => {
        setChatStage(4);
      }, 2000);
      
      return () => clearTimeout(timer);
    }
  }, [chatStage]);

  // Stage 4: Extractor Message Print (waits for status to progress past extraction)
  useEffect(() => {
    if (chatStage === 4) {
      const isExtractorDone = status !== 'extracting' && status !== 'identifying' && status !== 'queued';
      if (isExtractorDone) {
        const now = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
        setTypingUser(null);
        
        const peCount = results?.pe_results?.length || 0;
        const scriptCount = results?.script_results?.length || 0;

        setMessages(prev => [
          ...prev,
          {
            id: 'msg-extractor',
            sender: 'Extractor',
            text: `Archive unpacked successfully! \nExtracted **${peCount + scriptCount}** total items from container.\n- Found **${peCount}** executable PE binary payloads.\n- Found **${scriptCount}** script source files.\nProceeding with child node analysis...`,
            isUser: false,
            avatar: FolderArchive,
            color: '#ffb800',
            timestamp: now
          }
        ]);

        const hasPE = peCount > 0 || fileInfo?.route === 'pe';
        if (hasPE) {
          setTimeout(() => setChatStage(5), 1000); // Model typing next
        } else {
          setTimeout(() => setChatStage(7), 1000); // Agents live updates next
        }
      } else {
        setTypingUser({ name: 'Extractor', avatar: FolderArchive, color: '#ffb800' });
      }
    }
  }, [chatStage, status, results]);

  // Stage 5: ViGil Model Predictor typing (Minimum 2 seconds)
  useEffect(() => {
    if (chatStage === 5) {
      setTypingUser({ name: 'ViGil Advanced Model', avatar: Cpu, color: '#8b5cf6' });
      
      const timer = setTimeout(() => {
        setChatStage(6);
      }, 2000);
      
      return () => clearTimeout(timer);
    }
  }, [chatStage]);

  // Stage 6: Model Message Print (waits for mlPrediction to be populated)
  useEffect(() => {
    if (chatStage === 6) {
      if (mlPrediction) {
        console.log("[AgentsChat] Stage 6 match - mlPrediction found:", mlPrediction);
        const now = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
        setTypingUser(null);

        const verdict = mlPrediction.label || mlPrediction.verdict || 'SUSPICIOUS';
        const confVal = Math.round((mlPrediction.confidence || 0.8) * 100);

        setMessages(prev => {
          if (prev.some(m => m.id === 'msg-model')) return prev;
          return [
            ...prev,
            {
              id: 'msg-model',
              sender: 'ViGil Advanced Model',
              text: `ML Joint Model inference complete! \nPreliminary classification score is: **${verdict}** (Confidence: **${confVal}%**). \nPlease standby while the multi-agent consensus validation writes the final threat reports.`,
              isUser: false,
              avatar: Cpu,
              color: '#8b5cf6',
              timestamp: now
            }
          ];
        });

        const timer = setTimeout(() => setChatStage(7), 1000); // Agents live updates next
        return () => clearTimeout(timer);
      } else {
        console.log("[AgentsChat] Stage 6 waiting for mlPrediction");
        setTypingUser({ name: 'ViGil Advanced Model', avatar: Cpu, color: '#8b5cf6' });
      }
    }
  }, [chatStage, mlPrediction]);

  const [printedAgents, setPrintedAgents] = useState([]);

  // Stage 7: Live Agent Updates
  useEffect(() => {
    if (chatStage === 7) {
      // Find if any agent is currently thinking
      const thinkingAgent = Object.entries(agentActivity).find(
        ([_, act]) => act.status === 'thinking'
      );

      if (thinkingAgent) {
        const [agentName] = thinkingAgent;
        const roleMeta = AGENT_ROLES[agentName] || { color: '#00ff88' };
        setTypingUser({ name: agentName, avatar: Bot, color: roleMeta.color });
      } else {
        // Fallback typing
        setTypingUser({ name: 'ViGil Agents Group', avatar: Bot, color: '#00ff88' });
      }

      // Check if any agent has completed but hasn't been printed yet
      const completedAgents = Object.entries(agentActivity).filter(
        ([agentName, act]) => act.status === 'completed' && !printedAgents.includes(agentName)
      );

      if (completedAgents.length > 0) {
        completedAgents.sort((a, b) => {
          const orderA = AGENT_ROLES[a[0]]?.number || 99;
          const orderB = AGENT_ROLES[b[0]]?.number || 99;
          return orderA - orderB;
        });

        const now = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
        const newMessages = completedAgents.map(([agentName, act]) => {
          const roleMeta = AGENT_ROLES[agentName] || { color: '#00ff88' };
          const text = act.output || 'Task completed successfully.';
          const lines = text.split('\n').filter(l => l.trim().length > 0);
          const summary = lines.slice(0, 3).join('\n') + (lines.length > 3 ? '\n...' : '');

          return {
            id: `agent-msg-${agentName}`,
            sender: agentName,
            text: summary,
            fullOutput: text,
            isUser: false,
            avatar: Bot,
            color: roleMeta.color,
            timestamp: now
          };
        });

        setMessages(prev => [...prev, ...newMessages]);
        setPrintedAgents(prev => [...prev, ...completedAgents.map(([name]) => name)]);
      }

      // If status becomes completed/failed, transition to Stage 8
      if (status === 'completed') {
        setChatStage(8);
      }
    }
  }, [chatStage, agentActivity, printedAgents, status]);

  // Stage 8: Final Wrap up
  useEffect(() => {
    if (chatStage === 8) {
      setTypingUser({ name: 'ViGil Orchestrator', avatar: FileText, color: '#10b981' });
      
      const timer1 = setTimeout(() => {
        setTypingUser(null);
        const now = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
        
        setMessages(prev => {
          if (prev.some(m => m.id === 'msg-final')) return prev;
          return [
            ...prev,
            {
              id: 'msg-final',
              sender: 'ViGil Orchestrator',
              text: `Consensus compiled successfully! High-threat flags integrated and final HTML/Markdown report formatted. Redirecting to your dashboard views...`,
              isUser: false,
              avatar: FileText,
              color: '#10b981',
              timestamp: now
            }
          ];
        });

        const timer2 = setTimeout(() => {
          onComplete();
        }, 4000);

        return () => clearTimeout(timer2);
      }, 2000);

      return () => clearTimeout(timer1);
    }
  }, [chatStage, onComplete]);

  const toggleExpandMessage = (id) => {
    setExpandedMessageId(prev => prev === id ? null : id);
  };

  return (
    <div style={{
      display: 'flex',
      flexDirection: 'column',
      height: '850px',
      background: 'rgba(8, 12, 26, 0.6)',
      border: '1px solid var(--border-color)',
      borderRadius: '16px',
      overflow: 'hidden',
      backdropFilter: 'var(--glass-blur)',
      boxShadow: '0 20px 40px rgba(0, 0, 0, 0.4)',
    }} className="animate-fade">
      
      {/* Group Chat Header */}
      <div style={{
        display: 'flex',
        alignItems: 'center',
        padding: '16px 24px',
        background: 'rgba(16, 22, 42, 0.8)',
        borderBottom: '1px solid var(--border-color)',
        gap: '14px'
      }}>
        <div style={{
          width: '44px',
          height: '44px',
          borderRadius: '50%',
          background: 'linear-gradient(135deg, var(--color-primary), var(--color-purple))',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          boxShadow: '0 0 10px rgba(0, 212, 255, 0.2)',
        }}>
          <Bot size={22} color="#fff" />
        </div>
        
        <div style={{ display: 'flex', flexDirection: 'column', gap: '2px', flex: 1 }}>
          <span style={{ fontSize: '15px', fontWeight: '700', color: '#fff' }}>
            ViGil Agents Group
          </span>
          <span style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
            Participants: Identificator, Extractor, ViGil Model, Consensus Agents
          </span>
        </div>
        
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <span className="badge badge-info" style={{ gap: '4px' }}>
            <Clock size={11} />
            ANALYSIS IN PROGRESS
          </span>
        </div>
      </div>

      {/* Messages Scroll Area */}
      <div style={{
        flex: 1,
        padding: '24px',
        overflowY: 'auto',
        display: 'flex',
        flexDirection: 'column',
        gap: '16px',
        backgroundImage: 'radial-gradient(circle at 10% 20%, rgba(0, 212, 255, 0.01) 0%, transparent 40%)',
      }}>
        {messages.map((msg) => {
          const AvatarIcon = msg.avatar;
          const isExpanded = expandedMessageId === msg.id;

          if (msg.isUser) {
            return (
              <div 
                key={msg.id} 
                style={{
                  display: 'flex',
                  alignSelf: 'flex-end',
                  flexDirection: 'column',
                  alignItems: 'flex-end',
                  maxWidth: '70%',
                  gap: '4px'
                }}
              >
                <div style={{
                  background: 'linear-gradient(135deg, var(--color-purple), #581c87)',
                  color: '#fff',
                  padding: '12px 16px',
                  borderRadius: '16px 16px 4px 16px',
                  boxShadow: '0 4px 12px rgba(139, 92, 246, 0.15)',
                  fontSize: '13.5px',
                  lineHeight: '1.5',
                  display: 'flex',
                  flexDirection: 'column',
                  gap: '10px'
                }}>
                  {/* File Attachment Card */}
                  {msg.attachment && (
                    <div style={{
                      display: 'flex',
                      alignItems: 'center',
                      gap: '12px',
                      background: 'rgba(0, 0, 0, 0.25)',
                      padding: '10px 14px',
                      borderRadius: '10px',
                      border: '1px solid rgba(255, 255, 255, 0.1)',
                    }}>
                      <Paperclip size={18} color="var(--color-primary)" />
                      <div style={{ display: 'flex', flexDirection: 'column', gap: '2px' }}>
                        <span style={{ fontSize: '12px', fontWeight: '700', color: '#fff', wordBreak: 'break-all' }}>
                          {msg.attachment.name}
                        </span>
                        <span style={{ fontSize: '10px', color: 'rgba(255,255,255,0.6)', fontFamily: 'var(--font-mono)' }}>
                          {msg.attachment.size}
                        </span>
                      </div>
                    </div>
                  )}
                  <div>{msg.text}</div>
                  <span style={{
                    fontSize: '10px',
                    color: 'rgba(255, 255, 255, 0.5)',
                    alignSelf: 'flex-end',
                    display: 'flex',
                    alignItems: 'center',
                    gap: '4px'
                  }}>
                    {msg.timestamp}
                    <CheckCircle2 size={11} color="var(--color-primary)" />
                  </span>
                </div>
              </div>
            );
          }

          // Agent/System message
          return (
            <div 
              key={msg.id} 
              style={{
                display: 'flex',
                alignSelf: 'flex-start',
                gap: '12px',
                maxWidth: '75%'
              }}
            >
              {/* Left Avatar */}
              <div style={{
                width: '32px',
                height: '32px',
                borderRadius: '50%',
                background: msg.color + '20',
                border: `1px solid ${msg.color}`,
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                flexShrink: 0,
                marginTop: '4px'
              }}>
                <AvatarIcon size={16} color={msg.color} />
              </div>

              {/* Message Bubble */}
              <div style={{
                background: 'rgba(16, 22, 42, 0.45)',
                border: '1px solid var(--border-color)',
                padding: '12px 16px',
                borderRadius: '4px 16px 16px 16px',
                fontSize: '13.5px',
                lineHeight: '1.5',
                display: 'flex',
                flexDirection: 'column',
                gap: '6px',
                position: 'relative'
              }}>
                {/* Sender Title */}
                <span style={{ 
                  fontSize: '11px', 
                  fontWeight: '800', 
                  color: msg.color,
                  letterSpacing: '0.03em',
                  textTransform: 'uppercase'
                }}>
                  {msg.sender}
                </span>

                {/* Body Text */}
                <div style={{ 
                  color: 'var(--text-main)', 
                  whiteSpace: 'pre-wrap',
                  fontFamily: msg.fullOutput ? 'var(--font-mono)' : 'inherit',
                  fontSize: msg.fullOutput ? '12px' : '13.5px'
                }}>
                  {isExpanded ? msg.fullOutput : msg.text}
                </div>

                {/* Expand button for agents */}
                {msg.fullOutput && (
                  <button 
                    onClick={() => toggleExpandMessage(msg.id)}
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      gap: '4px',
                      background: 'rgba(255, 255, 255, 0.03)',
                      border: '1px solid rgba(255, 255, 255, 0.05)',
                      padding: '4px 8px',
                      borderRadius: '4px',
                      color: 'var(--color-primary)',
                      fontSize: '11px',
                      fontWeight: '600',
                      cursor: 'pointer',
                      alignSelf: 'flex-start',
                      marginTop: '4px',
                      transition: 'all 0.2s ease',
                    }}
                  >
                    {isExpanded ? (
                      <>Collapse <ChevronUp size={12} /></>
                    ) : (
                      <>Click to expand full output <ChevronDown size={12} /></>
                    )}
                  </button>
                )}

                {/* Timestamp */}
                <span style={{
                  fontSize: '10px',
                  color: 'var(--text-muted)',
                  alignSelf: 'flex-end',
                  marginTop: '2px'
                }}>
                  {msg.timestamp}
                </span>
              </div>
            </div>
          );
        })}

        {/* Typing Indicator */}
        {typingUser && (
          <div style={{
            display: 'flex',
            alignSelf: 'flex-start',
            gap: '12px',
            maxWidth: '70%',
            alignItems: 'center'
          }} className="animate-fade">
            <div style={{
              width: '32px',
              height: '32px',
              borderRadius: '50%',
              background: typingUser.color + '20',
              border: `1px solid ${typingUser.color}`,
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              flexShrink: 0
            }}>
              <typingUser.avatar size={16} color={typingUser.color} />
            </div>

            <div style={{
              background: 'rgba(16, 22, 42, 0.3)',
              border: '1px solid var(--border-color)',
              padding: '10px 16px',
              borderRadius: '18px',
              fontSize: '12px',
              color: 'var(--text-muted)',
              display: 'flex',
              alignItems: 'center',
              gap: '8px'
            }}>
              <span>{typingUser.name} is thinking</span>
              <div style={{ display: 'flex', gap: '3px', alignItems: 'center' }}>
                <span style={{ width: '4px', height: '4px', background: typingUser.color, borderRadius: '50%', animation: 'pulse 1.2s infinite ease-in-out 0s' }}></span>
                <span style={{ width: '4px', height: '4px', background: typingUser.color, borderRadius: '50%', animation: 'pulse 1.2s infinite ease-in-out 0.2s' }}></span>
                <span style={{ width: '4px', height: '4px', background: typingUser.color, borderRadius: '50%', animation: 'pulse 1.2s infinite ease-in-out 0.4s' }}></span>
              </div>
            </div>
          </div>
        )}

        <div ref={chatEndRef} />
      </div>

      {/* Message Input Mock */}
      <div style={{
        padding: '16px 24px',
        background: 'rgba(16, 22, 42, 0.9)',
        borderTop: '1px solid var(--border-color)',
        display: 'flex',
        alignItems: 'center',
        gap: '12px'
      }}>
        <Paperclip size={20} style={{ color: 'var(--text-muted)', cursor: 'not-allowed' }} />
        <div style={{
          flex: 1,
          background: 'rgba(255, 255, 255, 0.03)',
          border: '1px solid var(--border-color)',
          borderRadius: '24px',
          padding: '10px 18px',
          color: 'var(--text-dark)',
          fontSize: '13px',
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center'
        }}>
          <span>Chat locked while running analysis...</span>
          <Send size={16} color="var(--text-dark)" />
        </div>
      </div>
    </div>
  );
}
