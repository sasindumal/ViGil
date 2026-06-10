import { useEffect, useState, useRef, useCallback } from 'react';

export function useWebSocket(url, onMessage) {
  const onMessageRef = useRef(onMessage);
  useEffect(() => {
    onMessageRef.current = onMessage;
  }, [onMessage]);
  const [messages, setMessages] = useState([]);
  const [lastMessage, setLastMessage] = useState(null);
  const [isConnected, setIsConnected] = useState(false);
  const [connectionStatus, setConnectionStatus] = useState('connecting');
  
  const ws = useRef(null);
  const reconnectTimeout = useRef(null);
  const reconnectDelay = useRef(1000);
  const maxReconnectDelay = 30000;

  const connect = useCallback(() => {
    if (!url) return;

    logger("Connecting to WebSocket:", url);
    setConnectionStatus('connecting');

    try {
      ws.current = new WebSocket(url);

      ws.current.onopen = () => {
        logger("WebSocket connection opened.");
        setIsConnected(true);
        setConnectionStatus('connected');
        reconnectDelay.current = 1000; // Reset backoff
      };

      ws.current.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data);
          
          // Respond to heartbeats (pong)
          if (data.type === 'pong') return;

          console.log("[useWebSocket] Received:", data);
          logger("WebSocket received message:", data);
          if (onMessageRef.current) {
            onMessageRef.current(data);
          }
          setLastMessage(data);
          setMessages((prev) => [...prev, data]);
        } catch (e) {
          console.error("[useWebSocket] Error parsing message:", e);
          logger("Error parsing WebSocket message:", e);
        }
      };

      ws.current.onclose = (event) => {
        logger("WebSocket connection closed:", event.reason);
        setIsConnected(false);
        setConnectionStatus('disconnected');
        
        // Trigger auto-reconnect with exponential backoff
        reconnectTimeout.current = setTimeout(() => {
          reconnectDelay.current = Math.min(reconnectDelay.current * 2, maxReconnectDelay);
          connect();
        }, reconnectDelay.current);
      };

      ws.current.onerror = (error) => {
        logger("WebSocket encountered error:", error);
      };

    } catch (err) {
      logger("Failed to instantiate WebSocket:", err);
    }
  }, [url]);

  useEffect(() => {
    connect();

    return () => {
      // Cleanup
      if (ws.current) {
        ws.current.onclose = null; // Prevent reconnect cycle on unmount
        ws.current.close();
      }
      if (reconnectTimeout.current) {
        clearTimeout(reconnectTimeout.current);
      }
    };
  }, [connect]);

  const sendMessage = useCallback((msg) => {
    if (ws.current && isConnected) {
      ws.current.send(typeof msg === 'string' ? msg : JSON.stringify(msg));
    }
  }, [isConnected]);

  return {
    messages,
    lastMessage,
    isConnected,
    connectionStatus,
    sendMessage
  };
}

function logger(...args) {
  if (process.env.NODE_ENV !== 'production') {
    console.log("[WS]", ...args);
  }
}
