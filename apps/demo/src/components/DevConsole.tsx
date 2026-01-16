"use client";

import { useEffect, useRef } from "react";
import { useConsole, LogEntry } from "./ConsoleContext";

const typeColors: Record<LogEntry["type"], string> = {
  info: "#888",
  success: "#10b981",
  error: "#ef4444",
  key: "#f59e0b",
  network: "#3b82f6",
  crypto: "#8b5cf6",
};

const typeIcons: Record<LogEntry["type"], string> = {
  info: "→",
  success: "✓",
  error: "✗",
  key: "🔑",
  network: "⬆",
  crypto: "🔐",
};

export function DevConsole() {
  const { logs, clear } = useConsole();
  const scrollRef = useRef<HTMLDivElement>(null);

  // Auto-scroll to bottom when new logs arrive
  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [logs]);

  const formatTime = (date: Date) => {
    return date.toLocaleTimeString("en-US", {
      hour12: false,
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
    });
  };

  return (
    <div className="dev-console">
      <div className="console-header">
        <div className="console-title">
          <span className="console-dot red" />
          <span className="console-dot yellow" />
          <span className="console-dot green" />
          <span className="console-label">Capsule Console</span>
        </div>
        <button onClick={clear} className="console-clear">
          Clear
        </button>
      </div>
      <div className="console-body" ref={scrollRef}>
        {logs.map((entry) => (
          <div key={entry.id} className="console-line">
            <span className="console-time">{formatTime(entry.timestamp)}</span>
            <span
              className="console-icon"
              style={{ color: typeColors[entry.type] }}
            >
              {typeIcons[entry.type]}
            </span>
            <span
              className="console-message"
              style={{ color: typeColors[entry.type] }}
            >
              {entry.message}
            </span>
          </div>
        ))}
        <div className="console-cursor">
          <span className="cursor-prompt">$</span>
          <span className="cursor-blink" />
        </div>
      </div>
    </div>
  );
}
