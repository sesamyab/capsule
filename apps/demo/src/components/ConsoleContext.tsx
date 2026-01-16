"use client";

import { createContext, useContext, useState, useCallback, ReactNode } from "react";

export interface LogEntry {
  id: number;
  timestamp: Date;
  message: string;
  type: "info" | "success" | "error" | "key" | "network" | "crypto";
}

interface ConsoleContextType {
  logs: LogEntry[];
  log: (message: string, type?: LogEntry["type"]) => void;
  clear: () => void;
}

const ConsoleContext = createContext<ConsoleContextType | null>(null);

let logId = 0;

export function ConsoleProvider({ children }: { children: ReactNode }) {
  const [logs, setLogs] = useState<LogEntry[]>([
    {
      id: logId++,
      timestamp: new Date(),
      message: "Capsule Console initialized",
      type: "info",
    },
  ]);

  const log = useCallback((message: string, type: LogEntry["type"] = "info") => {
    setLogs((prev) => [
      ...prev,
      {
        id: logId++,
        timestamp: new Date(),
        message,
        type,
      },
    ]);
  }, []);

  const clear = useCallback(() => {
    setLogs([
      {
        id: logId++,
        timestamp: new Date(),
        message: "Console cleared",
        type: "info",
      },
    ]);
  }, []);

  return (
    <ConsoleContext.Provider value={{ logs, log, clear }}>
      {children}
    </ConsoleContext.Provider>
  );
}

export function useConsole() {
  const context = useContext(ConsoleContext);
  if (!context) {
    // Return a no-op version if not wrapped in provider
    return {
      logs: [],
      log: () => {},
      clear: () => {},
    };
  }
  return context;
}
