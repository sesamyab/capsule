"use client";

import { ReactNode, useEffect } from "react";
import { ConsoleProvider } from "./ConsoleContext";
import { DevConsole } from "./DevConsole";

export function DemoLayout({ children }: { children: ReactNode }) {
  useEffect(() => {
    document.body.classList.add("with-console");
    return () => {
      document.body.classList.remove("with-console");
    };
  }, []);

  return (
    <ConsoleProvider>
      {children}
      <DevConsole />
    </ConsoleProvider>
  );
}
