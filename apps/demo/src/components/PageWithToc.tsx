"use client";

import { ReactNode } from "react";
import { TableOfContents } from "./TableOfContents";

interface PageWithTocProps {
  children: ReactNode;
  position?: "left" | "right";
}

export function PageWithToc({ children, position = "right" }: PageWithTocProps) {
  return (
    <>
      {children}
      <TableOfContents position={position} />
    </>
  );
}
