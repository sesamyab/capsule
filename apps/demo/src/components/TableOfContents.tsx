"use client";

import { useEffect, useState, useRef } from "react";

interface TocItem {
  id: string;
  text: string;
  level: number;
}

interface TableOfContentsProps {
  /** Selector for the container to scan for headings */
  containerSelector?: string;
  /** Which heading levels to include */
  levels?: number[];
  /** Position: 'left' or 'right' */
  position?: "left" | "right";
}

export function TableOfContents({
  containerSelector = "main",
  levels = [2, 3],
  position = "right",
}: TableOfContentsProps) {
  const [items, setItems] = useState<TocItem[]>([]);
  const [activeId, setActiveId] = useState<string>("");
  const hasProcessed = useRef(false);

  // Scan for headings and build ToC - only once on mount
  useEffect(() => {
    if (hasProcessed.current) return;
    
    const container = document.querySelector(containerSelector);
    if (!container) return;

    const selector = levels.map((l) => `h${l}`).join(", ");
    const headings = container.querySelectorAll(selector);

    const tocItems: TocItem[] = [];
    const idCounts = new Map<string, number>();

    headings.forEach((heading) => {
      const text = heading.textContent || "";
      // Generate base ID from text
      const baseId = text
        .toLowerCase()
        .replace(/[^a-z0-9]+/g, "-")
        .replace(/(^-|-$)/g, "");
      
      // Handle duplicates by appending a counter
      const count = idCounts.get(baseId) || 0;
      idCounts.set(baseId, count + 1);
      
      let id = heading.id;
      if (!id) {
        id = count > 0 ? `${baseId}-${count}` : baseId;
        heading.id = id;
      }

      const level = parseInt(heading.tagName.charAt(1));
      tocItems.push({ id, text, level });
    });

    hasProcessed.current = true;
    setItems(tocItems);
  }, [containerSelector, levels]);

  // Track active section on scroll
  useEffect(() => {
    if (items.length === 0) return;

    const observer = new IntersectionObserver(
      (entries) => {
        entries.forEach((entry) => {
          if (entry.isIntersecting) {
            setActiveId(entry.target.id);
          }
        });
      },
      {
        rootMargin: "-80px 0px -80% 0px",
        threshold: 0,
      }
    );

    items.forEach((item) => {
      const element = document.getElementById(item.id);
      if (element) observer.observe(element);
    });

    return () => observer.disconnect();
  }, [items]);

  if (items.length === 0) return null;

  const minLevel = Math.min(...items.map((i) => i.level));

  return (
    <nav
      className={`toc toc-${position}`}
      aria-label="Table of contents"
    >
      <div className="toc-title">On this page</div>
      <ul className="toc-list">
        {items.map((item) => (
          <li
            key={item.id}
            className={`toc-item toc-level-${item.level - minLevel} ${
              activeId === item.id ? "toc-active" : ""
            }`}
          >
            <a href={`#${item.id}`} onClick={(e) => {
              e.preventDefault();
              const element = document.getElementById(item.id);
              if (element) {
                element.scrollIntoView({ behavior: "smooth" });
                // Update URL without triggering scroll
                history.pushState(null, "", `#${item.id}`);
                setActiveId(item.id);
              }
            }}>
              {item.text}
            </a>
          </li>
        ))}
      </ul>
    </nav>
  );
}
