"use client";

import Markdown from "react-markdown";
import remarkGfm from "remark-gfm";
import { CodeBlock } from "./CodeBlock";
import { PageWithToc } from "./PageWithToc";
import type { Components } from "react-markdown";

const components: Components = {
  pre(props) {
    // Extract language and content from the nested <code> child
    const codeChild = props.children as React.ReactElement<{
      className?: string;
      children?: React.ReactNode;
    }>;
    if (codeChild?.props) {
      const match = /language-(\w+)/.exec(codeChild.props.className || "");
      const lang = match?.[1] || "typescript";
      const content = String(codeChild.props.children || "").replace(/\n$/, "");
      return (
        <CodeBlock language={lang as React.ComponentProps<typeof CodeBlock>["language"]}>
          {content}
        </CodeBlock>
      );
    }
    return <pre>{props.children}</pre>;
  },
};

export function MarkdownPage({ content }: { content: string }) {
  return (
    <PageWithToc>
      <main className="content-page">
        <Markdown remarkPlugins={[remarkGfm]} components={components}>
          {content}
        </Markdown>
      </main>
    </PageWithToc>
  );
}
