import { readFileSync } from "fs";
import { join } from "path";
import { MarkdownPage } from "@/components/MarkdownPage";

export default function ServerPage() {
  const content = readFileSync(
    join(process.cwd(), "docs/03-server.md"),
    "utf-8",
  );
  return <MarkdownPage content={content} />;
}
