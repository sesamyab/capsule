import { readFileSync } from "fs";
import { join } from "path";
import { MarkdownPage } from "@/components/MarkdownPage";

export default function RoadmapPage() {
  const content = readFileSync(
    join(process.cwd(), "docs/05-roadmap.md"),
    "utf-8",
  );
  return <MarkdownPage content={content} />;
}
