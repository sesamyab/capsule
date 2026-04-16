import { readFileSync } from "fs";
import { join } from "path";
import { MarkdownPage } from "@/components/MarkdownPage";

export default function SpecPage() {
  const content = readFileSync(join(process.cwd(), "docs/01-spec.md"), "utf-8");
  return <MarkdownPage content={content} />;
}
