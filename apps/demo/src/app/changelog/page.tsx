import { readFileSync } from "fs";
import { join } from "path";
import { MarkdownPage } from "@/components/MarkdownPage";

export default function ChangelogPage() {
  const content = readFileSync(
    join(process.cwd(), "docs/06-changelog.md"),
    "utf-8",
  );
  return <MarkdownPage content={content} />;
}
