import { readFileSync } from "fs";
import { join } from "path";
import { MarkdownPage } from "@/components/MarkdownPage";

export default function ClientPage() {
  const content = readFileSync(
    join(process.cwd(), "docs/02-client.md"),
    "utf-8",
  );
  return <MarkdownPage content={content} />;
}
