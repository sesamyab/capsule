import { readFileSync } from "fs";
import { join } from "path";
import { MarkdownPage } from "@/components/MarkdownPage";
import { Metadata } from "next";

export const metadata: Metadata = {
  title: "Cryptography Glossary - Capsule",
  description:
    "Understanding the cryptographic concepts and key hierarchy used in Capsule.",
};

export default function GlossaryPage() {
  const content = readFileSync(
    join(process.cwd(), "docs/04-glossary.md"),
    "utf-8",
  );
  return <MarkdownPage content={content} />;
}
