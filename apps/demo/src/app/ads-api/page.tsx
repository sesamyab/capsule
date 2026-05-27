import { readFileSync } from "fs";
import { join } from "path";
import type { Metadata } from "next";
import { MarkdownPage } from "@/components/MarkdownPage";

export const metadata: Metadata = {
  title: "Ads API — Capsule",
  description:
    "How to run dynamic ads inside Capsule-locked content: markers, the ad manifest, and the window.dcaAds lifecycle.",
};

export default function AdsApiPage() {
  const content = readFileSync(
    join(process.cwd(), "docs/07-ads-api.md"),
    "utf-8",
  );
  return <MarkdownPage content={content} />;
}
