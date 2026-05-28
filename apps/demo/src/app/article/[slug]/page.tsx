import { notFound } from "next/navigation";
import { getArticle, getAllArticleIds } from "@/lib/articles";
import { renderDcaArticle } from "@/lib/server-encryption";
import { EncryptedSection } from "@/components/EncryptedSection";
import { AdDemoScripts } from "@/components/AdDemoScripts";
import { DemoLayout } from "@/components/DemoLayout";

/** Opt out of static generation — secrets are not available at build time */
export const dynamic = "force-dynamic";

interface ArticlePageProps {
  params: Promise<{ slug: string }>;
}

export default async function ArticlePage({ params }: ArticlePageProps) {
  const { slug } = await params;
  const article = getArticle(slug);

  if (!article) {
    notFound();
  }

  // Render DCA-encrypted content server-side
  const dcaResult = await renderDcaArticle(slug);

  // Build the cleartext ad manifest (entitlement-independent, cache-stable).
  const adManifest = article.ads
    ? {
        version: "1.0",
        page: { contentId: article.id },
        slots: article.ads.slots.map((s) => ({
          id: s.id,
          contentId: article.id,
          sizes: s.sizes,
          minHeight: s.minHeight,
          lazy: s.lazy ?? false,
          adUnitPath: s.adUnitPath,
        })),
      }
    : null;

  return (
    <DemoLayout>
      {/* 
        ============================================================
        DCA ENCRYPTED ARTICLE
        ============================================================
        This page demonstrates the DCA (Delegated Content Access) standard.
        The encrypted content below is embedded at request time.
        Decryption happens client-side using Web Crypto API.
        ============================================================
      */}

      {/* DCA manifest script embedded as standard DCA HTML */}
      {dcaResult && (
        <div
          dangerouslySetInnerHTML={{
            __html: dcaResult.result.html.manifestScript,
          }}
        />
      )}

      {/* Cleartext ad manifest — outside the encrypted payload, cache-stable.
          See the Ads API guide. */}
      {adManifest && (
        <script
          type="application/json"
          className="dca-ad-manifest"
          dangerouslySetInnerHTML={{
            __html: JSON.stringify(adManifest).replace(/</g, "\\u003c"),
          }}
        />
      )}
      {article.ads && <AdDemoScripts />}

      <main className="article-page">
        {/* publisher-content-id is the Capsule contentId; spread to satisfy JSX typing */}
        <article {...({ "publisher-content-id": article.id } as Record<string, string>)}>
          <header className="article-header">
            <h1>{article.title}</h1>
            <div className="article-meta">
              <span>By {article.author}</span>
              <span>•</span>
              <time dateTime={article.publishedAt}>
                {new Date(article.publishedAt).toLocaleDateString("en-US", {
                  year: "numeric",
                  month: "long",
                  day: "numeric",
                })}
              </time>
            </div>
          </header>

          <section className="preview-content">
            {article.previewContent.split("\n\n").map((paragraph, i) => (
              <p key={i}>{paragraph}</p>
            ))}
          </section>

          {/* Page ad OUTSIDE the lock — a normal page ad, filled immediately. */}
          {article.ads?.slots
            .filter((s) => s.placement === "above-lock")
            .map((s) => (
              <div
                key={s.id}
                className="dca-ad-slot"
                data-dca-ad={s.id}
                data-dca-ad-size={s.sizes.map(([w, h]) => `${w}x${h}`).join(",")}
                style={{ minHeight: s.minHeight }}
              />
            ))}

          <section className="premium-section">
            {/* DCA client-side decryption component */}
            <EncryptedSection
              resourceId={article.id}
              contentName="bodytext"
              hasEncryptedContent={!!dcaResult}
            />
          </section>
        </article>
      </main>
    </DemoLayout>
  );
}

// Generate static paths for all articles
export async function generateStaticParams() {
  const ids = getAllArticleIds();
  return ids.map((id) => ({ slug: id }));
}
