import { notFound } from "next/navigation";
import { getArticle, getAllArticleIds } from "@/lib/articles";
import { renderDcaArticle } from "@/lib/server-encryption";
import { EncryptedSection } from "@/components/EncryptedSection";
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

      {/* DCA data script + sealed content template embedded as standard DCA HTML */}
      {dcaResult && (
        <div
          dangerouslySetInnerHTML={{
            __html: dcaResult.result.html.dcaDataScript + dcaResult.result.html.sealedContentTemplate,
          }}
        />
      )}

      <main className="article-page">
        <article>
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

          <section className="premium-section">
            {/* DCA client-side decryption component */}
            <EncryptedSection
              resourceId={article.id}
              contentName={dcaResult?.tier ?? "TierA"}
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
