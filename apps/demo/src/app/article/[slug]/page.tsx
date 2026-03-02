import { notFound } from "next/navigation";
import { getArticle, getAllArticleIds } from "@/lib/articles";
import { getEncryptedArticle } from "@/lib/server-encryption";
import { EncryptedSection } from "@/components/EncryptedSection";
import { DemoLayout } from "@/components/DemoLayout";
import { KeyManager } from "@/components/KeyManager";
import { ShareButton } from "@/components/ShareButton";

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

  // Get the pre-encrypted content for SSR embedding (now async)
  const encryptedData = await getEncryptedArticle(slug);

  // Format encrypted data as readable JSON for view-source
  const formattedEncryptedData = encryptedData
    ? JSON.stringify(encryptedData, null, 2)
    : null;

  return (
    <DemoLayout>
      {/* 
        ============================================================
        CAPSULE ENCRYPTED ARTICLE
        ============================================================
        This page demonstrates the Capsule encryption standard.
        The encrypted content below is embedded at build/request time.
        Decryption happens client-side using Web Crypto API.
        ============================================================
      */}

      {/* Encrypted data embedded as readable JSON for demonstration */}
      {formattedEncryptedData && (
        <script
          id="capsule-encrypted-data"
          type="application/json"
          data-article-id={article.id}
          dangerouslySetInnerHTML={{
            __html: `\n${formattedEncryptedData}\n`,
          }}
        />
      )}

      <main className="article-page">
        <div className="key-manager-container">
          <KeyManager />
        </div>

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
            {/* Encrypted content embedded in the page for offline/cached decryption */}
            <EncryptedSection
              resourceId={article.id}
              encryptedData={encryptedData}
            />
          </section>

          <section
            className="share-section"
            style={{
              marginTop: "2rem",
              padding: "1rem",
              background: "var(--border)",
              borderRadius: "8px",
            }}
          >
            <h3 style={{ marginTop: 0, marginBottom: "0.5rem" }}>
              🔗 Share This Article
            </h3>
            <p
              style={{
                fontSize: "0.9rem",
                color: "var(--muted)",
                marginBottom: "1rem",
              }}
            >
              Generate a pre-signed link to share this article on social media
              or via email. Recipients can unlock the content without logging
              in.
            </p>
            <ShareButton resourceId={article.id} />
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
