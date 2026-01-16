import { notFound } from "next/navigation";
import { getArticle, getAllArticleIds } from "@/lib/articles";
import { getEncryptedArticle } from "@/lib/server-encryption";
import { EncryptedSection } from "@/components/EncryptedSection";
import { DemoLayout } from "@/components/DemoLayout";
import { KeyManager } from "@/components/KeyManager";

interface ArticlePageProps {
  params: Promise<{ slug: string }>;
}

export default async function ArticlePage({ params }: ArticlePageProps) {
  const { slug } = await params;
  const article = getArticle(slug);

  if (!article) {
    notFound();
  }

  // Get the pre-encrypted content for SSR embedding
  const encryptedData = getEncryptedArticle(slug);

  return (
    <DemoLayout>
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
              articleId={article.id}
              encryptedData={encryptedData}
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
