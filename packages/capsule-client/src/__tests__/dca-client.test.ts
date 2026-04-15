import { describe, it, expect, vi } from "vitest";
import { DcaClient } from "../dca-client";

/**
 * Minimal DOM setup: an article element with publisher-content-id
 * and a dca-manifest script.
 */
function setupDom(publisherContentId: string) {
  document.body.innerHTML = `
    <article publisher-content-id="${publisherContentId}">
      <script class="dca-manifest" type="application/json">${JSON.stringify({
        version: "0.10",
        resourceJWT: "fake.jwt.token",
        content: {
          bodytext: {
            contentType: "text/html",
            iv: "AAAA",
            aad: "test-aad",
            ciphertext: "encrypted-blob",
            wrappedContentKey: [],
          },
        },
        issuers: {
          testIssuer: {
            unlockUrl: "https://example.com/unlock",
            keyId: "k1",
            keys: [{ contentName: "bodytext", scope: "bodytext", contentKey: "ck", wrapKeys: [] }],
          },
        },
      })}</script>
      <div data-dca-content-name="bodytext">placeholder</div>
    </article>
  `;

  return document.querySelector("article")!;
}

describe("processPage access check", () => {
  it("does not call unlock when accessCheck returns hasAccess: false", async () => {
    const root = setupDom("article-123");
    const paywallFn = vi.fn();
    const unlockFn = vi.fn();

    const client = new DcaClient({
      accessCheck: async () => ({ hasAccess: false }),
      paywallFn,
      unlockFn,
    });

    const result = await client.processPage({ root });

    expect(result).toEqual({});
    expect(unlockFn).not.toHaveBeenCalled();
    expect(paywallFn).toHaveBeenCalledWith("article-123", root);
  });

  it("does not call unlock when accessCheck returns null", async () => {
    const root = setupDom("article-456");
    const paywallFn = vi.fn();
    const unlockFn = vi.fn();

    const client = new DcaClient({
      accessCheck: async () => null,
      paywallFn,
      unlockFn,
    });

    const result = await client.processPage({ root });

    expect(result).toEqual({});
    expect(unlockFn).not.toHaveBeenCalled();
    expect(paywallFn).toHaveBeenCalledWith("article-456", root);
  });

  it("proceeds with unlock when accessCheck returns hasAccess: true", async () => {
    const root = setupDom("article-789");
    const paywallFn = vi.fn();
    const unlockFn = vi.fn().mockResolvedValue({
      keys: [{ contentName: "bodytext", contentKey: "fake-key" }],
    });

    const client = new DcaClient({
      accessCheck: async () => ({ hasAccess: true }),
      paywallFn,
      unlockFn,
    });

    // Decrypt will fail (fake keys), but unlock should have been called
    await expect(client.processPage({ root })).rejects.toThrow();
    expect(unlockFn).toHaveBeenCalled();
    expect(paywallFn).not.toHaveBeenCalled();
  });
});
