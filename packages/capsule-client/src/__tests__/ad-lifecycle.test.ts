import { describe, it, expect, vi, afterEach } from "vitest";
import { DcaClient } from "../dca-client";
import type { DcaAdLifecycleEvent } from "../ad-lifecycle";

/**
 * The ad lifecycle registry (window.dcaAds) is a page-global singleton shared
 * across this test file, so its event buffer and emission counters accumulate.
 * Tests stay deterministic by using a unique `publisher-content-id` per test
 * (fresh counter → emission starts at 1) and filtering replayed events by it.
 */

/** Article with a content placeholder; no manifest (enough for renderToPage). */
function setupContent(contentId: string): HTMLElement {
    document.body.innerHTML = `
    <article publisher-content-id="${contentId}">
      <div data-dca-content-name="bodytext">teaser</div>
    </article>`;
    return document.querySelector("article")!;
}

/** Article with manifest + content (for processPage). */
function setupManifest(contentId: string): HTMLElement {
    document.body.innerHTML = `
    <article publisher-content-id="${contentId}">
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
    </article>`;
    return document.querySelector("article")!;
}

/** Capture the detail payloads of a lifecycle event for the duration of fn. */
async function captureEvents<T>(
    name: string,
    fn: () => T | Promise<T>,
): Promise<{ result: T; details: Array<Record<string, unknown>> }> {
    const details: Array<Record<string, unknown>> = [];
    const handler = (e: Event) => details.push((e as CustomEvent).detail);
    document.addEventListener(name, handler);
    try {
        const result = await fn();
        return { result, details };
    } finally {
        document.removeEventListener(name, handler);
    }
}

afterEach(() => {
    document.body.innerHTML = "";
});

describe("dca:rendered", () => {
    it("fires after placement with contentId, emission, and deduped slots in document order", async () => {
        const root = setupContent("rendered-1");
        const client = new DcaClient({ wrapKeyCache: false });

        const { details } = await captureEvents("dca:rendered", () =>
            client.renderToPage(
                {
                    bodytext: `<p>hi</p>
                        <div data-dca-ad="in-article-1"></div>
                        <div data-dca-ad="in-article-2"></div>`,
                },
                root,
            ),
        );

        expect(details).toHaveLength(1);
        expect(details[0]).toEqual({
            contentId: "rendered-1",
            emission: 1,
            slots: ["in-article-1", "in-article-2"],
        });
    });

    it("lists a duplicate slot id only once", async () => {
        const root = setupContent("rendered-dup");
        const client = new DcaClient({ wrapKeyCache: false });

        const { details } = await captureEvents("dca:rendered", () =>
            client.renderToPage(
                { bodytext: `<div data-dca-ad="dup"></div><div data-dca-ad="dup"></div>` },
                root,
            ),
        );

        expect(details[0]!.slots).toEqual(["dup"]);
    });

    it("increments emission on re-render of the same contentId (late unlock)", async () => {
        const root = setupContent("reemit-1");
        const client = new DcaClient({ wrapKeyCache: false });

        const { details } = await captureEvents("dca:rendered", () => {
            client.renderToPage({ bodytext: `<div data-dca-ad="s1"></div>` }, root);
            client.renderToPage({ bodytext: `<div data-dca-ad="s1"></div>` }, root);
        });

        expect(details.map((d) => d.emission)).toEqual([1, 2]);
    });
});

describe("dca:locked", () => {
    it("fires with reason no-access when accessCheck denies", async () => {
        const root = setupContent("locked-1");
        const client = new DcaClient({
            wrapKeyCache: false,
            accessCheck: async () => ({ hasAccess: false }),
            paywallFn: vi.fn(),
        });

        const { result, details } = await captureEvents("dca:locked", () =>
            client.processPage({ root }),
        );

        expect(result).toEqual({});
        expect(details).toEqual([{ contentId: "locked-1", reason: "no-access" }]);
    });

    it("fires with reason no-content-id when accessCheck is configured but the id is missing", async () => {
        document.body.innerHTML = `<div id="noid"></div>`;
        const root = document.getElementById("noid")!;
        const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
        const client = new DcaClient({
            wrapKeyCache: false,
            accessCheck: async () => ({ hasAccess: true }),
            paywallFn: vi.fn(),
        });

        const { result, details } = await captureEvents("dca:locked", () =>
            client.processPage({ root }),
        );
        warn.mockRestore();

        expect(result).toEqual({});
        expect(details).toContainEqual({ contentId: null, reason: "no-content-id" });
    });
});

describe("dca:error", () => {
    it("fires with stage decrypt before processPage rejects", async () => {
        const root = setupManifest("err-1");
        const client = new DcaClient({
            wrapKeyCache: false,
            accessCheck: async () => ({ hasAccess: true }),
            unlockFn: vi
                .fn()
                .mockResolvedValue({ keys: [{ contentName: "bodytext", contentKey: "fake-key" }] }),
        });

        const { details } = await captureEvents("dca:error", async () => {
            await expect(client.processPage({ root })).rejects.toThrow();
        });

        expect(
            details.some((d) => d.stage === "decrypt" && d.contentId === "err-1"),
        ).toBe(true);
    });
});

describe("window.dcaAds", () => {
    it("replays buffered emissions to a late subscriber", () => {
        const root = setupContent("replay-1");
        // Emit before subscribing.
        new DcaClient({ wrapKeyCache: false }).renderToPage(
            { bodytext: `<div data-dca-ad="r1"></div>` },
            root,
        );

        const seen: DcaAdLifecycleEvent[] = [];
        const unsub = window.dcaAds!.subscribe((e) => seen.push(e));
        unsub();

        const mine = seen.filter((e) => e.contentId === "replay-1");
        expect(mine).toHaveLength(1);
        expect(mine[0]).toMatchObject({ type: "rendered", emission: 1, slots: ["r1"] });
    });

    it("stops delivering after unsubscribe", () => {
        const seen: DcaAdLifecycleEvent[] = [];
        const unsub = window.dcaAds!.subscribe((e) => seen.push(e));
        const afterReplay = seen.length;
        unsub();

        const root = setupContent("unsub-1");
        new DcaClient({ wrapKeyCache: false }).renderToPage(
            { bodytext: `<div data-dca-ad="u1"></div>` },
            root,
        );

        expect(seen).toHaveLength(afterReplay);
    });

    it("whenRendered resolves on the first render for a contentId", async () => {
        const root = setupContent("when-1");
        const pending = window.dcaAds!.whenRendered("when-1");

        new DcaClient({ wrapKeyCache: false }).renderToPage(
            { bodytext: `<div data-dca-ad="w1"></div>` },
            root,
        );

        const event = await pending;
        expect(event).toMatchObject({ type: "rendered", contentId: "when-1", emission: 1 });
    });

    it("a throwing subscriber does not break placement or starve other subscribers", () => {
        const errSpy = vi.spyOn(console, "error").mockImplementation(() => {});
        const good: DcaAdLifecycleEvent[] = [];
        const unsubBad = window.dcaAds!.subscribe(() => {
            throw new Error("boom");
        });
        const unsubGood = window.dcaAds!.subscribe((e) => {
            if (e.contentId === "throw-1") good.push(e);
        });

        const root = setupContent("throw-1");
        const result = new DcaClient({ wrapKeyCache: false }).renderToPage(
            { bodytext: `<div data-dca-ad="t1"></div>` },
            root,
        );

        unsubBad();
        unsubGood();
        errSpy.mockRestore();

        expect(result.has("bodytext")).toBe(true);
        expect(good).toHaveLength(1);
    });
});
