/**
 * Reference Capsule ad adapter (Google Publisher Tag flavour).
 *
 * This is production-shaped GPT code. It is the bridge described by the Ads API
 * guide: it reads the cleartext `dca-ad-manifest`, requests page-level ads
 * immediately, and binds in-content ads to Capsule's lifecycle via
 * `window.dcaAds`. The only demo-specific part is that `window.googletag` is the
 * fake stub from `fake-googletag.ts`; against real `gpt.js` this code is unchanged.
 *
 * Contract behaviour implemented here:
 *   - request a slot only after its marker exists and has geometry (page ads at
 *     load; in-content ads on `dca:rendered`);
 *   - on re-emission (`emission > 1`, e.g. late unlock) destroy that region's
 *     slots before re-initialising, so no ad iframe is orphaned or reloaded;
 *   - ignore marker ids with no manifest entry, and manifest entries with no
 *     marker;
 *   - honour `lazy` via IntersectionObserver.
 */

import type { DcaAdLifecycleEvent } from "@sesamy/capsule";

interface AdManifestSlot {
    id: string;
    contentId?: string | null;
    sizes: Array<[number, number]>;
    minHeight?: number;
    lazy?: boolean;
    adUnitPath: string;
    targeting?: Record<string, string | string[]>;
}

interface AdManifest {
    version: string;
    page: { contentId: string | null };
    slots: AdManifestSlot[];
}

let started = false;

export function startGptAdAdapter(): void {
    if (typeof window === "undefined") return;
    if (started) return; // idempotent across React StrictMode double-mount
    started = true;

    const manifest = readManifest();
    if (!manifest) {
        console.warn("[dca-ads] no <script class=\"dca-ad-manifest\"> on the page");
        return;
    }

    const byId = new Map(manifest.slots.map((s) => [s.id, s]));
    const defined = new Map<string, unknown>(); // div id -> googletag slot
    const renderedByContent = new Map<string | null, Set<string>>();

    googletag().cmd.push(() => {
        googletag().pubads().enableSingleRequest();
        googletag().enableServices();
    });

    // Page-level ads (outside locked content) have markers present at load.
    for (const slot of manifest.slots) {
        if (document.querySelector(`[data-dca-ad="${cssEscape(slot.id)}"]`)) {
            request(slot);
        }
    }

    // In-content ads: bind to the content lifecycle. `subscribe` replays any
    // emission that fired before this ran, so we cannot miss one.
    window.dcaAds?.subscribe((event: DcaAdLifecycleEvent) => {
        if (event.type !== "rendered") return;

        if (event.emission > 1) destroyForContent(event.contentId);

        const seen = renderedByContent.get(event.contentId) ?? new Set<string>();
        for (const id of event.slots) {
            const slot = byId.get(id);
            if (!slot) {
                console.warn(`[dca-ads] marker "${id}" has no manifest entry — skipping`);
                continue;
            }
            request(slot);
            seen.add(id);
        }
        renderedByContent.set(event.contentId, seen);
    });

    function request(slot: AdManifestSlot): void {
        const el = document.querySelector<HTMLElement>(
            `[data-dca-ad="${cssEscape(slot.id)}"]`,
        );
        if (!el) return; // manifest entry with no marker — nothing to fill
        if (defined.has(slot.id)) return; // already requested

        if (slot.lazy && !nearViewport(el)) {
            observeOnce(el, () => requestNow(slot, el));
            return;
        }
        requestNow(slot, el);
    }

    function requestNow(slot: AdManifestSlot, el: HTMLElement): void {
        // GPT addresses slots by element id; bridge from the data attribute.
        if (!el.id) el.id = slot.id;
        googletag().cmd.push(() => {
            const gptSlot = googletag().defineSlot(slot.adUnitPath, slot.sizes, el.id);
            if (!gptSlot) return;
            gptSlot.addService(googletag().pubads());
            for (const [k, v] of Object.entries(slot.targeting ?? {})) {
                gptSlot.setTargeting(k, v);
            }
            googletag().display(el.id);
            defined.set(slot.id, gptSlot);
        });
    }

    function destroyForContent(contentId: string | null): void {
        const ids = renderedByContent.get(contentId);
        if (!ids || ids.size === 0) return;
        const slots = Array.from(ids)
            .map((id) => defined.get(id))
            .filter((s): s is NonNullable<typeof s> => Boolean(s));
        googletag().cmd.push(() => googletag().destroySlots(slots as never[]));
        ids.forEach((id) => defined.delete(id));
        renderedByContent.set(contentId, new Set());
    }
}

function readManifest(): AdManifest | null {
    const el = document.querySelector("script.dca-ad-manifest");
    if (!el?.textContent) return null;
    try {
        return JSON.parse(el.textContent) as AdManifest;
    } catch (err) {
        console.error("[dca-ads] failed to parse ad manifest", err);
        return null;
    }
}

function googletag() {
    const gt = window.googletag;
    if (!gt) throw new Error("googletag not installed");
    return gt;
}

function cssEscape(value: string): string {
    return typeof CSS !== "undefined" && CSS.escape
        ? CSS.escape(value)
        : value.replace(/[^a-zA-Z0-9_-]/g, (c) => `\\${c}`);
}

function nearViewport(el: Element, margin = 400): boolean {
    const rect = el.getBoundingClientRect();
    return rect.top < window.innerHeight + margin && rect.bottom > -margin;
}

function observeOnce(el: Element, cb: () => void): void {
    const io = new IntersectionObserver(
        (entries) => {
            if (entries.some((e) => e.isIntersecting)) {
                io.disconnect();
                cb();
            }
        },
        { rootMargin: "400px" },
    );
    io.observe(el);
}
