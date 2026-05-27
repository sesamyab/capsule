/**
 * Fake Google Publisher Tag (`googletag`) for the demo.
 *
 * Mimics just enough of the real GPT surface (`cmd`, `defineSlot`, `pubads`,
 * `enableServices`, `display`, `destroySlots`) that the ad adapter in
 * `gpt-ad-adapter.ts` is *real* GPT code — going live means dropping the real
 * `gpt.js` in place of this stub and removing the install call. Instead of
 * calling Google, `display()` paints a labelled placeholder creative into the
 * slot element, so the ad flow is visible with no network and no ad units.
 */

export interface FakeSlot {
    getSlotElementId(): string;
    getAdUnitPath(): string;
    addService(service: unknown): FakeSlot;
    setTargeting(key: string, value: string | string[]): FakeSlot;
}

interface FakePubAdsService {
    enableSingleRequest(): FakePubAdsService;
    setTargeting(key: string, value: string | string[]): FakePubAdsService;
    addEventListener(): FakePubAdsService;
}

export interface FakeGoogletag {
    /** Marker so we don't double-install or mistake it for the real GPT. */
    __fake: true;
    cmd: { push(fn: () => void): number };
    defineSlot(
        adUnitPath: string,
        sizes: Array<[number, number]>,
        divId: string,
    ): FakeSlot | null;
    pubads(): FakePubAdsService;
    enableServices(): void;
    display(divId: string): void;
    destroySlots(slots?: FakeSlot[]): boolean;
}

declare global {
    interface Window {
        googletag?: FakeGoogletag;
    }
}

function escapeHtml(value: string): string {
    return value
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;");
}

function renderPlaceholder(
    el: HTMLElement,
    adUnitPath: string,
    sizes: Array<[number, number]>,
): void {
    const size = sizes[0] ? `${sizes[0][0]}×${sizes[0][1]}` : "fluid";
    el.classList.add("dca-ad-filled");
    el.innerHTML = `<div class="dca-ad-creative">
        <span class="dca-ad-label">Advertisement</span>
        <span class="dca-ad-meta">${escapeHtml(adUnitPath)} · ${size}</span>
    </div>`;
}

/**
 * Install the fake `window.googletag`. Idempotent and SSR-safe.
 */
export function installFakeGoogletag(): void {
    if (typeof window === "undefined") return;
    if (window.googletag?.__fake) return;

    const slots = new Map<string, { slot: FakeSlot; sizes: Array<[number, number]> }>();

    const pubads: FakePubAdsService = {
        enableSingleRequest: () => pubads,
        setTargeting: () => pubads,
        addEventListener: () => pubads,
    };

    const googletag: FakeGoogletag = {
        __fake: true,
        cmd: {
            // Real GPT queues until the library loads; the stub runs immediately.
            push(fn) {
                try {
                    fn();
                } catch (err) {
                    console.error("[fake-gpt] command threw", err);
                }
                return 1;
            },
        },
        defineSlot(adUnitPath, sizes, divId) {
            const slot: FakeSlot = {
                getSlotElementId: () => divId,
                getAdUnitPath: () => adUnitPath,
                addService: () => slot,
                setTargeting: () => slot,
            };
            slots.set(divId, { slot, sizes });
            return slot;
        },
        pubads: () => pubads,
        enableServices() {
            /* no-op in the stub */
        },
        display(divId) {
            const entry = slots.get(divId);
            const el = document.getElementById(divId);
            if (!entry || !el) {
                console.warn(`[fake-gpt] display("${divId}"): slot or element missing`);
                return;
            }
            renderPlaceholder(el, entry.slot.getAdUnitPath(), entry.sizes);
            console.log(`[fake-gpt] displayed ${entry.slot.getAdUnitPath()} in #${divId}`);
        },
        destroySlots(toDestroy) {
            const targets = toDestroy ?? Array.from(slots.values()).map((e) => e.slot);
            for (const slot of targets) {
                const id = slot.getSlotElementId();
                const el = document.getElementById(id);
                if (el) {
                    el.innerHTML = "";
                    el.classList.remove("dca-ad-filled");
                }
                slots.delete(id);
            }
            console.log(`[fake-gpt] destroyed ${targets.length} slot(s)`);
            return true;
        },
    };

    window.googletag = googletag;
}
