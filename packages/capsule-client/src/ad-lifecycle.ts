/**
 * Capsule ad-contract lifecycle.
 *
 * Implements the publisher-facing side of the ad contract (see the Ad Contract
 * specification): the `dca:rendered` / `dca:locked` / `dca:error` DOM events and
 * the `window.dcaAds` replay global that lets a publisher ad adapter bind ad
 * demand to Capsule's content lifecycle without racing it.
 *
 * Design notes:
 *   - The registry is a page-global singleton. The `emission` counter lives here
 *     (not on a {@link DcaClient} instance) so it stays monotonic per `contentId`
 *     no matter how many clients exist on the page.
 *   - `subscribe` replays every buffered event synchronously, so an adapter that
 *     attaches late (e.g. on a cached page where unlock resolves immediately)
 *     still sees the emissions it missed.
 *   - Subscriber handlers run inside try/catch: a throwing adapter must never
 *     break content placement or starve other subscribers.
 */

/** Lifecycle event discriminator. */
export type DcaLifecycleType = "rendered" | "locked" | "error";

/** Reason a locked region did not render. */
export type DcaLockedReason = "no-access" | "no-content-id";

/** Stage at which content resolution failed. */
export type DcaErrorStage = "parse" | "unlock" | "decrypt" | "render";

/**
 * A lifecycle event delivered to {@link DcaAdLifecycle.subscribe} handlers.
 *
 * The DOM `CustomEvent` form (`dca:rendered` etc.) carries the same fields on
 * its `detail`, minus `type` (which is encoded in the event name).
 */
export type DcaAdLifecycleEvent =
    | {
          type: "rendered";
          /** The `publisher-content-id`, or `null` when the page has no such attribute. */
          contentId: string | null;
          /** Monotonic counter per `contentId`. `1` is first render; `> 1` supersedes the prior DOM. */
          emission: number;
          /** `data-dca-ad` slot ids discovered in the placed subtree, in document order, deduped. */
          slots: string[];
      }
    | { type: "locked"; contentId: string | null; reason: DcaLockedReason }
    | { type: "error"; contentId: string | null; stage: DcaErrorStage; message: string };

/** A subscriber to the ad lifecycle. */
export type DcaAdLifecycleHandler = (event: DcaAdLifecycleEvent) => void;

/** Public surface exposed as `window.dcaAds`. */
export interface DcaAdLifecycle {
    /**
     * Subscribe to lifecycle events. Replays every event emitted so far
     * (synchronously, in order) before forwarding future ones. This is the
     * recommended integration point because it cannot miss an emission.
     *
     * @returns an unsubscribe function.
     */
    subscribe(handler: DcaAdLifecycleHandler): () => void;
    /**
     * Resolve once the first `dca:rendered` for `contentId` has happened.
     *
     * First-emission-only sugar: a promise cannot model re-emission
     * (`emission > 1`), so adapters that handle late unlock must use
     * {@link subscribe} instead.
     */
    whenRendered(contentId: string | null): Promise<DcaAdLifecycleEvent & { type: "rendered" }>;
}

interface AdLifecycleRegistry extends DcaAdLifecycle {
    /** Increment and return the emission count for a `contentId`. */
    nextEmission(contentId: string | null): number;
    /** Buffer + broadcast a lifecycle event. */
    emit(event: DcaAdLifecycleEvent): void;
}

/**
 * Build the page-global lifecycle registry.
 *
 * `buffer` retains every emitted event for the life of the page so that
 * {@link DcaAdLifecycle.subscribe} and {@link DcaAdLifecycle.whenRendered} can
 * replay the full history to late subscribers. This is deliberate: replaying
 * everything is the simplest thing that is always correct (a late adapter sees
 * exactly what an early one saw). The cost is unbounded growth — a long-lived
 * SPA that re-renders many regions will accumulate one entry per emission and
 * never release them. Capsule emits at most a handful of events per content
 * region, so this is fine in practice; an integrator embedding Capsule on a
 * page with very high emission volume may want to cap or window the buffer
 * (e.g. keep only the latest emission per `contentId`).
 */
function createRegistry(): AdLifecycleRegistry {
    const buffer: DcaAdLifecycleEvent[] = [];
    const handlers = new Set<DcaAdLifecycleHandler>();
    const emissionCounts = new Map<string, number>();
    const renderedWaiters = new Map<
        string,
        Array<(e: DcaAdLifecycleEvent & { type: "rendered" }) => void>
    >();

    // `null` contentId is bucketed under a stable sentinel key.
    const key = (contentId: string | null) => contentId ?? "\0null";

    function notify(handler: DcaAdLifecycleHandler, event: DcaAdLifecycleEvent): void {
        try {
            handler(event);
        } catch (err) {
            // A faulty adapter must not break placement or other subscribers.
            console.error("dcaAds: subscriber threw", err);
        }
    }

    return {
        nextEmission(contentId) {
            const k = key(contentId);
            const next = (emissionCounts.get(k) ?? 0) + 1;
            emissionCounts.set(k, next);
            return next;
        },

        emit(event) {
            buffer.push(event);
            for (const handler of handlers) {
                notify(handler, event);
            }
            if (event.type === "rendered") {
                const waiters = renderedWaiters.get(key(event.contentId));
                if (waiters) {
                    renderedWaiters.delete(key(event.contentId));
                    for (const resolve of waiters) resolve(event);
                }
            }
        },

        subscribe(handler) {
            // Replay first so a late subscriber cannot miss an emission.
            for (const event of buffer) {
                notify(handler, event);
            }
            handlers.add(handler);
            return () => {
                handlers.delete(handler);
            };
        },

        whenRendered(contentId) {
            const existing = buffer.find(
                (e): e is DcaAdLifecycleEvent & { type: "rendered" } =>
                    e.type === "rendered" && e.contentId === contentId,
            );
            if (existing) return Promise.resolve(existing);

            return new Promise((resolve) => {
                const k = key(contentId);
                const waiters = renderedWaiters.get(k) ?? [];
                waiters.push(resolve);
                renderedWaiters.set(k, waiters);
            });
        },
    };
}

/** The page-global registry. One per JS realm. */
const registry: AdLifecycleRegistry = createRegistry();

declare global {
    interface Window {
        dcaAds?: DcaAdLifecycle;
    }
}

// Install the global entry point for adapters (browser only; SSR-safe).
if (typeof window !== "undefined") {
    window.dcaAds ??= registry;
}

/**
 * Dispatch a lifecycle event: fires the DOM `CustomEvent` on `target` (bubbling
 * and composed so a single page-level listener works) and feeds the replay
 * registry. Capsule calls this from its content-placement, paywall, and error
 * paths.
 *
 * @param target - The `publisher-content-id` element, or `document` when none exists.
 */
export function dispatchDcaLifecycle(
    target: EventTarget,
    event: DcaAdLifecycleEvent,
): void {
    const { type, ...detail } = event;
    if (typeof CustomEvent !== "undefined") {
        target.dispatchEvent(
            new CustomEvent(`dca:${type}`, {
                detail,
                bubbles: true,
                composed: true,
            }),
        );
    }
    registry.emit(event);
}

/** Increment and return the page-global emission count for a `contentId`. */
export function nextAdEmission(contentId: string | null): number {
    return registry.nextEmission(contentId);
}

/** Test-only/advanced access to the registry. */
export function getAdLifecycle(): DcaAdLifecycle {
    return registry;
}
