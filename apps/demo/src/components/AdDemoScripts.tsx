"use client";

import { useEffect } from "react";

/**
 * Demo glue: installs the fake Google Publisher Tag and starts the reference ad
 * adapter on the client. In production a publisher would instead load the real
 * `gpt.js` and ship the adapter as a normal script — Capsule provides neither.
 *
 * Importing `@sesamy/capsule` first guarantees `window.dcaAds` is installed
 * before the adapter subscribes; its replay then covers any `dca:rendered`
 * that fired earlier.
 */
export function AdDemoScripts() {
    useEffect(() => {
        let cancelled = false;
        (async () => {
            await import("@sesamy/capsule");
            if (cancelled) return;
            const { installFakeGoogletag } = await import("@/lib/fake-googletag");
            const { startGptAdAdapter } = await import("@/lib/gpt-ad-adapter");
            installFakeGoogletag();
            startGptAdAdapter();
        })();
        return () => {
            cancelled = true;
        };
    }, []);

    return null;
}
