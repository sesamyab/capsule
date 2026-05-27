// jsdom (the vitest test environment) does not implement the `CSS` namespace
// object, so `CSS.escape` — used by DcaClient.renderToPage — is unavailable.
// Provide a minimal polyfill so DOM-placement code paths are testable. Real
// browsers ship a native CSS.escape, so this only affects the test env.
if (
    typeof globalThis.CSS === "undefined" ||
    typeof globalThis.CSS.escape !== "function"
) {
    (globalThis as unknown as { CSS: { escape(value: string): string } }).CSS = {
        escape: (value: string) =>
            String(value).replace(/[^a-zA-Z0-9_-]/g, (ch) => `\\${ch}`),
    };
}
