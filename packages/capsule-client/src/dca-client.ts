/**
 * DCA Client — browser-side parser, unlock caller, and decryptor.
 *
 * This module provides:
 *   1. Page parsing: extract the DCA manifest from the DOM
 *   2. Unlock flow: call issuer's unlock endpoint and receive keys
 *   3. Decryption: AES-256-GCM content decryption with AAD support
 *   4. WrapKey caching: reuse wrapKeys across pages
 *
 * Designed for browser environments (Web Crypto API required).
 *
 * @example
 * ```typescript
 * import { DcaClient } from '@sesamy/capsule-client';
 *
 * const client = new DcaClient();
 *
 * // Parse the manifest from the current page
 * const page = client.parsePage();
 *
 * // Unlock via an issuer
 * const keys = await client.unlock(page, "sesamy");
 *
 * // Decrypt a specific content item
 * const html = await client.decrypt(page, "bodytext", keys);
 *
 * // Inject into the DOM
 * document.querySelector('[data-dca-content-name="bodytext"]')!.innerHTML = html;
 * ```
 */

// ============================================================================
// Types (self-contained for browser bundle size)
// ============================================================================

/** DCA manifest from `<script class="dca-manifest">` */
export interface DcaManifest {
    version: string;
    resourceJWT: string;
    content: Record<string, {
        contentType: string;
        iv: string;
        aad: string;
        ciphertext: string;
        wrappedContentKey: Array<{
            kid: string;
            iv: string;
            ciphertext: string;
        }>;
    }>;
    issuers: Record<string, {
        unlockUrl: string;
        keyId: string;
        keys: Array<{
            contentName?: string;
            scope: string;
            contentKey: string;
            wrapKeys: Array<{ kid: string; key: string }>;
        }>;
    }>;
}

/** Parsed page data — manifest only (ciphertext lives inside manifest.content) */
export interface DcaParsedPage {
    manifest: DcaManifest;
}

/** Unlock response from issuer — each entry has exactly one delivery form */
export interface DcaUnlockResponse {
    keys: Array<
        | { contentName?: string; scope?: string; contentKey: string; wrapKeys?: never }
        | { contentName?: string; scope?: string; wrapKeys: Array<{ kid: string; key: string }>; contentKey?: never }
    >;
    /**
     * Transport mode used by the issuer:
     *   - "direct": keys are plaintext base64url strings
     *   - "client-bound": keys are RSA-OAEP wrapped with the client's public key
     * Absent means direct (backward compatible).
     */
    transport?: "direct" | "client-bound";
}

/** Result of an access check */
export interface DcaAccessResult {
    hasAccess: boolean;
}

/** Options for DcaClient */
export interface DcaClientOptions {
    /**
     * Custom fetch function (useful for adding auth headers).
     * Defaults to globalThis.fetch.
     */
    fetch?: typeof globalThis.fetch;
    /**
     * Custom unlock function — replaces the default fetch-based unlock.
     * Receives the issuer's unlockUrl and the request body.
     */
    unlockFn?: (unlockUrl: string, body: unknown) => Promise<DcaUnlockResponse>;
    /**
     * WrapKey cache implementation.
     *
     * - Omitted / `undefined` (default): uses an IndexedDB-backed cache so
     *   wrapKeys are reused across page navigations.
     * - A custom {@link DcaWrapKeyCache}: delegates to the provided cache
     *   (e.g. sessionStorage, in-memory).
     * - `false`: disables caching entirely.
     */
    wrapKeyCache?: DcaWrapKeyCache | false;
    /**
     * Enable client-bound transport mode.
     *
     * When true, the client generates an RSA-OAEP key pair, stores the
     * private key as non-extractable in IndexedDB, and sends the public key
     * with each unlock request. The issuer wraps returned keys with this
     * public key, so no readable key material is sent over the network.
     *
     * Defaults to false (direct transport).
     */
    clientBound?: boolean;
    /**
     * RSA key size for client-bound transport (2048 or 4096).
     * Defaults to 2048.
     */
    rsaKeySize?: 2048 | 4096;
    /**
     * IndexedDB database name for RSA key pair storage.
     * Defaults to "dca-keys".
     */
    keyDbName?: string;
    /**
     * Check whether the user has access to the content before attempting
     * unlock. Receives the `publisher-content-id` attribute value from the
     * article element. Return `{ hasAccess: true }` to proceed with
     * decryption, or `null` / `{ hasAccess: false }` to skip unlock and
     * trigger the paywall via {@link paywallFn}.
     */
    accessCheck?: (publisherContentId: string) => Promise<DcaAccessResult | null>;
    /**
     * Called when {@link accessCheck} indicates the user has no access.
     * Use this to inject a paywall UI.
     *
     * @param publisherContentId - The content ID that was denied
     * @param root - The DOM root that contains the DCA content
     */
    paywallFn?: (publisherContentId: string | null, root: Document | Element) => void;
}

/** Simple key-value cache interface for wrapKeys */
export interface DcaWrapKeyCache {
    get(key: string): Promise<string | null>;
    set(key: string, value: string): Promise<void>;
}

/** Options for the {@link DcaClient.processPage} convenience method */
export interface DcaProcessPageOptions {
    /** Override issuer name (default: first issuer found in manifest) */
    issuerName?: string;
    /**
     * Override share token.
     * - `undefined` (default): auto-detect from URL query param
     * - `string`: use this token
     * - `null`: skip share token detection
     */
    shareToken?: string | null;
    /** Query parameter name for share token auto-detection (default: "share") */
    shareTokenParam?: string;
    /** Additional fields to include in the unlock request body */
    additionalBody?: Record<string, unknown>;
    /** DOM root to parse (default: document) */
    root?: Document | Element;
}

// ============================================================================
// Base64url utilities (browser-friendly, no dependencies)
// ============================================================================

function base64UrlDecode(s: string): Uint8Array {
    const pad = s.length % 4;
    const padded = pad ? s + "=".repeat(4 - pad) : s;
    const b64 = padded.replace(/-/g, "+").replace(/_/g, "/");
    const binary = atob(b64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
}

function base64UrlEncode(bytes: Uint8Array): string {
    let binary = "";
    for (let i = 0; i < bytes.length; i++) {
        binary += String.fromCharCode(bytes[i]!);
    }
    return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}

/** RSA public exponent (65537) */
const RSA_PUBLIC_EXPONENT = new Uint8Array([0x01, 0x00, 0x01]);

/** IndexedDB defaults for RSA key pair storage */
const DEFAULT_KEY_DB_NAME = "dca-keys";
const DEFAULT_KEY_STORE_NAME = "keypair";
const DEFAULT_KEY_ID = "default";

/** IndexedDB defaults for the wrapKey cache */
const DEFAULT_WRAP_KEY_DB_NAME = "dca-wrap-keys";
const DEFAULT_WRAP_KEY_STORE_NAME = "wrap-keys";

/**
 * Build an IndexedDB-backed {@link DcaWrapKeyCache}.
 *
 * Used as the default cache when no explicit one is provided. Silently
 * no-ops in environments without IndexedDB (SSR, Node) so the client
 * stays safe to import server-side.
 */
function createDefaultWrapKeyCache(): DcaWrapKeyCache {
    let dbPromise: Promise<IDBDatabase> | null = null;

    function openDb(): Promise<IDBDatabase> {
        if (!dbPromise) {
            dbPromise = new Promise((resolve, reject) => {
                const request = indexedDB.open(DEFAULT_WRAP_KEY_DB_NAME, 1);
                request.onupgradeneeded = () => {
                    const db = request.result;
                    if (!db.objectStoreNames.contains(DEFAULT_WRAP_KEY_STORE_NAME)) {
                        db.createObjectStore(DEFAULT_WRAP_KEY_STORE_NAME);
                    }
                };
                request.onsuccess = () => resolve(request.result);
                request.onerror = () => reject(request.error);
            });
        }
        return dbPromise;
    }

    return {
        async get(key) {
            if (typeof indexedDB === "undefined") return null;
            try {
                const db = await openDb();
                return await new Promise<string | null>((resolve) => {
                    const tx = db.transaction(DEFAULT_WRAP_KEY_STORE_NAME, "readonly");
                    const store = tx.objectStore(DEFAULT_WRAP_KEY_STORE_NAME);
                    const req = store.get(key);
                    req.onsuccess = () => resolve((req.result as string) ?? null);
                    req.onerror = () => resolve(null);
                });
            } catch {
                return null;
            }
        },
        async set(key, value) {
            if (typeof indexedDB === "undefined") return;
            try {
                const db = await openDb();
                await new Promise<void>((resolve, reject) => {
                    const tx = db.transaction(DEFAULT_WRAP_KEY_STORE_NAME, "readwrite");
                    const store = tx.objectStore(DEFAULT_WRAP_KEY_STORE_NAME);
                    store.put(value, key);
                    tx.oncomplete = () => resolve();
                    tx.onerror = () => reject(tx.error);
                });
            } catch {
                // ignore — cache is best-effort
            }
        },
    };
}

// ============================================================================
// DCA Client
// ============================================================================

export class DcaClient {
    private fetchFn: typeof globalThis.fetch;
    private unlockFn?: (unlockUrl: string, body: unknown) => Promise<DcaUnlockResponse>;
    private wrapKeyCache?: DcaWrapKeyCache;
    private clientBound: boolean;
    private rsaKeySize: 2048 | 4096;
    private keyDbName: string;
    private keyPairPromise: Promise<CryptoKeyPair> | null = null;
    private accessCheck?: (publisherContentId: string) => Promise<DcaAccessResult | null>;
    private paywallFn?: (publisherContentId: string | null, root: Document | Element) => void;

    constructor(options: DcaClientOptions = {}) {
        this.fetchFn = options.fetch ?? globalThis.fetch.bind(globalThis);
        this.unlockFn = options.unlockFn;
        this.wrapKeyCache = options.wrapKeyCache === false
            ? undefined
            : options.wrapKeyCache ?? createDefaultWrapKeyCache();
        this.clientBound = options.clientBound ?? false;
        this.rsaKeySize = options.rsaKeySize ?? 2048;
        this.keyDbName = options.keyDbName ?? DEFAULT_KEY_DB_NAME;
        this.accessCheck = options.accessCheck;
        this.paywallFn = options.paywallFn;
    }

    // --------------------------------------------------------------------------
    // Page parsing
    // --------------------------------------------------------------------------

    /**
     * Parse the DCA manifest from the current page DOM.
     *
     * Looks for `<script class="dca-manifest">` and parses its JSON body.
     * The manifest contains everything needed for decryption — no separate
     * sealed-content template is required.
     *
     * @param root - DOM root to search (default: document)
     * @returns Parsed page data
     * @throws Error if the manifest element is not found or data is invalid
     */
    parsePage(root?: Document | Element): DcaParsedPage {
        const container = root ?? document;

        const scriptEl = container.querySelector("script.dca-manifest");
        if (!scriptEl) {
            throw new Error("DCA: <script class=\"dca-manifest\"> not found");
        }

        const manifest = JSON.parse(scriptEl.textContent ?? "") as DcaManifest;

        return { manifest };
    }

    /**
     * Parse a DCA manifest from a JSON API response.
     */
    parseJsonResponse(json: DcaManifest): DcaParsedPage {
        return { manifest: json };
    }

    /**
     * Check whether the given root (or current page) contains a DCA manifest.
     *
     * @param root - DOM root to search (default: document)
     * @returns `true` if a `<script class="dca-manifest">` element exists
     */
    static hasDcaContent(root?: Document | Element): boolean {
        const container = root ?? document;
        return container.querySelector("script.dca-manifest") !== null;
    }

    // --------------------------------------------------------------------------
    // Unlock
    // --------------------------------------------------------------------------

    /**
     * Request key material from an issuer's unlock endpoint.
     *
     * @param page - Parsed page data
     * @param issuerName - Which issuer to call
     * @param additionalBody - Extra fields to include in the request body (e.g., auth tokens, shareToken)
     * @returns Unlock response with key material
     */
    async unlock(
        page: DcaParsedPage,
        issuerName: string,
        additionalBody?: Record<string, unknown>,
    ): Promise<DcaUnlockResponse> {
        const issuerEntry = page.manifest.issuers[issuerName];
        if (!issuerEntry) {
            throw new Error(`DCA: issuer "${issuerName}" not found in manifest.issuers`);
        }

        const body: Record<string, unknown> = {
            resourceJWT: page.manifest.resourceJWT,
            keys: issuerEntry.keys,
            ...additionalBody,
        };

        if (this.clientBound) {
            body.clientPublicKey = await this.getPublicKey();
        }

        if (this.unlockFn) {
            return this.unlockFn(issuerEntry.unlockUrl, body);
        }

        const response = await this.fetchFn(issuerEntry.unlockUrl, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(body),
        });

        if (!response.ok) {
            throw new Error(`DCA unlock failed: ${response.status} ${response.statusText}`);
        }

        return response.json() as Promise<DcaUnlockResponse>;
    }

    /**
     * Unlock content using a share link token.
     */
    async unlockWithShareToken(
        page: DcaParsedPage,
        issuerName: string,
        shareToken: string,
        additionalBody?: Record<string, unknown>,
    ): Promise<DcaUnlockResponse> {
        return this.unlock(page, issuerName, {
            ...additionalBody,
            shareToken,
        });
    }

    /**
     * Extract a share token from the current URL's query parameters.
     */
    static getShareTokenFromUrl(paramName = "share"): string | null {
        if (typeof window === "undefined" || typeof URL === "undefined") return null;
        try {
            const url = new URL(window.location.href);
            return url.searchParams.get(paramName);
        } catch {
            return null;
        }
    }

    // --------------------------------------------------------------------------
    // Decryption
    // --------------------------------------------------------------------------

    /**
     * Decrypt a content item using keys from the unlock response.
     *
     * Handles both delivery modes:
     *   - direct (contentKey): decrypts directly
     *   - wrapKey: unwraps contentKey from manifest.content[name].wrappedContentKey first
     *
     * @param page - Parsed page data
     * @param contentName - Which content item to decrypt
     * @param unlockResponse - Keys from the unlock endpoint
     * @returns Decrypted content as a string
     */
    async decrypt(
        page: DcaParsedPage,
        contentName: string,
        unlockResponse: DcaUnlockResponse,
        /** @internal Pre-resolved key entry — skips the linear scan when provided. */
        resolvedKeyEntry?: DcaUnlockResponse["keys"][number],
    ): Promise<string> {
        const entry = page.manifest.content[contentName];
        if (!entry) {
            throw new Error(`DCA: content entry not found for "${contentName}"`);
        }

        const keyEntry = resolvedKeyEntry ?? unlockResponse.keys.find(
            k => (k.contentName ?? "default") === contentName,
        );
        if (!keyEntry) {
            throw new Error(`DCA: no key provided for "${contentName}"`);
        }

        const isClientBound = unlockResponse.transport === "client-bound";

        const wrapKeysRecord = keyEntry.wrapKeys
            ? Object.fromEntries(keyEntry.wrapKeys.map(wk => [wk.kid, wk.key]))
            : undefined;

        let contentKeyBytes: Uint8Array;

        if (keyEntry.contentKey) {
            // Direct delivery: contentKey provided
            contentKeyBytes = isClientBound
                ? await this.rsaUnwrapKey(keyEntry.contentKey)
                : base64UrlDecode(keyEntry.contentKey);
        } else if (wrapKeysRecord) {
            // WrapKey delivery: unwrap contentKey from manifest using a wrapKey
            const rawWrapKeys = isClientBound
                ? await this.unwrapWrapKeyMap(wrapKeysRecord)
                : wrapKeysRecord;

            contentKeyBytes = await this.unwrapContentKey(
                entry.wrappedContentKey,
                rawWrapKeys,
            );

            // Cache by scope for cross-content reuse
            if (this.wrapKeyCache) {
                const scope = this.resolveScope(page, contentName) ?? contentName;
                await this.cacheWrapKeys(scope, rawWrapKeys);
            }
        } else {
            // Try cached wrapKeys (by scope)
            const scope = this.resolveScope(page, contentName) ?? contentName;
            const cached = await this.getCachedWrapKeys(scope, entry.wrappedContentKey);
            if (cached) {
                contentKeyBytes = await this.unwrapContentKey(
                    entry.wrappedContentKey,
                    cached,
                );
            } else {
                throw new Error(`DCA: no contentKey or wrapKeys available for "${contentName}"`);
            }
        }

        // Decrypt content body
        const ciphertextBytes = base64UrlDecode(entry.ciphertext);
        const iv = base64UrlDecode(entry.iv);
        const aad = new TextEncoder().encode(entry.aad);

        const aesKey = await crypto.subtle.importKey(
            "raw",
            contentKeyBytes as BufferSource,
            { name: "AES-GCM" },
            false,
            ["decrypt"],
        );

        const decrypted = await crypto.subtle.decrypt(
            { name: "AES-GCM", iv: iv as BufferSource, additionalData: aad as BufferSource, tagLength: 128 },
            aesKey,
            ciphertextBytes as BufferSource,
        );

        return new TextDecoder().decode(decrypted);
    }

    /**
     * Decrypt all content items that have unlocked keys and return a map.
     */
    async decryptAll(
        page: DcaParsedPage,
        unlockResponse: DcaUnlockResponse,
    ): Promise<Record<string, string>> {
        const results: Record<string, string> = {};
        const keyEntryMap = new Map(
            unlockResponse.keys.map(e => [e.contentName ?? "default", e]),
        );
        for (const [contentName, entry] of keyEntryMap) {
            results[contentName] = await this.decrypt(page, contentName, unlockResponse, entry);
        }
        return results;
    }

    // --------------------------------------------------------------------------
    // Convenience
    // --------------------------------------------------------------------------

    /**
     * Parse, unlock, and decrypt all content in a single call.
     *
     * Auto-detects the issuer (first key in `manifest.issuers`) and share token
     * (from URL query parameters) unless explicitly overridden via `options`.
     *
     * @param options - Optional overrides for issuer, share token, root, etc.
     * @returns Decrypted content map (`contentName` → decrypted HTML string)
     */
    async processPage(options: DcaProcessPageOptions = {}): Promise<Record<string, string>> {
        const root = options.root ?? document;

        if (this.accessCheck) {
            const publisherContentId = DcaClient.getPublisherContentId(root);
            if (!publisherContentId) {
                console.warn("DCA: accessCheck is configured but no publisher-content-id attribute was found on the page. Treating as denied.");
                if (this.paywallFn) {
                    this.paywallFn(publisherContentId, root);
                }
                return {};
            }

            const result = await this.accessCheck(publisherContentId);
            if (!result || !result.hasAccess) {
                if (this.paywallFn) {
                    this.paywallFn(publisherContentId, root);
                }
                return {};
            }
        }

        const page = this.parsePage(root);

        const issuerName = options.issuerName
            ?? Object.keys(page.manifest.issuers)[0];
        if (!issuerName) {
            throw new Error("DCA: no issuers found in manifest.issuers");
        }

        const shareToken = options.shareToken !== undefined
            ? options.shareToken
            : DcaClient.getShareTokenFromUrl(options.shareTokenParam);

        const unlockResponse = shareToken
            ? await this.unlockWithShareToken(page, issuerName, shareToken, options.additionalBody)
            : await this.unlock(page, issuerName, options.additionalBody);

        return this.decryptAll(page, unlockResponse);
    }

    /**
     * Inject decrypted content into the DOM.
     *
     * Finds elements with matching `data-dca-content-name` attributes and
     * sets their `innerHTML` to the corresponding decrypted content.
     *
     * @param content - Decrypted content map (from {@link processPage} or {@link decryptAll})
     * @param root - DOM root to search for target elements (default: document)
     * @returns The set of content names that were successfully rendered
     */
    renderToPage(
        content: Record<string, string>,
        root?: Document | Element,
    ): Set<string> {
        const container = root ?? document;
        const rendered = new Set<string>();

        for (const [contentName, html] of Object.entries(content)) {
            const el = container.querySelector(
                `[data-dca-content-name="${CSS.escape(contentName)}"]`,
            );
            if (el) {
                el.innerHTML = html;
                rendered.add(contentName);
            }
        }

        return rendered;
    }

    /**
     * Find the `publisher-content-id` attribute on the nearest ancestor of the
     * DCA content, or on the root element itself.
     *
     * @param root - DOM root to search (default: document)
     * @returns The publisher content ID, or null if not found
     */
    static getPublisherContentId(root?: Document | Element): string | null {
        const container = root ?? document;

        if (container instanceof Element) {
            const match = container.closest("[publisher-content-id]");
            if (match) return match.getAttribute("publisher-content-id");
        }

        const scriptEl = container.querySelector("script.dca-manifest");
        if (scriptEl) {
            const match = scriptEl.closest("[publisher-content-id]");
            if (match) return match.getAttribute("publisher-content-id");
        }

        return null;
    }

    /**
     * Start observing the DOM for dynamically added DCA content.
     *
     * When new elements containing `<script class="dca-manifest">` are inserted,
     * the observer automatically runs the access check and, if entitled,
     * calls {@link processPage} + {@link renderToPage}. If not entitled,
     * it calls the configured {@link DcaClientOptions.paywallFn | paywallFn}.
     *
     * @param root - DOM root to observe (default: document.body)
     * @param options - Options forwarded to {@link processPage}
     * @returns The MutationObserver instance (call `.disconnect()` to stop)
     */
    observe(
        root?: Element,
        options?: Omit<DcaProcessPageOptions, "root">,
    ): MutationObserver {
        const container = root ?? document.body;

        const observer = new MutationObserver((mutations) => {
            for (const mutation of mutations) {
                for (const node of Array.from(mutation.addedNodes)) {
                    if (!(node instanceof HTMLElement)) continue;

                    const targets: Element[] = [];

                    if (node.matches("script.dca-manifest")) {
                        const scriptContainer = node.parentElement ?? node;
                        if (!targets.includes(scriptContainer)) {
                            targets.push(scriptContainer);
                        }
                    }

                    const scripts = node.querySelectorAll("script.dca-manifest");
                    for (const script of Array.from(scripts)) {
                        const scriptContainer = script.parentElement ?? node;
                        if (!targets.includes(scriptContainer)) {
                            targets.push(scriptContainer);
                        }
                    }

                    for (const target of targets) {
                        this.processPage({ ...options, root: target })
                            .then((content) => {
                                if (Object.keys(content).length > 0) {
                                    this.renderToPage(content, target);
                                }
                            })
                            .catch((err) =>
                                console.error("DCA auto-process failed:", err),
                            );
                    }
                }
            }
        });

        observer.observe(container, { childList: true, subtree: true });
        return observer;
    }

    // --------------------------------------------------------------------------
    // WrapKey management
    // --------------------------------------------------------------------------

    /**
     * Resolve the scope for a given content item from the manifest.
     */
    private resolveScope(page: DcaParsedPage, contentName: string): string | undefined {
        for (const issuer of Object.values(page.manifest.issuers)) {
            const match = issuer.keys.find(k => (k.contentName ?? "default") === contentName);
            if (match) return match.scope;
        }
        return undefined;
    }

    /**
     * Unwrap a contentKey using one of the provided wrapKeys.
     * Tries each wrappedContentKey entry until one matches a provided wrapKey.
     */
    private async unwrapContentKey(
        wrappedContentKey: Array<{ kid: string; iv: string; ciphertext: string }>,
        wrapKeys: Record<string, string>,
    ): Promise<Uint8Array> {
        for (const entry of wrappedContentKey) {
            const wrapKeyB64 = wrapKeys[entry.kid];
            if (!wrapKeyB64) continue;

            const wrapKeyBytes = base64UrlDecode(wrapKeyB64);
            const iv = base64UrlDecode(entry.iv);
            const ciphertext = base64UrlDecode(entry.ciphertext);

            const aesKey = await crypto.subtle.importKey(
                "raw",
                wrapKeyBytes as BufferSource,
                { name: "AES-GCM" },
                false,
                ["decrypt"],
            );

            try {
                const decrypted = await crypto.subtle.decrypt(
                    { name: "AES-GCM", iv: iv as BufferSource, tagLength: 128 },
                    aesKey,
                    ciphertext as BufferSource,
                );
                return new Uint8Array(decrypted);
            } catch {
                continue;
            }
        }

        throw new Error("DCA: could not unwrap contentKey — no matching wrapKey");
    }

    private async cacheWrapKeys(
        scope: string,
        wrapKeys: Record<string, string>,
    ): Promise<void> {
        if (!this.wrapKeyCache) return;
        for (const [kid, keyB64] of Object.entries(wrapKeys)) {
            await this.wrapKeyCache.set(`dca:wk:${scope}:${kid}`, keyB64);
        }
    }

    private async getCachedWrapKeys(
        scope: string,
        wrappedContentKey: Array<{ kid: string }>,
    ): Promise<Record<string, string> | null> {
        if (!this.wrapKeyCache) return null;

        const keys: Record<string, string> = {};
        let found = false;
        for (const entry of wrappedContentKey) {
            const cached = await this.wrapKeyCache.get(`dca:wk:${scope}:${entry.kid}`);
            if (cached) {
                keys[entry.kid] = cached;
                found = true;
            }
        }
        return found ? keys : null;
    }

    // --------------------------------------------------------------------------
    // Client-bound transport: RSA key pair management
    // --------------------------------------------------------------------------

    /**
     * Get the client's RSA public key as a base64url-encoded SPKI string.
     * Generates and stores a new key pair on first call.
     */
    async getPublicKey(): Promise<string> {
        const keyPair = await this.ensureKeyPair();
        const spki = await crypto.subtle.exportKey("spki", keyPair.publicKey);
        return base64UrlEncode(new Uint8Array(spki));
    }

    /**
     * Check if a key pair exists (without creating one).
     */
    async hasKeyPair(): Promise<boolean> {
        try {
            const db = await this.openKeyDb();
            const stored = await this.idbGet(db, DEFAULT_KEY_ID);
            return stored !== undefined;
        } catch {
            return false;
        }
    }

    private ensureKeyPair(): Promise<CryptoKeyPair> {
        if (!this.keyPairPromise) {
            this.keyPairPromise = this.loadOrCreateKeyPair();
        }
        return this.keyPairPromise;
    }

    private async loadOrCreateKeyPair(): Promise<CryptoKeyPair> {
        try {
            const db = await this.openKeyDb();
            const stored = await this.idbGet(db, DEFAULT_KEY_ID);
            if (stored?.publicKey && stored?.privateKey) {
                return { publicKey: stored.publicKey, privateKey: stored.privateKey } as CryptoKeyPair;
            }
        } catch {
            // IndexedDB not available, fall through to generate in-memory
        }

        const keyPair = await crypto.subtle.generateKey(
            {
                name: "RSA-OAEP",
                modulusLength: this.rsaKeySize,
                publicExponent: RSA_PUBLIC_EXPONENT,
                hash: "SHA-256",
            },
            true,
            ["encrypt", "decrypt"],
        ) as CryptoKeyPair;

        const privateKeyJwk = await crypto.subtle.exportKey("jwk", keyPair.privateKey);
        const nonExtractablePrivateKey = await crypto.subtle.importKey(
            "jwk",
            privateKeyJwk,
            { name: "RSA-OAEP", hash: "SHA-256" },
            false,
            ["decrypt"],
        );

        const result = { publicKey: keyPair.publicKey, privateKey: nonExtractablePrivateKey } as CryptoKeyPair;

        try {
            const db = await this.openKeyDb();
            await this.idbPut(db, DEFAULT_KEY_ID, {
                id: DEFAULT_KEY_ID,
                publicKey: keyPair.publicKey,
                privateKey: nonExtractablePrivateKey,
                createdAt: Date.now(),
                keySize: this.rsaKeySize,
            });
        } catch {
            // IndexedDB not available — key pair lives in memory only
        }

        return result;
    }

    /**
     * RSA-OAEP decrypt a base64url-encoded ciphertext using the client's private key.
     * Returns the raw key bytes.
     */
    private async rsaUnwrapKey(wrappedKeyB64: string): Promise<Uint8Array> {
        const keyPair = await this.ensureKeyPair();
        const ciphertext = base64UrlDecode(wrappedKeyB64);
        const decrypted = await crypto.subtle.decrypt(
            { name: "RSA-OAEP" },
            keyPair.privateKey,
            ciphertext as BufferSource,
        );
        return new Uint8Array(decrypted);
    }

    /**
     * Unwrap a map of kid → RSA-OAEP-wrapped wrapKey to raw base64url strings.
     */
    private async unwrapWrapKeyMap(
        wrappedWrapKeys: Record<string, string>,
    ): Promise<Record<string, string>> {
        const raw: Record<string, string> = {};
        for (const [kid, wrappedKey] of Object.entries(wrappedWrapKeys)) {
            const keyBytes = await this.rsaUnwrapKey(wrappedKey);
            raw[kid] = base64UrlEncode(keyBytes);
        }
        return raw;
    }

    // --------------------------------------------------------------------------
    // IndexedDB helpers (minimal, no dependencies)
    // --------------------------------------------------------------------------

    private keyDbPromise: Promise<IDBDatabase> | null = null;

    private openKeyDb(): Promise<IDBDatabase> {
        if (!this.keyDbPromise) {
            this.keyDbPromise = new Promise((resolve, reject) => {
                const request = indexedDB.open(this.keyDbName, 1);
                request.onupgradeneeded = () => {
                    const db = request.result;
                    if (!db.objectStoreNames.contains(DEFAULT_KEY_STORE_NAME)) {
                        db.createObjectStore(DEFAULT_KEY_STORE_NAME, { keyPath: "id" });
                    }
                };
                request.onsuccess = () => resolve(request.result);
                request.onerror = () => reject(request.error);
            });
        }
        return this.keyDbPromise;
    }

    private idbGet(db: IDBDatabase, key: string): Promise<Record<string, unknown> | undefined> {
        return new Promise((resolve, reject) => {
            const tx = db.transaction(DEFAULT_KEY_STORE_NAME, "readonly");
            const store = tx.objectStore(DEFAULT_KEY_STORE_NAME);
            const request = store.get(key);
            request.onsuccess = () => resolve(request.result as Record<string, unknown> | undefined);
            request.onerror = () => reject(request.error);
        });
    }

    private idbPut(db: IDBDatabase, _key: string, value: Record<string, unknown>): Promise<void> {
        return new Promise((resolve, reject) => {
            const tx = db.transaction(DEFAULT_KEY_STORE_NAME, "readwrite");
            const store = tx.objectStore(DEFAULT_KEY_STORE_NAME);
            const request = store.put(value);
            request.onsuccess = () => resolve();
            request.onerror = () => reject(request.error);
        });
    }
}
