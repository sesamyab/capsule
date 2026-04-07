/**
 * Capsule Client — DCA (Delegated Content Access) browser client.
 *
 * Provides client-side DCA content decryption:
 * - Parse DCA data from the DOM or JSON API responses
 * - Call issuer unlock endpoints to obtain keys
 * - AES-256-GCM content decryption with AAD support
 * - Period key caching for cross-page key reuse
 * - Optional client-bound transport (RSA-OAEP key wrapping)
 *
 * @example
 * ```ts
 * import { DcaClient } from '@sesamy/capsule';
 *
 * const client = new DcaClient();
 *
 * // Parse DCA data from the current page
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

import { DcaClient } from "./dca-client";

export {
  DcaClient,
  type DcaAccessResult,
  type DcaClientOptions,
  type DcaParsedPage,
  type DcaPeriodKeyCache,
  type DcaData,
  type DcaUnlockResponse,
  type DcaProcessPageOptions,
} from "./dca-client";

/** Standalone re-export of {@link DcaClient.getShareTokenFromUrl}. */
export function parseShareToken(paramName?: string): string | null {
  return DcaClient.getShareTokenFromUrl(paramName);
}

/** Standalone re-export of {@link DcaClient.hasDcaContent}. */
export function hasDcaContent(root?: Document | Element): boolean {
  return DcaClient.hasDcaContent(root);
}
