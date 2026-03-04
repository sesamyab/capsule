import { CodeBlock } from "@/components/CodeBlock";
import { PageWithToc } from "@/components/PageWithToc";

const th = { textAlign: "left" as const, padding: "0.5rem", borderBottom: "2px solid #333" };
const td = { padding: "0.5rem", borderBottom: "1px solid #ddd" };

function SectionCard({ color, children }: { color: "amber" | "indigo" | "emerald" | "slate"; children: React.ReactNode }) {
  const palette = {
    amber:   { bg: "rgba(251, 191, 36, 0.08)", border: "rgba(251, 191, 36, 0.35)" },
    indigo:  { bg: "rgba(99, 102, 241, 0.08)", border: "rgba(99, 102, 241, 0.35)" },
    emerald: { bg: "rgba(16, 185, 129, 0.08)", border: "rgba(16, 185, 129, 0.35)" },
    slate:   { bg: "rgba(148, 163, 184, 0.08)", border: "rgba(148, 163, 184, 0.35)" },
  }[color];
  return (
    <section style={{
      border: `1px solid ${palette.border}`,
      borderRadius: "10px",
      padding: "1.5rem 1.75rem",
      marginBottom: "2.5rem",
      background: palette.bg,
    }}>
      {children}
    </section>
  );
}

function CompatBadge({ compatible }: { compatible: boolean }) {
  return (
    <span style={{
      display: "inline-block",
      background: compatible
        ? "linear-gradient(135deg, #10b981, #059669)"
        : "linear-gradient(135deg, #f59e0b, #d97706)",
      color: "#fff",
      padding: "0.1rem 0.55rem",
      borderRadius: "5px",
      fontSize: "0.75rem",
      fontWeight: 700,
      verticalAlign: "middle",
    }}>
      {compatible ? "Backwards compatible" : "Not backwards compatible"}
    </span>
  );
}

export default function BetaPage() {
  return (
    <PageWithToc>
      <main className="content-page">
        <h1>v2 Changes <span style={{
          background: 'linear-gradient(135deg, #fbbf24, #f59e0b)',
          color: '#78350f',
          padding: '0.15rem 0.6rem',
          borderRadius: '6px',
          fontSize: '0.6em',
          fontWeight: 700,
          verticalAlign: 'middle',
          marginLeft: '0.5rem',
        }}>Beta</span></h1>

        <p>
          v2 introduces three changes to the unlock protocol. Each is described below
          with its motivation, what changed, and whether it&apos;s backwards compatible.
        </p>

        {/* ================================================================
            Change 1 — Simplified Unlock Request
            ================================================================ */}

        <h2>1. Simplified Unlock Request</h2>
        <SectionCard color="amber">
          <CompatBadge compatible={false} />

          <h3>Motivation</h3>
          <p>
            The v1 unlock request sends six fields and two JWTs. After analysis, four fields
            and one entire JWT turn out to be redundant:
          </p>
          <ul>
            <li><code>resource</code> — unsigned copy of what&apos;s already in <code>resourceJWT</code></li>
            <li><code>issuerName</code> — the subscription service already knows its own name</li>
            <li><code>issuerJWT</code> — contains SHA-256 integrity proofs of the sealed blobs,
              but AES-GCM is already <strong>authenticated encryption</strong> — any tampered
              blob fails at unseal time. The proofs are redundant.</li>
          </ul>

          <h3>Description</h3>
          <p>
            v2 strips the request down to the cryptographic essentials:
          </p>
          <ul>
            <li><code>resourceJWT</code> — publisher-signed resource metadata (authentication)</li>
            <li><code>sealed</code> — the sealed keys (AES-GCM provides integrity)</li>
            <li><code>keyId</code> — which private key to use (from page&apos;s <code>issuerData</code>)</li>
          </ul>

          <p><strong>Why the issuerJWT is unnecessary:</strong></p>
          <ol>
            <li>
              <strong>Integrity proofs:</strong> SHA-256 hashes of sealed blobs, to detect tampering.
              But sealed blobs use <strong>AES-GCM</strong> (authenticated encryption) — any modification
              causes the unseal to fail with a GCM authentication error. The hashes add nothing.
            </li>
            <li>
              <strong>Metadata:</strong> <code>issuerName</code>, <code>keyId</code>, and <code>renderId</code>.
              The service knows its own name. The <code>keyId</code> comes from the page&apos;s <code>issuerData</code>.
              The <code>renderId</code> is in the <code>resourceJWT</code>.
            </li>
          </ol>
          <p>
            Removing the issuerJWT eliminates one JWT signature verification per unlock request
            and the SHA-256 proof computation on both publisher and service sides.
          </p>

          <CodeBlock>{`// v1 unlock request (current) — 6 fields + 2 JWTs
POST /api/unlock
{
  "resource": { "domain": "news.example.com", "resourceId": "…", … },
  "resourceJWT": "eyJ…",
  "issuerJWT": "eyJ…",
  "sealed": { "bodytext": { "contentKey": "…", "periodKeys": { … } } },
  "keyId": "issuer-key-1",
  "issuerName": "sesamy",
  "clientPublicKey": "…"   // optional
}

// v2 unlock request (beta) — 3 fields + 1 JWT
POST /api/unlock
{
  "resourceJWT": "eyJ…",
  "sealed": { "bodytext": { "contentKey": "…", "periodKeys": { … } } },
  "keyId": "2025-10",
  "clientPublicKey": "…"   // optional
}`}</CodeBlock>

          <p>
            The service auto-detects the format based on whether <code>resource</code> is
            present in the request:
          </p>
          <ol>
            <li>
              <strong>Verify resourceJWT:</strong> Decode the JWT payload (unverified) to get the
              domain for publisher key selection. Verify the signature with the looked-up key.
              This is standard JWT practice (same as OIDC).
            </li>
            <li>
              <strong>Check keyId:</strong> The <code>keyId</code> in the request must match the
              service&apos;s configured key. This is the same check as v1, just sourced from the
              request body (which the client reads from <code>issuerData</code> on the page).
            </li>
            <li>
              <strong>Unseal:</strong> The service unseals the requested content keys. AES-GCM
              authentication ensures any tampered blob is rejected — no proof hashes needed.
            </li>
          </ol>

          <h3>Backwards Compatibility</h3>
          <table style={{ width: "100%", borderCollapse: "collapse", marginTop: "0.75rem", marginBottom: "0.5rem" }}>
            <thead>
              <tr>
                <th style={th}>Scenario</th>
                <th style={th}>Works?</th>
                <th style={th}>Notes</th>
              </tr>
            </thead>
            <tbody>
              <tr>
                <td style={td}>v1 client → v1 service</td>
                <td style={td}>✅</td>
                <td style={td}>No change</td>
              </tr>
              <tr>
                <td style={td}>v1 client → v2 service</td>
                <td style={td}>✅</td>
                <td style={td}>Service auto-detects v1 format, processes normally</td>
              </tr>
              <tr>
                <td style={td}>v2 client → v2 service</td>
                <td style={td}>✅</td>
                <td style={td}>Minimal request, full security</td>
              </tr>
              <tr>
                <td style={td}>v2 client → v1 service</td>
                <td style={td}>❌</td>
                <td style={td}>v1 service requires <code>issuerJWT</code>, <code>resource</code>, <code>issuerName</code></td>
              </tr>
            </tbody>
          </table>
          <p>
            <strong>Recommended migration:</strong> Upgrade the service first (accepts both formats),
            then switch clients to v2 at your own pace.
          </p>
        </SectionCard>

        {/* ================================================================
            Change 2 — Standard JWT Claims in resourceJWT
            ================================================================ */}

        <h2>2. Standard JWT Claims in resourceJWT</h2>
        <SectionCard color="emerald">
          <CompatBadge compatible={true} />

          <h3>Motivation</h3>
          <p>
            The v1 <code>resourceJWT</code> uses custom field names (<code>domain</code>,{' '}
            <code>resourceId</code>, <code>issuedAt</code>, <code>renderId</code>) instead
            of the well-known JWT claim names defined in RFC 7519. Using standard claims
            improves interoperability and makes the JWT self-describing.
          </p>

          <h3>Description</h3>
          <p>
            v2 maps the <code>resourceJWT</code> payload to standard JWT claim names:
          </p>
          <table style={{ width: "100%", borderCollapse: "collapse", marginTop: "0.75rem", marginBottom: "0.75rem" }}>
            <thead>
              <tr>
                <th style={th}>DcaResource field</th>
                <th style={th}>JWT claim</th>
                <th style={th}>RFC 7519 name</th>
                <th style={th}>Notes</th>
              </tr>
            </thead>
            <tbody>
              <tr>
                <td style={td}><code>domain</code></td>
                <td style={td}><code>iss</code></td>
                <td style={td}>Issuer</td>
                <td style={td}>The publisher that signed the JWT</td>
              </tr>
              <tr>
                <td style={td}><code>resourceId</code></td>
                <td style={td}><code>sub</code></td>
                <td style={td}>Subject</td>
                <td style={td}>The resource being accessed</td>
              </tr>
              <tr>
                <td style={td}><code>issuedAt</code> (ISO 8601)</td>
                <td style={td}><code>iat</code></td>
                <td style={td}>Issued At</td>
                <td style={td}>Unix timestamp (seconds) instead of ISO string</td>
              </tr>
              <tr>
                <td style={td}><code>renderId</code></td>
                <td style={td}><code>jti</code></td>
                <td style={td}>JWT ID</td>
                <td style={td}>Unique per-render identifier</td>
              </tr>
              <tr>
                <td style={td}><code>data</code></td>
                <td style={td}><code>data</code></td>
                <td style={td}>(custom)</td>
                <td style={td}>Publisher-defined metadata, unchanged</td>
              </tr>
            </tbody>
          </table>
          <p>
            The decoded <code>resourceJWT</code> payload now looks like a standard JWT:
          </p>
          <CodeBlock>{`// resourceJWT payload (decoded)
{
  "iss": "news.example.com",       // domain
  "sub": "article-123",            // resourceId
  "iat": 1735689600,               // issuedAt (Unix seconds)
  "jti": "abc123def456",           // renderId
  "data": { "section": "politics"} // custom metadata
}`}</CodeBlock>
          <p>
            The page&apos;s <code>DcaData.resource</code> still uses the human-readable field names
            (<code>domain</code>, <code>resourceId</code>, etc.) for debugging and display.
            The mapping happens automatically when the publisher creates the JWT and when
            the service verifies it.
          </p>

          <h3>Backwards Compatibility</h3>
          <p>
            Fully backwards compatible. The service detects the claim format automatically
            (checking for <code>iss</code> vs <code>domain</code>). Both v1 and v2 resource
            JWTs are accepted. No publisher or client changes are required.
          </p>
        </SectionCard>

        {/* ================================================================
            Change 3 — keyName
            ================================================================ */}

        <h2>3. keyName: Decoupling Content Identity from Key Domain</h2>
        <SectionCard color="indigo">
          <CompatBadge compatible={true} />

          <h3>Motivation</h3>
          <p>
            In v1, <code>contentName</code> serves three roles simultaneously:
          </p>
          <ol>
            <li><strong>Content identity</strong> — uniquely identifies a content item within a resource (e.g. &quot;bodytext&quot;, &quot;sidebar&quot;)</li>
            <li><strong>Key derivation salt</strong> — used as the HKDF salt for periodKey derivation</li>
            <li><strong>Access control scope</strong> — the issuer grants access by contentName</li>
          </ol>
          <p>
            This conflation forces publishers to use artificial names like &quot;TierA&quot; or
            &quot;premium&quot; as their contentName, losing the ability to describe <em>what</em> the
            content actually is. If a page has both a premium body and a premium sidebar, they
            need different contentNames but the same access scope — impossible in v1.
          </p>

          <h3>Description</h3>
          <p>
            <code>keyName</code> is an optional field on each content item that controls which key
            domain that item belongs to. When set, HKDF uses <code>keyName</code> instead
            of <code>contentName</code> as the salt, and the issuer can grant access
            by <code>keyName</code> instead of listing individual content names.
          </p>
          <table style={{ width: "100%", borderCollapse: "collapse", marginTop: "0.75rem", marginBottom: "0.75rem" }}>
            <thead>
              <tr>
                <th style={th}>Role</th>
                <th style={th}>v1 (contentName only)</th>
                <th style={th}>v2 (with keyName)</th>
              </tr>
            </thead>
            <tbody>
              <tr>
                <td style={td}>Content identity</td>
                <td style={td}><code>contentName</code></td>
                <td style={td}><code>contentName</code> (unchanged)</td>
              </tr>
              <tr>
                <td style={td}>Key derivation salt</td>
                <td style={td}><code>contentName</code></td>
                <td style={td}><code>keyName</code> (falls back to contentName)</td>
              </tr>
              <tr>
                <td style={td}>Access control scope</td>
                <td style={td}><code>grantedContentNames</code></td>
                <td style={td}><code>grantedKeyNames</code> (resolves via contentKeyMap)</td>
              </tr>
            </tbody>
          </table>

          <p><strong>Publisher — before &amp; after:</strong></p>
          <CodeBlock>{`// v1: contentName = "TierA" (conflates identity with access scope)
const result = await publisher.render({
  resourceId: "article-123",
  contentItems: [
    { contentName: "TierA", content: body, contentType: "text/html" },
  ],
  issuers: [{
    issuerName: "sesamy",
    publicKeyPem, keyId, unlockUrl,
    contentNames: ["TierA"],
  }],
});

// v2: contentName describes WHAT, keyName describes WHO can access
const result = await publisher.render({
  resourceId: "article-123",
  contentItems: [
    { contentName: "bodytext", keyName: "premium", content: body, contentType: "text/html" },
    { contentName: "sidebar",  keyName: "premium", content: side, contentType: "text/html" },
  ],
  issuers: [{
    issuerName: "sesamy",
    publicKeyPem, keyId, unlockUrl,
    keyNames: ["premium"],           // seals all items with this keyName
  }],
});`}</CodeBlock>

          <p><strong>Wire format — contentKeyMap:</strong></p>
          <p>
            When any content item has an explicit <code>keyName</code>, the publisher
            includes a <code>contentKeyMap</code> in the DCA data — a lightweight mapping
            from contentName to keyName:
          </p>
          <CodeBlock>{`// DcaData (embedded in page)
{
  "resource": { "resourceId": "article-123", "domain": "news.example.com", … },
  "contentKeyMap": {
    "bodytext": "premium",
    "sidebar": "premium"
  },
  "contentSealData": { "bodytext": { … }, "sidebar": { … } },
  "sealedContentKeys": { "bodytext": [ … ], "sidebar": [ … ] },
  …
}`}</CodeBlock>
          <p>
            The <code>contentKeyMap</code> is omitted when all keyNames equal their contentNames
            (the v1-compatible case), keeping zero overhead for publishers that don&apos;t use this feature.
          </p>

          <p><strong>Issuer — grantedKeyNames:</strong></p>
          <p>
            The issuer&apos;s access decision can now use <code>grantedKeyNames</code> instead of
            (or alongside) <code>grantedContentNames</code>:
          </p>
          <CodeBlock>{`// v1: grant by content name
const result = await issuer.unlock(request, {
  grantedContentNames: ["bodytext", "sidebar"],
  deliveryMode: "periodKey",
});

// v2: grant by key name — resolves to all matching content items
const result = await issuer.unlock(request, {
  grantedKeyNames: ["premium"],    // grants both "bodytext" and "sidebar"
  deliveryMode: "periodKey",
});`}</CodeBlock>

          <p><strong>Client — transparent handling:</strong></p>
          <p>
            The client handles <code>keyName</code> transparently. Period keys are cached
            by <code>keyName</code> instead of <code>contentName</code>, so unlocking any
            &quot;premium&quot; article automatically caches the key for all other &quot;premium&quot; articles:
          </p>
          <CodeBlock>{`const client = new DcaClient({ requestFormat: "v2" });
const page = client.parsePage();

// contentKeyMap is included automatically in the unlock request
const keys = await client.unlock(page, "sesamy");

// Decrypt by contentName — keyName is resolved internally
const body = await client.decrypt(page, "bodytext", keys);
const side = await client.decrypt(page, "sidebar", keys);

// Period key cache is keyed by "premium" (the keyName),
// so navigating to another "premium" article skips the unlock call`}</CodeBlock>

          <h3>Backwards Compatibility</h3>
          <p>
            Fully backwards compatible. When <code>keyName</code> is omitted it defaults
            to <code>contentName</code>, so existing pages and unlock requests work
            unchanged. The <code>contentKeyMap</code> is only included when explicitly needed.
          </p>
        </SectionCard>

        {/* ================================================================
            Client & Service Usage
            ================================================================ */}

        <h2>Client Usage</h2>
        <CodeBlock>{`import { DcaClient } from '@sesamy/capsule-client';

// v1 (default) — compatible with all services
const clientV1 = new DcaClient();

// v2 (beta) — requires v2-capable service
const clientV2 = new DcaClient({ requestFormat: "v2" });

// Usage is identical — only the wire format changes
const page = clientV2.parsePage();
const response = await clientV2.unlock(page, "sesamy");
const html = await clientV2.decrypt(page, "bodytext", response);`}</CodeBlock>

        <h2>Service-Side Setup</h2>
        <p>
          The service automatically handles both v1 and v2 requests with no configuration
          needed. The detection is based on whether the <code>resource</code> field is
          present:
        </p>
        <CodeBlock>{`// No code changes needed — auto-detection is built in
const issuer = createDcaIssuer({
  issuerName: "sesamy",
  privateKeyPem: process.env.ISSUER_ECDH_P256_PRIVATE_KEY!,
  keyId: "2025-10",
  trustedPublisherKeys: {
    "news.example.com": process.env.PUBLISHER_ES256_PUBLIC_KEY!,
  },
});

// Handles both v1 and v2 requests transparently
const result = await issuer.unlock(request, {
  grantedContentNames: ["bodytext"],
  deliveryMode: "contentKey",
});`}</CodeBlock>

        {/* ================================================================
            Summary & Security
            ================================================================ */}

        <h2>Summary</h2>
        <table style={{ width: "100%", borderCollapse: "collapse", marginTop: "0.75rem", marginBottom: "0.75rem" }}>
          <thead>
            <tr>
              <th style={th}>Component</th>
              <th style={th}>Change</th>
              <th style={th}>Breaking?</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td style={td}><strong>Publisher</strong></td>
              <td style={td}>No change (still generates issuerJWT for v1 clients)</td>
              <td style={td}>No</td>
            </tr>
            <tr>
              <td style={td}><strong>Service</strong></td>
              <td style={td}>Auto-detects v1/v2; v2 skips proof verification</td>
              <td style={td}>No — v1 requests still work unchanged</td>
            </tr>
            <tr>
              <td style={td}><strong>Client</strong></td>
              <td style={td}>New <code>requestFormat: &quot;v2&quot;</code> option; drops issuerJWT from request</td>
              <td style={td}>No — defaults to v1</td>
            </tr>
            <tr>
              <td style={td}><strong>Wire format</strong></td>
              <td style={td}>4 fields + 1 JWT removed from unlock request</td>
              <td style={td}>Yes — v2 requests fail against v1-only services</td>
            </tr>
          </tbody>
        </table>

        <h2>Security</h2>
        <p>
          v2 provides <strong>identical security</strong> to v1:
        </p>
        <ul>
          <li>
            <strong>Publisher authentication:</strong> The <code>resourceJWT</code> is ES256-signed
            by the publisher. The service verifies the signature against the trusted-publisher
            allowlist. This is unchanged from v1.
          </li>
          <li>
            <strong>Sealed blob integrity:</strong> AES-GCM is authenticated encryption — modifying
            any sealed blob causes the unseal to fail with a GCM authentication error. The
            SHA-256 proof hashes in the issuerJWT were a redundant second integrity check.
          </li>
          <li>
            <strong>Blob substitution:</strong> Content keys are random per render. Substituting
            sealed blobs from a different article gives you that article&apos;s keys, which cannot
            decrypt this article&apos;s content.
          </li>
          <li>
            <strong>Domain lookup from JWT:</strong> The service decodes the JWT payload (unverified)
            only for key selection, then fully verifies the signature. Standard JWT practice
            (same as OIDC providers).
          </li>
        </ul>

        {/* ================================================================
            Suggested Updates — under consideration
            ================================================================ */}

        <h2>Suggested Updates</h2>
        <p>
          The following changes are under consideration for future versions. They are not
          yet implemented but documented here for discussion.
        </p>

        <h3>A. JWE for Sealed Key Blobs</h3>
        <SectionCard color="slate">
          <p>
            The current seal format is a custom binary blob: ephemeral public key ‖ nonce ‖ ciphertext.
            This works but is non-standard. Replacing it with{' '}
            <strong>JWE Compact Serialization</strong> (<a href="https://datatracker.ietf.org/doc/html/rfc7516">RFC 7516</a>)
            would give us:
          </p>
          <ul>
            <li>A well-known, auditable format instead of a custom byte layout</li>
            <li>Standard algorithm identifiers (<code>alg: ECDH-ES</code>, <code>enc: A256GCM</code>)</li>
            <li>Built-in algorithm agility through the <code>alg</code>/<code>enc</code> headers</li>
            <li>Interoperability with any JWE library (jose, node-jose, etc.)</li>
          </ul>
          <CodeBlock>{`// Current custom format
"sealed": "Base64url(ephemeralPub ‖ nonce ‖ AES-GCM(sharedSecret, plainKey))"

// Proposed JWE Compact Serialization
"sealed": "eyJhbGciOiJFQ0RILUVTIiwiZW5jIjoiQTI1NkdDTSIsImVwayI6ey4uLn19.    .nonce.ciphertext.tag"
//               header          .CEK.  IV  . ciphertext .tag`}</CodeBlock>
          <p>
            The <code>epk</code> (ephemeral public key) moves into the JWE protected header,
            and AES-GCM nonce/ciphertext/tag are standard JWE fields. The same ECDH-ES +
            HKDF key derivation is used under the hood.
          </p>
        </SectionCard>

        <h3>B. Standard JWT Claims for Share Link Tokens</h3>
        <SectionCard color="slate">
          <p>
            Share link tokens currently use custom claim names (<code>domain</code>,{' '}
            <code>resourceId</code>, <code>type</code>) similar to v1 resource JWTs.
            The same RFC 7519 mapping applied to <code>resourceJWT</code> in Change 2 above
            should be applied to share tokens:
          </p>
          <table style={{ width: "100%", borderCollapse: "collapse", marginTop: "0.75rem", marginBottom: "0.75rem" }}>
            <thead>
              <tr>
                <th style={th}>Current claim</th>
                <th style={th}>Standard claim</th>
                <th style={th}>Notes</th>
              </tr>
            </thead>
            <tbody>
              <tr>
                <td style={td}><code>domain</code></td>
                <td style={td}><code>iss</code></td>
                <td style={td}>Publisher that signed the token</td>
              </tr>
              <tr>
                <td style={td}><code>resourceId</code></td>
                <td style={td}><code>sub</code></td>
                <td style={td}>Resource being shared</td>
              </tr>
              <tr>
                <td style={td}><code>type: &quot;dca-share&quot;</code></td>
                <td style={td}>JWT header <code>typ: &quot;dca-share+jwt&quot;</code></td>
                <td style={td}>Distinguishes from resource JWTs without a payload claim</td>
              </tr>
            </tbody>
          </table>
          <p>
            This aligns all publisher-signed JWTs (resource + share) under the same conventions
            and allows reusing the same verification code path.
          </p>
        </SectionCard>

        <h3>C. Structured Error Types</h3>
        <SectionCard color="slate">
          <p>
            Currently, callers distinguish error kinds by parsing <code>error.message</code> strings
            (e.g. <code>error.message.includes(&quot;not trusted&quot;)</code>). This is fragile —
            message text can change between versions.
          </p>
          <p>
            Instead, the library should expose typed error subclasses with a stable <code>code</code> property:
          </p>
          <CodeBlock>{`// Proposed error hierarchy
class DcaError extends Error {
  code: string;
}

class DcaUntrustedPublisherError extends DcaError {
  code = "UNTRUSTED_PUBLISHER";
  domain: string;
}

class DcaKeyMismatchError extends DcaError {
  code = "KEY_MISMATCH";
  expected: string;
  received: string;
}

class DcaUnsealError extends DcaError {
  code = "UNSEAL_FAILED";
  algorithm: string;
}

// Callers can now match on stable codes
try {
  await issuer.unlock(request, decision);
} catch (err) {
  if (err instanceof DcaUntrustedPublisherError) {
    // handle untrusted publisher
  }
  // or match on err.code === "UNTRUSTED_PUBLISHER"
}`}</CodeBlock>
        </SectionCard>

        <h3>D. Rename <code>DcaSealedContentKey.t</code> Field</h3>
        <SectionCard color="slate">
          <p>
            The <code>DcaSealedContentKey</code> type uses a single-character field name{' '}
            <code>t</code> for the time bucket identifier:
          </p>
          <CodeBlock>{`// Current wire format
"sealedContentKeys": {
  "bodytext": [
    { "t": "2025-06-d", "nonce": "...", "key": "..." },
    { "t": "2025-06-d-12", "nonce": "...", "key": "..." }
  ]
}`}</CodeBlock>
          <p>
            The abbreviated name saves a few bytes per entry but hurts readability and
            discoverability. Two options:
          </p>
          <ol>
            <li>
              <strong>Rename to <code>timeBucket</code></strong> — explicit and self-documenting.
              Costs ~10 extra bytes per entry (negligible in practice).
            </li>
            <li>
              <strong>Switch to array format</strong> — use <code>[timeBucket, nonce, key]</code> tuples
              instead of objects. Smaller wire size than either naming option and positional semantics
              are unambiguous given the fixed schema.
            </li>
          </ol>
        </SectionCard>
      </main>
    </PageWithToc>
  );
}
