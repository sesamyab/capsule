import { CodeBlock } from "@/components/CodeBlock";
import { PageWithToc } from "@/components/PageWithToc";

const th = { textAlign: "left" as const, padding: "0.5rem", borderBottom: "2px solid #333" };
const td = { padding: "0.5rem", borderBottom: "1px solid #ddd" };

function SectionCard({ color, children }: { color: "amber" | "indigo" | "emerald" | "slate" | "rose"; children: React.ReactNode }) {
  const palette = {
    amber:   { bg: "rgba(251, 191, 36, 0.08)", border: "rgba(251, 191, 36, 0.35)" },
    indigo:  { bg: "rgba(99, 102, 241, 0.08)", border: "rgba(99, 102, 241, 0.35)" },
    emerald: { bg: "rgba(16, 185, 129, 0.08)", border: "rgba(16, 185, 129, 0.35)" },
    slate:   { bg: "rgba(148, 163, 184, 0.08)", border: "rgba(148, 163, 184, 0.35)" },
    rose:    { bg: "rgba(244, 63, 94, 0.08)",  border: "rgba(244, 63, 94, 0.35)" },
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

function CompatBadge({ compatible, breaking }: { compatible?: boolean; breaking?: boolean }) {
  const bg = breaking
    ? "linear-gradient(135deg, #ef4444, #dc2626)"
    : compatible
      ? "linear-gradient(135deg, #10b981, #059669)"
      : "linear-gradient(135deg, #f59e0b, #d97706)";
  const label = breaking
    ? "Breaking"
    : compatible
      ? "Backwards compatible"
      : "Not backwards compatible";
  return (
    <span style={{
      display: "inline-block",
      background: bg,
      color: "#fff",
      padding: "0.1rem 0.55rem",
      borderRadius: "5px",
      fontSize: "0.75rem",
      fontWeight: 700,
      verticalAlign: "middle",
    }}>
      {label}
    </span>
  );
}

function VersionBadge({ version }: { version: string }) {
  return (
    <span style={{
      display: "inline-block",
      background: "linear-gradient(135deg, #6366f1, #4f46e5)",
      color: "#fff",
      padding: "0.15rem 0.6rem",
      borderRadius: "6px",
      fontSize: "0.85em",
      fontWeight: 700,
      verticalAlign: "middle",
      marginLeft: "0.5rem",
    }}>
      {version}
    </span>
  );
}

export default function ChangelogPage() {
  return (
    <PageWithToc>
      <main className="content-page">
        <h1>Changelog</h1>
        <p>
          Protocol and library changes by version. Each entry describes what changed,
          why, and whether it&apos;s backwards compatible.
        </p>

        {/* ================================================================
            v0.10
            ================================================================ */}

        <h2>v0.10 <VersionBadge version="Latest" /></h2>
        <p>
          v0.10 is a pre-release terminology and structure migration. Crypto vocabulary is
          aligned with WebCrypto, time-based naming is removed, access control is aligned
          with OAuth scopes, and the three top-level key/ciphertext maps are merged into a
          single <code>content</code> map. The wire format version is <code>&quot;0.10&quot;</code>.
        </p>

        {/* ---- Terminology & structure migration ---- */}

        <h3>Terminology &amp; Structure Migration</h3>
        <SectionCard color="rose">
          <CompatBadge breaking />

          <h4>What Changed</h4>
          <p>
            The protocol is renamed and restructured end-to-end. The wire format version
            is reset to <code>&quot;1&quot;</code> for the pre-release.
          </p>
          <ul>
            <li><strong>Crypto vocabulary</strong> — aligned with WebCrypto: <code>seal</code>/<code>sealed</code>/<code>sealing</code> → <code>wrap</code>/<code>wrapped</code>/<code>wrapping</code>, and <code>nonce</code> → <code>iv</code> on content items.</li>
            <li><strong>Time-based naming removed</strong> — <code>periodKey</code> → <code>wrapKey</code>, <code>periodSecret</code> → <code>rotationSecret</code>, <code>bucket</code>/<code>t</code> → <code>kid</code>.</li>
            <li><strong>OAuth-aligned access control</strong> — <code>keyName</code>/<code>keyNames</code> → <code>scope</code>/<code>scopes</code>.</li>
            <li><strong>Manifest rename</strong> — <code>DcaData</code> → <code>DcaManifest</code>, and the embedded <code>&lt;template class=&quot;dca-data&quot;&gt;</code> → <code>&lt;template class=&quot;dca-manifest&quot;&gt;</code>.</li>
            <li><strong>Top-level map merge</strong> — <code>contentSealData</code>, <code>sealedContentKeys</code>, and <code>sealedContent</code> are merged into a single <code>content</code> map keyed by <code>contentName</code>. The separate <code>&lt;template class=&quot;dca-sealed-content&quot;&gt;</code> is eliminated — the manifest now carries ciphertext inline.</li>
            <li><strong>Field renames</strong> — <code>issuerData</code> → <code>issuers</code>, <code>contentEncryptionKeys</code> → <code>keys</code>.</li>
            <li><strong>Delivery modes</strong> — <code>deliveryMode: &quot;contentKey&quot;</code> → <code>deliveryMode: &quot;direct&quot;</code>, and <code>deliveryMode: &quot;periodKey&quot;</code> → <code>deliveryMode: &quot;wrapKey&quot;</code>.</li>
            <li><strong>Version bump</strong> — <code>version: &quot;2&quot;</code> → <code>version: &quot;1&quot;</code> (reset for pre-release).</li>
          </ul>

          <h4>Why</h4>
          <p>
            The previous vocabulary mixed metaphors (&quot;seal&quot; vs WebCrypto&apos;s <code>wrapKey</code>),
            encoded a rotation strategy into field names (&quot;period&quot;, &quot;bucket&quot;), and used
            a project-specific access term (&quot;keyName&quot;) instead of the OAuth <code>scope</code>
            that most consumers already understand. Splitting content across three parallel
            top-level maps (seal data, sealed keys, sealed content) also made the manifest
            harder to reason about than a single content-keyed map.
          </p>

          <h4>Current Wire Format</h4>
          <CodeBlock>{`// DcaManifest — embedded as <script class="dca-manifest"> JSON
{
  "version": "0.10",
  "resourceJWT": "eyJ…",
  "issuers": {
    "sesamy": {
      "keys": [
        {
          "contentName": "bodytext",
          "scope": "premium",
          "contentKey": "wrapped…",        // wrapped content key (direct delivery)
          "wrapKeys": [                    // wrapped rotation keys (cacheable)
            { "kid": "260409T11", "key": "wrapped…" },
            { "kid": "260409T12", "key": "wrapped…" }
          ]
        }
      ]
    }
  },
  "content": {
    "bodytext": {
      "contentType": "text/html",
      "iv": "base64url…",
      "ciphertext": "base64url…",
      "kid": "260409T11"                   // wrap key id used for this ciphertext
    }
  }
}

// resourceJWT payload (decoded)
{
  "iss": "news.example.com",
  "sub": "article-123",
  "iat": 1735689600,
  "jti": "abc123def456",
  "scopes": ["premium"],                   // renamed from keyNames
  "data": { "section": "politics" }
}

// Unlock request
POST /api/unlock
{
  "resourceJWT": "eyJ…",
  "keys": [
    { "contentName": "bodytext", "scope": "premium", "contentKey": "wrapped…", "wrapKeys": [ … ] }
  ],
  "clientPublicKey": "…"                   // optional
}

// Issuer grant
const result = await issuer.unlock(request, {
  grantedScopes: ["premium"],              // renamed from grantedKeyNames
  deliveryMode: "wrapKey",                 // or "direct" (was "periodKey" / "contentKey")
});`}</CodeBlock>

          <h4>Migration</h4>
          <table style={{ width: "100%", borderCollapse: "collapse", marginTop: "0.75rem", marginBottom: "0.5rem" }}>
            <thead>
              <tr>
                <th style={th}>Component</th>
                <th style={th}>Change</th>
              </tr>
            </thead>
            <tbody>
              <tr>
                <td style={td}><strong>Publisher</strong></td>
                <td style={td}>Update to <code>@sesamy/capsule</code> v0.10 — <code>render()</code> emits the new manifest shape with inline ciphertext</td>
              </tr>
              <tr>
                <td style={td}><strong>Client</strong></td>
                <td style={td}>Update to <code>@sesamy/capsule-client</code> v0.10 — reads <code>content</code> and <code>issuers[name].keys</code>, uses <code>iv</code>/<code>kid</code></td>
              </tr>
              <tr>
                <td style={td}><strong>Service</strong></td>
                <td style={td}>Update to <code>@sesamy/capsule-server</code> v0.10 — <code>issuer.unlock()</code> accepts <code>keys</code> and <code>grantedScopes</code>, emits <code>direct</code>/<code>wrapKey</code> delivery</td>
              </tr>
              <tr>
                <td style={td}><strong>Wire format</strong></td>
                <td style={td}><code>version: &quot;1&quot;</code> (reset). Pre-release — no backwards compatibility shims for the old <code>&quot;2&quot;</code> shape</td>
              </tr>
            </tbody>
          </table>
        </SectionCard>

        {/* ================================================================
            v0.9
            ================================================================ */}

        <h2>v0.9</h2>
        <p>
          v0.9 introduces two changes: entitlement claims in the resourceJWT and a flattened
          wire format for content encryption keys.
        </p>

        {/* ---- Change 1: keyNames in resourceJWT ---- */}

        <h3>Entitlement Claims in resourceJWT</h3>
        <SectionCard color="emerald">
          <CompatBadge compatible={true} />

          <h4>What Changed</h4>
          <p>
            The <code>resourceJWT</code> payload now includes a <code>keyNames</code> claim — an array
            of required entitlement key domains (tiers/roles) declared by the publisher at render time.
          </p>

          <h4>Why</h4>
          <p>
            Previously the issuer had to independently look up which tier a resource required
            (e.g. querying a database by <code>resourceId</code>). With <code>keyNames</code> in
            the signed JWT, the issuer has a <strong>trusted source of truth</strong> for what
            entitlements are needed — it can compare directly against the user&apos;s subscription
            without a separate server-side lookup.
          </p>
          <p>
            The client can also read <code>keyNames</code> before calling unlock to show
            the right paywall (e.g. &quot;Subscribe to Premium to read this&quot;) without a round-trip.
          </p>

          <CodeBlock>{`// resourceJWT payload (decoded)
{
  "iss": "news.example.com",
  "sub": "article-123",
  "iat": 1735689600,
  "jti": "abc123def456",
  "keyNames": ["premium"],           // ← NEW: required entitlements
  "data": { "section": "politics" }
}

// Issuer access decision is now a simple set intersection:
// user entitlements ∩ resource keyNames → grant
const { resource } = await issuer.verify(request);
const userTiers = await getUserSubscriptions(userId);
const grantedKeyNames = resource.keyNames.filter(k => userTiers.includes(k));`}</CodeBlock>

          <h4>Backwards Compatibility</h4>
          <p>
            Fully backwards compatible. The field is populated automatically by the publisher.
            Issuers that don&apos;t use it can ignore it. The <code>keyNames</code> field defaults
            to an empty array when parsing older JWTs that lack it.
          </p>
        </SectionCard>

        {/* ---- Change 2: Flat contentEncryptionKeys ---- */}

        <h3>Flat contentEncryptionKeys Array</h3>
        <SectionCard color="rose">
          <CompatBadge breaking />

          <h4>What Changed</h4>
          <p>
            The deeply nested <code>Record&lt;string, DcaContentKeys&gt;</code> wire format for
            content encryption keys is replaced with a flat <code>DcaContentEncryptionKey[]</code> array.
            This affects three surfaces:
          </p>
          <ul>
            <li><code>issuerData[name].contentKeys</code> → <code>issuerData[name].contentEncryptionKeys</code> (typed as <code>DcaSealedContentEncryptionKey[]</code>)</li>
            <li><code>DcaUnlockRequest.contentKeys</code> → <code>DcaUnlockRequest.contentEncryptionKeys</code> (typed as <code>DcaSealedContentEncryptionKey[]</code>)</li>
            <li><code>DcaUnlockResponse.keys</code> → <code>DcaUnlockResponse.contentEncryptionKeys</code> (typed as <code>DcaContentEncryptionKey[]</code> — union of delivery variants)</li>
          </ul>

          <h4>Why</h4>
          <p>
            The nested <code>Record&lt;string, Record&lt;string, string&gt;&gt;</code> shape had
            poor TypeScript ergonomics — no autocomplete on dynamic keys, hard to type, and
            <code>any</code>-adjacent in practice. The flat array gives every field a name and
            makes the simplest case (single unnamed content item) trivially simple.
          </p>

          <CodeBlock>{`// Before (v0.8) — nested Records
{
  "contentKeys": {
    "bodytext": {
      "contentKey": "base64url…",
      "periodKeys": { "260409T11": "base64url…", "260409T12": "base64url…" }
    }
  }
}

// After (v0.9) — flat array
{
  "contentEncryptionKeys": [
    {
      "contentName": "bodytext",
      "contentKey": "base64url…",
      "periodKeys": [
        { "bucket": "260409T11", "key": "base64url…" },
        { "bucket": "260409T12", "key": "base64url…" }
      ]
    }
  ]
}

// Simplest case — single unnamed content item:
{
  "contentEncryptionKeys": [
    { "contentKey": "base64url…", "periodKeys": [{ "bucket": "260409T11", "key": "base64url…" }] }
  ]
}`}</CodeBlock>

          <h4>New Types</h4>
          <CodeBlock>{`// Wire format (issuerData + unlock request): both fields required
interface DcaSealedContentEncryptionKey {
  contentName?: string;           // defaults to "default" when omitted
  contentKey: string;             // sealed contentKey (always present)
  periodKeys: DcaPeriodKeyEntry[];  // sealed periodKeys (always present, default 1-hour buckets)
}

// Unlock response: exactly one delivery form per entry
type DcaContentEncryptionKey = DcaContentKeyDelivery | DcaPeriodKeyDelivery;

interface DcaContentKeyDelivery {
  contentName?: string;
  contentKey: string;             // direct key delivery
}

interface DcaPeriodKeyDelivery {
  contentName?: string;
  periodKeys: DcaPeriodKeyEntry[];  // cacheable period key delivery
}

interface DcaPeriodKeyEntry {
  bucket: string;          // e.g. "260409T11"
  key: string;             // base64url-encoded key
}`}</CodeBlock>

          <h4>Removed Types</h4>
          <ul>
            <li><code>DcaContentKeys</code> — replaced by <code>DcaSealedContentEncryptionKey</code></li>
            <li><code>DcaUnlockedKeys</code> — folded into <code>DcaContentEncryptionKey</code></li>
          </ul>

          <h4>Migration</h4>
          <table style={{ width: "100%", borderCollapse: "collapse", marginTop: "0.75rem", marginBottom: "0.5rem" }}>
            <thead>
              <tr>
                <th style={th}>Component</th>
                <th style={th}>Change</th>
              </tr>
            </thead>
            <tbody>
              <tr>
                <td style={td}><strong>Publisher</strong></td>
                <td style={td}>Automatic — <code>render()</code> now produces the new format</td>
              </tr>
              <tr>
                <td style={td}><strong>Client</strong></td>
                <td style={td}>Update to <code>@sesamy/capsule</code> v0.9 — reads <code>contentEncryptionKeys</code> from both page data and unlock response</td>
              </tr>
              <tr>
                <td style={td}><strong>Service</strong></td>
                <td style={td}>Update to <code>@sesamy/capsule-server</code> v0.9 — <code>issuer.unlock()</code> accepts and returns the new format</td>
              </tr>
            </tbody>
          </table>
        </SectionCard>

        {/* ================================================================
            v0.8
            ================================================================ */}

        <h2>v0.8</h2>
        <p>
          v0.8 introduces a security fix for sealed key binding and removes the legacy v1 request format.
        </p>

        {/* ---- Change 1: Seal AAD Binding ---- */}

        <h3>Seal AAD Binding</h3>
        <SectionCard color="rose">
          <CompatBadge compatible={false} />

          <h4>What Changed</h4>
          <p>
            Sealed key blobs (<code>contentKeys</code> and <code>periodKeys</code>) are now
            cryptographically bound to the access tier via <code>keyName</code> as AES-GCM AAD /
            RSA-OAEP label.
          </p>

          <h4>Why</h4>
          <p>
            Prevents a <strong>cross-tier key substitution attack</strong> where an attacker
            could change <code>keyName</code> on a sealed entry to a tier they have access to,
            tricking the issuer into unsealing keys for a different tier.
          </p>

          <h4>How It Works</h4>
          <ol>
            <li>
              The <strong>publisher</strong> passes <code>keyName</code> as AAD when sealing keys
              for issuers. Each entry carries its own <code>keyName</code>.
            </li>
            <li>
              The <strong>issuer</strong> reads <code>keyName</code> from each entry when unsealing.
            </li>
            <li>
              Mismatched AAD causes decryption to <strong>fail</strong> — a blob sealed for tier
              &quot;free&quot; cannot be unsealed with AAD &quot;premium&quot;.
            </li>
          </ol>

          <CodeBlock>{`// Publisher side — keyName bound as AAD during seal
const result = await publisher.render({
  resourceId: "article-123",
  contentItems: [
    { contentName: "bodytext", keyName: "premium", content: body, contentType: "text/html" },
  ],
  issuers: [{ issuerName: "sesamy", publicKeyPem, keyId, unlockUrl, keyNames: ["premium"] }],
});
// keyName is automatically included as AES-GCM AAD in the sealed blobs

// Issuer side — keyName from each entry used as AAD during unseal
const result = await issuer.unlock(request, {
  grantedKeyNames: ["premium"],
  deliveryMode: "contentKey",
});
// If keyName was tampered with, unseal fails`}</CodeBlock>
        </SectionCard>

        {/* ---- Change 2: v1 Legacy Removed ---- */}

        <h3>v1 Legacy Removed</h3>
        <SectionCard color="amber">
          <CompatBadge breaking />

          <h4>What Changed</h4>
          <p>
            Removed the v1 request format. The following fields are no longer accepted:
          </p>
          <ul>
            <li><code>resource</code> (unsigned copy)</li>
            <li><code>issuerJWT</code></li>
            <li><code>sealed</code></li>
            <li><code>keyId</code></li>
            <li><code>issuerName</code></li>
          </ul>
          <p>
            <code>DcaData</code> version is now <code>&quot;2&quot;</code> (was <code>&quot;1&quot;</code>).
          </p>

          <h4>Why</h4>
          <p>
            v2 is simpler (2 fields instead of 6 + 2 JWTs) and seal AAD provides stronger
            cryptographic binding than <code>issuerJWT</code> integrity proofs.
          </p>

          <h4>Removed Types &amp; Functions</h4>
          <ul>
            <li>Types: <code>DcaIssuerJwtPayload</code>, <code>DcaIssuerProof</code></li>
            <li>Functions: <code>createIssuerJwt</code>, <code>buildIssuerProof</code>, <code>verifyIssuerProof</code></li>
          </ul>

          <h4>Migration</h4>
          <p>
            Use the v2 unlock request format:
          </p>
          <CodeBlock>{`// v2 request format (the only format now)
POST /api/unlock
{
  "resourceJWT": "eyJ…",
  "contentKeys": { "bodytext": { "contentKey": "…", "periodKeys": { … } } },
  "clientPublicKey": "…"   // optional
}`}</CodeBlock>
        </SectionCard>

        {/* ================================================================
            v0.7
            ================================================================ */}

        <h2>v0.7</h2>
        <p>
          v0.7 introduces three changes to the unlock protocol.
        </p>

        {/* ---- Change 1 ---- */}

        <h3>Simplified Unlock Request</h3>
        <SectionCard color="amber">
          <CompatBadge compatible={false} />

          <h4>Motivation</h4>
          <p>
            The previous unlock request sends six fields and two JWTs. After analysis, five fields
            and one entire JWT turn out to be redundant:
          </p>
          <ul>
            <li><code>resource</code> — unsigned copy of what&apos;s already in <code>resourceJWT</code></li>
            <li><code>issuerName</code> — the subscription service already knows its own name</li>
            <li><code>keyId</code> — the service knows its own key; a wrong key fails at AES-GCM unseal anyway</li>
            <li><code>issuerJWT</code> — contains SHA-256 integrity proofs of the encrypted blobs,
              but AES-GCM is already <strong>authenticated encryption</strong> — any tampered
              blob fails at unseal time. The proofs are redundant.</li>
          </ul>
          <p>
            The <code>sealed</code> field is also renamed to <code>contentKeys</code> to better
            describe what it contains (encrypted content keys, not a generic &ldquo;sealed&rdquo; blob).
          </p>

          <h4>What Changed</h4>
          <p>
            The request is stripped down to the cryptographic essentials:
          </p>
          <ul>
            <li><code>resourceJWT</code> — publisher-signed resource metadata (authentication)</li>
            <li><code>contentKeys</code> — the encrypted content keys (AES-GCM provides integrity)</li>
          </ul>

          <p><strong>Why the issuerJWT is unnecessary:</strong></p>
          <ol>
            <li>
              <strong>Integrity proofs:</strong> SHA-256 hashes of encrypted blobs, to detect tampering.
              But encrypted blobs use <strong>AES-GCM</strong> (authenticated encryption) — any modification
              causes the unseal to fail with a GCM authentication error. The hashes add nothing.
            </li>
            <li>
              <strong>Metadata:</strong> <code>issuerName</code>, <code>keyId</code>, and <code>renderId</code>.
              The service knows its own name. The <code>keyId</code> is redundant (wrong key fails at unseal).
              The <code>renderId</code> is in the <code>resourceJWT</code>.
            </li>
          </ol>
          <p>
            Removing the issuerJWT eliminates one JWT signature verification per unlock request
            and the SHA-256 proof computation on both publisher and service sides.
          </p>

          <CodeBlock>{`// Before — 6 fields + 2 JWTs
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

// After — 1 field + 1 JWT
POST /api/unlock
{
  "resourceJWT": "eyJ…",
  "contentKeys": { "bodytext": { "contentKey": "…", "periodKeys": { … } } },
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
              <strong>Unseal:</strong> The service unseals the requested content keys using its
              configured private key. AES-GCM authentication ensures any tampered blob is
              rejected — no proof hashes or keyId checks needed.
            </li>
          </ol>

          <h4>Backwards Compatibility</h4>
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
                <td style={td}>Old client → old service</td>
                <td style={td}>Yes</td>
                <td style={td}>No change</td>
              </tr>
              <tr>
                <td style={td}>Old client → v0.7 service</td>
                <td style={td}>Yes</td>
                <td style={td}>Service auto-detects old format, processes normally</td>
              </tr>
              <tr>
                <td style={td}>v0.7 client → v0.7 service</td>
                <td style={td}>Yes</td>
                <td style={td}>Minimal request, full security</td>
              </tr>
              <tr>
                <td style={td}>v0.7 client → old service</td>
                <td style={td}>No</td>
                <td style={td}>Old service requires <code>issuerJWT</code>, <code>resource</code>, <code>issuerName</code>, <code>sealed</code></td>
              </tr>
            </tbody>
          </table>
          <p>
            <strong>Recommended migration:</strong> Upgrade the service first (accepts both formats),
            then switch clients at your own pace.
          </p>
        </SectionCard>

        {/* ---- Change 2 ---- */}

        <h3>Standard JWT Claims in resourceJWT</h3>
        <SectionCard color="emerald">
          <CompatBadge compatible={true} />

          <h4>Motivation</h4>
          <p>
            The previous <code>resourceJWT</code> uses custom field names (<code>domain</code>,{' '}
            <code>resourceId</code>, <code>issuedAt</code>, <code>renderId</code>) instead
            of the well-known JWT claim names defined in RFC 7519. Using standard claims
            improves interoperability and makes the JWT self-describing.
          </p>

          <h4>What Changed</h4>
          <p>
            The <code>resourceJWT</code> payload now uses standard JWT claim names:
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

          <h4>Backwards Compatibility</h4>
          <p>
            Fully backwards compatible. The service detects the claim format automatically
            (checking for <code>iss</code> vs <code>domain</code>). Both old and new resource
            JWTs are accepted. No publisher or client changes are required.
          </p>
        </SectionCard>

        {/* ---- Change 3 ---- */}

        <h3>keyName: Decoupling Content Identity from Key Domain</h3>
        <SectionCard color="indigo">
          <CompatBadge compatible={true} />

          <h4>Motivation</h4>
          <p>
            Previously, <code>contentName</code> serves three roles simultaneously:
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
            need different contentNames but the same access scope — impossible before this change.
          </p>

          <h4>What Changed</h4>
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
                <th style={th}>Before</th>
                <th style={th}>After (with keyName)</th>
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
                <td style={td}><code>grantedKeyNames</code> (resolves via entry keyName)</td>
              </tr>
            </tbody>
          </table>

          <p><strong>Publisher — before &amp; after:</strong></p>
          <CodeBlock>{`// Before: contentName = "TierA" (conflates identity with access scope)
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

// After: contentName describes WHAT, keyName describes WHO can access
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

          <p><strong>Wire format — keyName on entries:</strong></p>
          <p>
            Each <code>contentEncryptionKeys</code> entry carries its own <code>keyName</code>,
            making it self-describing. The <code>keyName</code> is cryptographically bound
            via seal AAD — tampering causes unseal failure:
          </p>
          <CodeBlock>{`// issuerData entry (embedded in page)
{
  "contentEncryptionKeys": [
    { "contentName": "bodytext", "keyName": "premium", "contentKey": "sealed...", "periodKeys": [...] },
    { "contentName": "sidebar",  "keyName": "premium", "contentKey": "sealed...", "periodKeys": [...] }
  ]
}`}</CodeBlock>
          <p>
            When <code>keyName</code> is not explicitly set on a content item, it defaults
            to <code>contentName</code>, so the simplest case requires no extra configuration.
          </p>

          <p><strong>Issuer — grantedKeyNames:</strong></p>
          <p>
            The issuer&apos;s access decision can now use <code>grantedKeyNames</code> instead of
            (or alongside) <code>grantedContentNames</code>:
          </p>
          <CodeBlock>{`// Before: grant by content name
const result = await issuer.unlock(request, {
  grantedContentNames: ["bodytext", "sidebar"],
  deliveryMode: "periodKey",
});

// After: grant by key name — resolves to all matching content items
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
          <CodeBlock>{`const client = new DcaClient();
const page = client.parsePage();

// keyName is carried on each entry — no separate mapping needed
const keys = await client.unlock(page, "sesamy");

// Decrypt by contentName — keyName is resolved from the entries
const body = await client.decrypt(page, "bodytext", keys);
const side = await client.decrypt(page, "sidebar", keys);

// Period key cache is keyed by "premium" (the keyName),
// so navigating to another "premium" article skips the unlock call`}</CodeBlock>

          <h4>Breaking Change</h4>
          <p>
            This is a breaking change — the seal AAD now includes <code>keyName</code>,
            so existing encrypted content must be re-rendered. When <code>keyName</code> is
            omitted on a content item, it defaults to <code>contentName</code>.
            The <code>contentKeyMap</code> field has been removed from the wire format.
            The <code>resourceJWT</code> is now optional in unlock requests.
          </p>
        </SectionCard>

        {/* ---- Usage examples ---- */}

        <h3>Client Usage</h3>
        <CodeBlock>{`import { DcaClient } from '@sesamy/capsule-client';

const client = new DcaClient();

const page = client.parsePage();
const response = await client.unlock(page, "sesamy");
const html = await client.decrypt(page, "bodytext", response);`}</CodeBlock>

        <h3>Service-Side Setup</h3>
        <p>
          The service accepts unlock requests with <code>resourceJWT</code> and <code>contentKeys</code>:
        </p>
        <CodeBlock>{`const issuer = createDcaIssuer({
  issuerName: "sesamy",
  privateKeyPem: process.env.ISSUER_ECDH_P256_PRIVATE_KEY!,
  keyId: "2025-10",
  trustedPublisherKeys: {
    "news.example.com": process.env.PUBLISHER_ES256_PUBLIC_KEY!,
  },
});

const result = await issuer.unlock(request, {
  grantedContentNames: ["bodytext"],
  deliveryMode: "contentKey",
});`}</CodeBlock>

        {/* ---- Summary & Security ---- */}

        <h3>Summary</h3>
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
              <td style={td}>No change</td>
              <td style={td}>No</td>
            </tr>
            <tr>
              <td style={td}><strong>Service</strong></td>
              <td style={td}>Accepts resourceJWT + contentKeys</td>
              <td style={td}>No</td>
            </tr>
            <tr>
              <td style={td}><strong>Client</strong></td>
              <td style={td}>Sends resourceJWT + contentKeys (legacy fields removed)</td>
              <td style={td}>Yes — legacy v1 format removed</td>
            </tr>
            <tr>
              <td style={td}><strong>Wire format</strong></td>
              <td style={td}>Only resourceJWT + contentKeys; legacy fields (issuerJWT, keyId, resource, issuerName, sealed) removed</td>
              <td style={td}>Yes — new format fails against pre-v0.7 services</td>
            </tr>
          </tbody>
        </table>

        <h3>Security</h3>
        <p>
          The simplified format provides <strong>identical security</strong>:
        </p>
        <ul>
          <li>
            <strong>Publisher authentication:</strong> The <code>resourceJWT</code> is ES256-signed
            by the publisher. The service verifies the signature against the trusted-publisher
            allowlist. Unchanged.
          </li>
          <li>
            <strong>Content key integrity:</strong> AES-GCM is authenticated encryption — modifying
            any encrypted blob causes the unseal to fail with a GCM authentication error. The
            SHA-256 proof hashes in the issuerJWT were a redundant second integrity check.
          </li>
          <li>
            <strong>Blob substitution:</strong> Content keys are random per render. Substituting
            encrypted blobs from a different article gives you that article&apos;s keys, which cannot
            decrypt this article&apos;s content.
          </li>
          <li>
            <strong>Domain lookup from JWT:</strong> The service decodes the JWT payload (unverified)
            only for key selection, then fully verifies the signature. Standard JWT practice
            (same as OIDC providers).
          </li>
        </ul>

        <h3>Breaking Changes</h3>
        <p>
          The following wire format changes are <strong>not backwards compatible</strong> with
          pre-v0.7 services. Upgrade the service first, then switch clients.
        </p>
        <SectionCard color="amber">
          <table style={{ width: "100%", borderCollapse: "collapse" }}>
            <thead>
              <tr>
                <th style={th}>Old field</th>
                <th style={th}>v0.7 status</th>
                <th style={th}>Reason</th>
              </tr>
            </thead>
            <tbody>
              <tr>
                <td style={td}><code>resource</code></td>
                <td style={td}>Removed</td>
                <td style={td}>Decoded from <code>resourceJWT</code> (the signed source of truth)</td>
              </tr>
              <tr>
                <td style={td}><code>issuerName</code></td>
                <td style={td}>Removed</td>
                <td style={td}>The service already knows its own name</td>
              </tr>
              <tr>
                <td style={td}><code>issuerJWT</code></td>
                <td style={td}>Removed</td>
                <td style={td}>SHA-256 integrity proofs are redundant — AES-GCM authenticated encryption catches any tampered blob at unseal time</td>
              </tr>
              <tr>
                <td style={td}><code>keyId</code></td>
                <td style={td}>Removed</td>
                <td style={td}>The service uses its configured key; a wrong key fails at AES-GCM unseal</td>
              </tr>
              <tr>
                <td style={td}><code>sealed</code></td>
                <td style={td}>Renamed to <code>contentKeys</code></td>
                <td style={td}>Describes <em>what</em> the data is (encrypted content keys) rather than <em>what was done to it</em></td>
              </tr>
            </tbody>
          </table>
          <p style={{ marginTop: "1rem", marginBottom: 0 }}>
            <strong>v0.7 services accept both formats:</strong> when <code>resource</code> is present the
            request is treated as the old format (full validation including issuerJWT). When absent, it is
            treated as the new format. The deprecated <code>sealed</code> field name is also accepted as a
            fallback for <code>contentKeys</code>.
          </p>
        </SectionCard>
      </main>
    </PageWithToc>
  );
}
