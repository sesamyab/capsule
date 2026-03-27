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
            v0.7
            ================================================================ */}

        <h2>v0.7 <VersionBadge version="Latest" /></h2>
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
                <td style={td}><code>grantedKeyNames</code> (resolves via contentKeyMap)</td>
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
            (the backwards-compatible case), keeping zero overhead for publishers that don&apos;t use this feature.
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
          <CodeBlock>{`const client = new DcaClient({ requestFormat: "v2" });
const page = client.parsePage();

// contentKeyMap is included automatically in the unlock request
const keys = await client.unlock(page, "sesamy");

// Decrypt by contentName — keyName is resolved internally
const body = await client.decrypt(page, "bodytext", keys);
const side = await client.decrypt(page, "sidebar", keys);

// Period key cache is keyed by "premium" (the keyName),
// so navigating to another "premium" article skips the unlock call`}</CodeBlock>

          <h4>Backwards Compatibility</h4>
          <p>
            Fully backwards compatible. When <code>keyName</code> is omitted it defaults
            to <code>contentName</code>, so existing pages and unlock requests work
            unchanged. The <code>contentKeyMap</code> is only included when explicitly needed.
          </p>
        </SectionCard>

        {/* ---- Usage examples ---- */}

        <h3>Client Usage</h3>
        <CodeBlock>{`import { DcaClient } from '@sesamy/capsule-client';

// Old format (default) — compatible with all services
const clientV1 = new DcaClient();

// New format — requires v0.7+ service
const clientV2 = new DcaClient({ requestFormat: "v2" });

// Usage is identical — only the wire format changes
const page = clientV2.parsePage();
const response = await clientV2.unlock(page, "sesamy");
const html = await clientV2.decrypt(page, "bodytext", response);`}</CodeBlock>

        <h3>Service-Side Setup</h3>
        <p>
          The service automatically handles both old and new request formats with no configuration
          needed. Detection is based on whether the <code>resource</code> field is present:
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

// Handles both formats transparently
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
              <td style={td}>No change (still generates issuerJWT for old clients)</td>
              <td style={td}>No</td>
            </tr>
            <tr>
              <td style={td}><strong>Service</strong></td>
              <td style={td}>Auto-detects old/new format; new format skips proof verification</td>
              <td style={td}>No — old requests still work unchanged</td>
            </tr>
            <tr>
              <td style={td}><strong>Client</strong></td>
              <td style={td}>New <code>requestFormat: &quot;v2&quot;</code> option; drops issuerJWT, keyId, resource, issuerName; renames sealed → contentKeys</td>
              <td style={td}>No — defaults to old format</td>
            </tr>
            <tr>
              <td style={td}><strong>Wire format</strong></td>
              <td style={td}>5 fields + 1 JWT removed; <code>sealed</code> renamed to <code>contentKeys</code></td>
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
