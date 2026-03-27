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

function StatusBadge({ status }: { status: "considering" | "planned" | "in-progress" }) {
  const styles = {
    considering: { bg: "linear-gradient(135deg, #94a3b8, #64748b)", label: "Under consideration" },
    planned:     { bg: "linear-gradient(135deg, #6366f1, #4f46e5)", label: "Planned" },
    "in-progress": { bg: "linear-gradient(135deg, #10b981, #059669)", label: "In progress" },
  }[status];
  return (
    <span style={{
      display: "inline-block",
      background: styles.bg,
      color: "#fff",
      padding: "0.1rem 0.55rem",
      borderRadius: "5px",
      fontSize: "0.75rem",
      fontWeight: 700,
      verticalAlign: "middle",
    }}>
      {styles.label}
    </span>
  );
}

export default function RoadmapPage() {
  return (
    <PageWithToc>
      <main className="content-page">
        <h1>Roadmap</h1>
        <p>
          Future protocol and library improvements under consideration.
          These are not yet implemented — feedback is welcome.
        </p>

        {/* ---- JWE ---- */}

        <h2>JWE for Sealed Key Blobs</h2>
        <SectionCard color="slate">
          <StatusBadge status="considering" />
          <p style={{ marginTop: "1rem" }}>
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

        {/* ---- Share link JWT claims ---- */}

        <h2>Standard JWT Claims for Share Link Tokens</h2>
        <SectionCard color="slate">
          <StatusBadge status="considering" />
          <p style={{ marginTop: "1rem" }}>
            Share link tokens currently use custom claim names (<code>domain</code>,{' '}
            <code>resourceId</code>, <code>type</code>) similar to the old resource JWTs.
            The same RFC 7519 mapping applied to <code>resourceJWT</code> in v0.7
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

        {/* ---- Structured errors ---- */}

        <h2>Structured Error Types</h2>
        <SectionCard color="slate">
          <StatusBadge status="considering" />
          <p style={{ marginTop: "1rem" }}>
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

        {/* ---- Rename t field ---- */}

        <h2>Rename <code>DcaSealedContentKey.t</code> Field</h2>
        <SectionCard color="slate">
          <StatusBadge status="considering" />
          <p style={{ marginTop: "1rem" }}>
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
