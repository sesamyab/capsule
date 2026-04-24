#!/usr/bin/env node

import {
    generateEcdsaP256KeyPair,
    generateEcdhP256KeyPair,
    exportP256KeyPairPem,
    generateAesKeyBytes,
    toBase64,
} from "./index";

type Format = "text" | "json";

interface ParsedArgs {
    subcommand: string | null;
    format: Format;
    help: boolean;
}

const USAGE = `Usage: capsule-server <command> [--json]

Commands:
  generate-publisher-keys   ECDSA P-256 keypair for publisher JWT signing (PEM)
  generate-issuer-keys      ECDH P-256 keypair for issuer key wrapping (PEM + JWK)
  generate-period-secret    32 random bytes base64-encoded (rotation secret)
  generate-all              Publisher keys + period secret, formatted for .env

Flags:
  --json    Emit machine-readable JSON instead of human-readable text
  --help    Show this help

Examples:
  npx @sesamy/capsule-server generate-all >> .env.local
  npx @sesamy/capsule-server generate-issuer-keys --json | jq -r .privateKeyPem > issuer.pem
`;

function parseArgs(argv: string[]): ParsedArgs {
    let subcommand: string | null = null;
    let format: Format = "text";
    let help = false;
    for (const arg of argv) {
        if (arg === "--json") format = "json";
        else if (arg === "--help" || arg === "-h") help = true;
        else if (!subcommand) subcommand = arg;
    }
    return { subcommand, format, help };
}

function isTTY(): boolean {
    return Boolean(process.stdout.isTTY);
}

function writeComment(text: string): void {
    if (isTTY()) process.stdout.write(`# ${text}\n`);
}

async function cmdPublisherKeys(format: Format): Promise<void> {
    const pair = await generateEcdsaP256KeyPair();
    const { privateKeyPem, publicKeyPem } = await exportP256KeyPairPem(
        pair.privateKey,
        pair.publicKey,
    );
    if (format === "json") {
        process.stdout.write(JSON.stringify({ privateKeyPem, publicKeyPem }) + "\n");
        return;
    }
    writeComment("Publisher ECDSA P-256 private key (keep secret)");
    process.stdout.write(privateKeyPem + "\n");
    writeComment("Publisher ECDSA P-256 public key (share with issuers)");
    process.stdout.write(publicKeyPem + "\n");
}

async function cmdIssuerKeys(format: Format): Promise<void> {
    const pair = await generateEcdhP256KeyPair();
    const { privateKeyPem } = await exportP256KeyPairPem(pair.privateKey, pair.publicKey);
    const rawJwk = (await globalThis.crypto.subtle.exportKey("jwk", pair.publicKey)) as Record<
        string,
        unknown
    >;
    const publicKeyJwk = {
        kty: rawJwk.kty,
        crv: rawJwk.crv,
        x: rawJwk.x,
        y: rawJwk.y,
        kid: `enc-${Date.now()}`,
        use: "enc",
        alg: "ECDH-ES",
    };

    if (format === "json") {
        process.stdout.write(JSON.stringify({ privateKeyPem, publicKeyJwk }) + "\n");
        return;
    }
    writeComment("Issuer ECDH P-256 private key (keep secret)");
    process.stdout.write(privateKeyPem + "\n");
    writeComment("Issuer ECDH P-256 public key JWK (serve from .well-known/dca-issuers.json)");
    process.stdout.write(JSON.stringify(publicKeyJwk, null, 2) + "\n");
}

async function cmdPeriodSecret(format: Format): Promise<void> {
    const secret = toBase64(generateAesKeyBytes());
    if (format === "json") {
        process.stdout.write(JSON.stringify({ periodSecret: secret }) + "\n");
        return;
    }
    writeComment("Period/rotation secret (32 random bytes, base64 — publisher-only, keep secret)");
    process.stdout.write(secret + "\n");
}

async function cmdAll(format: Format): Promise<void> {
    const pair = await generateEcdsaP256KeyPair();
    const { privateKeyPem, publicKeyPem } = await exportP256KeyPairPem(
        pair.privateKey,
        pair.publicKey,
    );
    const periodSecret = toBase64(generateAesKeyBytes());

    if (format === "json") {
        process.stdout.write(
            JSON.stringify({
                publisherSigningKeyPem: privateKeyPem,
                publisherPublicKeyPem: publicKeyPem,
                periodSecret,
            }) + "\n",
        );
        return;
    }
    writeComment("Paste into .env / .env.local");
    process.stdout.write(`PUBLISHER_SIGNING_KEY="${privateKeyPem}"\n`);
    process.stdout.write(`PUBLISHER_PUBLIC_KEY="${publicKeyPem}"\n`);
    process.stdout.write(`PERIOD_SECRET="${periodSecret}"\n`);
}

async function main(): Promise<void> {
    const args = parseArgs(process.argv.slice(2));

    if (args.help) {
        process.stdout.write(USAGE);
        return;
    }
    if (!args.subcommand) {
        process.stderr.write(USAGE);
        process.exit(1);
    }

    switch (args.subcommand) {
        case "generate-publisher-keys":
            await cmdPublisherKeys(args.format);
            return;
        case "generate-issuer-keys":
            await cmdIssuerKeys(args.format);
            return;
        case "generate-period-secret":
            await cmdPeriodSecret(args.format);
            return;
        case "generate-all":
            await cmdAll(args.format);
            return;
        default:
            process.stderr.write(`Unknown command: ${args.subcommand}\n\n${USAGE}`);
            process.exit(1);
    }
}

main().catch((err) => {
    process.stderr.write(`Error: ${err instanceof Error ? err.message : String(err)}\n`);
    process.exit(1);
});
