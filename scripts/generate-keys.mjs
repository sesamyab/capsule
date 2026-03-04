#!/usr/bin/env node

/**
 * Generate DCA key pairs and optionally push them to Vercel.
 *
 * Usage:
 *   node scripts/generate-keys.mjs                  # print to stdout
 *   node scripts/generate-keys.mjs --env .env       # write to .env file
 *   node scripts/generate-keys.mjs --vercel          # push to linked Vercel project
 *   node scripts/generate-keys.mjs --vercel --cwd apps/demo --scope sesamy
 */

import { webcrypto } from "node:crypto";
import { execSync } from "node:child_process";
import { writeFileSync, existsSync, readFileSync } from "node:fs";

const subtle = webcrypto.subtle;

// ── Helpers ────────────────────────────────────────────────────────────

function toPem(buf, label) {
  const b64 = Buffer.from(buf).toString("base64");
  const lines = b64.match(/.{1,64}/g).join("\n");
  return `-----BEGIN ${label}-----\n${lines}\n-----END ${label}-----`;
}

function parseArgs() {
  const args = process.argv.slice(2);
  const flags = {};
  for (let i = 0; i < args.length; i++) {
    if (args[i] === "--env") {
      flags.envFile = args[++i] || ".env";
    } else if (args[i] === "--vercel") {
      flags.vercel = true;
    } else if (args[i] === "--cwd") {
      flags.cwd = args[++i];
    } else if (args[i] === "--scope" || args[i] === "-S") {
      flags.scope = args[++i];
    } else if (args[i] === "--help" || args[i] === "-h") {
      flags.help = true;
    }
  }
  return flags;
}

// ── Key generation ─────────────────────────────────────────────────────

async function generateKeys() {
  // 1. ES256 signing key pair (ECDSA P-256)
  const signingPair = await subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"],
  );
  const sigPriv = await subtle.exportKey("pkcs8", signingPair.privateKey);
  const sigPub = await subtle.exportKey("spki", signingPair.publicKey);

  // 2. ECDH sealing key pair (ECDH P-256)
  const sealPair = await subtle.generateKey(
    { name: "ECDH", namedCurve: "P-256" },
    true,
    ["deriveBits"],
  );
  const sealPriv = await subtle.exportKey("pkcs8", sealPair.privateKey);
  const sealPub = await subtle.exportKey("spki", sealPair.publicKey);

  // 3. Period secret (256-bit random)
  const secretBytes = new Uint8Array(32);
  webcrypto.getRandomValues(secretBytes);

  return {
    PUBLISHER_ES256_PRIVATE_KEY: toPem(sigPriv, "PRIVATE KEY"),
    PUBLISHER_ES256_PUBLIC_KEY: toPem(sigPub, "PUBLIC KEY"),
    ISSUER_ECDH_PRIVATE_KEY: toPem(sealPriv, "PRIVATE KEY"),
    ISSUER_ECDH_PUBLIC_KEY: toPem(sealPub, "PUBLIC KEY"),
    PERIOD_SECRET: Buffer.from(secretBytes).toString("base64"),
  };
}

// ── Output helpers ─────────────────────────────────────────────────────

function printKeys(keys) {
  for (const [name, value] of Object.entries(keys)) {
    console.log(`\n# ${name}`);
    console.log(`${name}="${value}"`);
  }
  console.log();
}

function writeEnvFile(keys, filePath) {
  let existing = "";
  if (existsSync(filePath)) {
    existing = readFileSync(filePath, "utf-8");
  }

  const lines = [];
  for (const [name, value] of Object.entries(keys)) {
    // Remove existing entry if present
    const re = new RegExp(`^${name}=.*$`, "m");
    existing = existing.replace(re, "").trim();
    lines.push(`${name}="${value}"`);
  }

  const content = [existing, "", "# DCA keys (generated)", ...lines, ""].filter(
    (l, i, arr) => !(l === "" && i === 0),
  ).join("\n");

  writeFileSync(filePath, content, "utf-8");
  console.log(`✓ Keys written to ${filePath}`);
}

function pushToVercel(keys, { cwd, scope } = {}) {
  // Check that vercel CLI is available
  try {
    execSync("vercel --version", { stdio: "ignore" });
  } catch {
    console.error("Error: Vercel CLI not found. Install with: npm i -g vercel");
    process.exit(1);
  }

  const globalFlags = [
    cwd ? `--cwd ${cwd}` : "",
    scope ? `--scope ${scope}` : "",
  ].filter(Boolean).join(" ");
  const globalSuffix = globalFlags ? ` ${globalFlags}` : "";

  const environments = ["production", "preview", "development"];

  for (const [name, value] of Object.entries(keys)) {
    console.log(`  Setting ${name} ...`);

    for (const env of environments) {
      try {
        // Remove existing value (ignore errors if it doesn't exist)
        execSync(
          `vercel env rm ${name} ${env}${globalSuffix} --yes 2>/dev/null`,
          { stdio: "ignore" },
        );
      } catch {
        // Ignore — variable might not exist yet
      }
    }

    for (const env of environments) {
      // Add the new value via stdin
      execSync(
        `printf '%s' "${value}" | vercel env add ${name} ${env}${globalSuffix}`,
        { stdio: ["pipe", "inherit", "inherit"], shell: true },
      );
    }
  }

  console.log("\n✓ All keys pushed to Vercel.");
  console.log("  Trigger a redeploy for changes to take effect:");
  console.log(`  vercel${globalSuffix} --prod`);
}

// ── Main ───────────────────────────────────────────────────────────────

const HELP = `
Generate DCA key pairs for Capsule.

Usage:
  node scripts/generate-keys.mjs                        Print keys to stdout
  node scripts/generate-keys.mjs --env .env             Write to .env file
  node scripts/generate-keys.mjs --vercel                          Push to linked Vercel project
  node scripts/generate-keys.mjs --vercel --cwd apps/demo          Target a linked project dir
  node scripts/generate-keys.mjs --vercel --scope sesamy           Specify Vercel team/scope

Keys generated:
  PUBLISHER_ES256_PRIVATE_KEY   ES256 (ECDSA P-256) signing private key (PEM)
  PUBLISHER_ES256_PUBLIC_KEY    ES256 (ECDSA P-256) signing public key (PEM)
  ISSUER_ECDH_PRIVATE_KEY       ECDH P-256 issuer private key (PEM)
  ISSUER_ECDH_PUBLIC_KEY        ECDH P-256 issuer public key (PEM)
  PERIOD_SECRET                 256-bit random secret (base64)
`.trim();

async function main() {
  const flags = parseArgs();

  if (flags.help) {
    console.log(HELP);
    process.exit(0);
  }

  console.log("Generating DCA key pairs...\n");
  const keys = await generateKeys();

  if (flags.envFile) {
    writeEnvFile(keys, flags.envFile);
  } else if (flags.vercel) {
    pushToVercel(keys, { cwd: flags.cwd, scope: flags.scope });
  } else {
    printKeys(keys);
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
