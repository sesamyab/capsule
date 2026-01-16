"use client";

import { useState, useEffect, useCallback } from "react";

// Types that mirror the client library
interface EncryptedPayload {
  encryptedContent: string;
  iv: string;
  encryptedDek: string;
}

interface CapsuleClientInterface {
  generateKeyPair(): Promise<string>;
  getPublicKey(): Promise<string>;
  decryptArticle(payload: EncryptedPayload): Promise<string>;
  hasKeyPair(): Promise<boolean>;
}

/**
 * React hook for using the Capsule client-side decryption library.
 * Handles key generation, storage, and decryption.
 */
export function useCapsule() {
  const [client, setClient] = useState<CapsuleClientInterface | null>(null);
  const [isReady, setIsReady] = useState(false);
  const [isInitializing, setIsInitializing] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Initialize the client
  useEffect(() => {
    let mounted = true;

    async function loadClient() {
      // Only run in browser
      if (typeof window === "undefined") return;

      setIsInitializing(true);
      setError(null);

      try {
        // Dynamically import the client library
        const { CapsuleClient } = await import("capsule-client");

        const capsuleClient = new CapsuleClient({
          keyId: "demo-key",
          keySize: 2048,
        });

        // Check if keys exist, if not generate them
        const hasKeys = await capsuleClient.hasKeyPair();
        if (!hasKeys) {
          await capsuleClient.generateKeyPair();
        }

        if (mounted) {
          setClient(capsuleClient as CapsuleClientInterface);
          setIsReady(true);
        }
      } catch (err) {
        console.error("Failed to initialize Capsule client:", err);
        if (mounted) {
          setError(err instanceof Error ? err.message : "Failed to initialize");
        }
      } finally {
        if (mounted) {
          setIsInitializing(false);
        }
      }
    }

    loadClient();

    return () => {
      mounted = false;
    };
  }, []);

  // Get the public key (Base64 SPKI)
  const getPublicKey = useCallback(async (): Promise<string | null> => {
    if (!client) return null;
    try {
      return await client.getPublicKey();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to get public key");
      return null;
    }
  }, [client]);

  // Decrypt content
  const decrypt = useCallback(
    async (payload: EncryptedPayload): Promise<string | null> => {
      if (!client) {
        setError("Client not initialized");
        return null;
      }
      try {
        return await client.decryptArticle(payload);
      } catch (err) {
        console.error("Decryption failed:", err);
        setError(err instanceof Error ? err.message : "Decryption failed");
        return null;
      }
    },
    [client]
  );

  return {
    isReady,
    isInitializing,
    error,
    getPublicKey,
    decrypt,
  };
}
