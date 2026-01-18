"use client";

import { useState, useEffect, useCallback } from "react";
import type { EncryptedPayload, CapsuleClient as CapsuleClientType } from "@sesamy/capsule";

/**
 * React hook for using the Capsule client-side decryption library.
 * Handles key generation, storage, and decryption.
 * 
 * The new Capsule client auto-creates keys on first use, so no manual
 * key generation is needed.
 */
export function useCapsule() {
  const [client, setClient] = useState<CapsuleClientType | null>(null);
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
        const { CapsuleClient } = await import("@sesamy/capsule");

        const capsuleClient = new CapsuleClient({
          keySize: 2048,
        });

        // Keys are auto-created on first getPublicKey() call
        // Just verify we can access them
        await capsuleClient.getPublicKey();

        if (mounted) {
          setClient(capsuleClient);
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

  // Decrypt content using the low-level decryptPayload method
  const decrypt = useCallback(
    async (payload: EncryptedPayload): Promise<string | null> => {
      if (!client) {
        setError("Client not initialized");
        return null;
      }
      try {
        return await client.decryptPayload(payload);
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
    client, // Also expose the client for advanced usage
  };
}
