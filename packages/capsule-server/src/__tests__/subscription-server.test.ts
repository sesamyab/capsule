import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { generateKeyPairSync } from 'crypto';
import { SubscriptionServer, createSubscriptionServer } from '../subscription-server';
import { generateDek, wrapDek } from '../encryption';

// Generate a test RSA key pair (SPKI format for public key)
function generateTestKeyPair() {
  const { publicKey, privateKey } = generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'der' },
    privateKeyEncoding: { type: 'pkcs8', format: 'der' },
  });
  return {
    publicKeyB64: publicKey.toString('base64'),
    privateKey,
  };
}

describe('SubscriptionServer', () => {
  const masterSecret = Buffer.from('test-master-secret-for-capsule-tests', 'utf-8');
  const testKeyPair = generateTestKeyPair();

  beforeEach(() => {
    vi.useFakeTimers();
    // Set to a known time: 2024-01-01T00:00:00Z
    vi.setSystemTime(1704067200000);
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  describe('createSubscriptionServer', () => {
    it('creates a SubscriptionServer instance', () => {
      const server = createSubscriptionServer({ masterSecret });
      expect(server).toBeInstanceOf(SubscriptionServer);
    });

    it('accepts base64 encoded master secret', () => {
      const server = createSubscriptionServer({
        masterSecret: masterSecret.toString('base64'),
      });
      expect(server).toBeInstanceOf(SubscriptionServer);
    });
  });

  describe('getBucketKeysForCms', () => {
    it('returns current and next bucket keys', () => {
      const server = createSubscriptionServer({ masterSecret, bucketPeriodSeconds: 30 });
      
      const keys = server.getBucketKeysForCms('premium');
      
      expect(keys.current.bucketId).toBe('56802240');
      expect(keys.next.bucketId).toBe('56802241');
      expect(keys.current.key).toBeInstanceOf(Buffer);
      expect(keys.current.key.length).toBe(32);
    });
  });

  describe('getBucketKeysResponse', () => {
    it('returns keys formatted for API response', () => {
      const server = createSubscriptionServer({ masterSecret, bucketPeriodSeconds: 30 });
      
      const response = server.getBucketKeysResponse('premium');
      
      expect(typeof response.current.key).toBe('string'); // Base64
      expect(typeof response.current.expiresAt).toBe('string'); // ISO date
      expect(response.current.bucketId).toBe('56802240');
    });
  });

  describe('isBucketValid', () => {
    it('validates current bucket', () => {
      const server = createSubscriptionServer({ masterSecret, bucketPeriodSeconds: 30 });
      
      expect(server.isBucketValid('56802240')).toBe(true); // current
      expect(server.isBucketValid('56802241')).toBe(true); // next
      expect(server.isBucketValid('56802239')).toBe(true); // previous
      expect(server.isBucketValid('56802238')).toBe(false); // too old
    });
  });

  describe('unlockForUser', () => {
    it('unlocks with bucket key', async () => {
      const server = createSubscriptionServer({ masterSecret, bucketPeriodSeconds: 30 });
      
      // Create a wrapped DEK using the current bucket key
      const dek = generateDek();
      const bucketKey = server.getBucketKey('premium', '56802240');
      const wrappedDekBuffer = wrapDek(dek, bucketKey);
      
      const wrappedKey = {
        keyId: 'premium:56802240',
        wrappedDek: wrappedDekBuffer.toString('base64'),
      };
      
      const result = await server.unlockForUser(wrappedKey, testKeyPair.publicKeyB64);
      
      expect(result.keyId).toBe('premium:56802240');
      expect(result.bucketId).toBe('56802240');
      expect(typeof result.encryptedDek).toBe('string');
      expect(typeof result.expiresAt).toBe('string');
    });

    it('unlocks with static key via staticKeyLookup', async () => {
      const server = createSubscriptionServer({ masterSecret, bucketPeriodSeconds: 30 });
      
      // Create a static key for an article
      const staticKey = generateDek();
      const dek = generateDek();
      const wrappedDekBuffer = wrapDek(dek, staticKey);
      
      const wrappedKey = {
        keyId: 'article:my-article',
        wrappedDek: wrappedDekBuffer.toString('base64'),
      };
      
      const staticKeyLookup = vi.fn().mockReturnValue(staticKey);
      
      const result = await server.unlockForUser(
        wrappedKey,
        testKeyPair.publicKeyB64,
        staticKeyLookup
      );
      
      expect(staticKeyLookup).toHaveBeenCalledWith('article:my-article');
      expect(result.keyId).toBe('article:my-article');
      expect(result.bucketId).toBeUndefined(); // Static keys don't have bucketId
    });

    it('supports async staticKeyLookup', async () => {
      const server = createSubscriptionServer({ masterSecret, bucketPeriodSeconds: 30 });
      
      const staticKey = generateDek();
      const dek = generateDek();
      const wrappedDekBuffer = wrapDek(dek, staticKey);
      
      const wrappedKey = {
        keyId: 'article:async-article',
        wrappedDek: wrappedDekBuffer.toString('base64'),
      };
      
      // Async lookup
      const staticKeyLookup = vi.fn().mockResolvedValue(staticKey);
      
      const result = await server.unlockForUser(
        wrappedKey,
        testKeyPair.publicKeyB64,
        staticKeyLookup
      );
      
      expect(result.keyId).toBe('article:async-article');
    });

    it('throws for expired bucket', async () => {
      const server = createSubscriptionServer({ masterSecret, bucketPeriodSeconds: 30 });
      
      const dek = generateDek();
      const oldBucketKey = server.getBucketKey('premium', '56802230'); // Old bucket
      const wrappedDekBuffer = wrapDek(dek, oldBucketKey);
      
      const wrappedKey = {
        keyId: 'premium:56802230',
        wrappedDek: wrappedDekBuffer.toString('base64'),
      };
      
      await expect(
        server.unlockForUser(wrappedKey, testKeyPair.publicKeyB64)
      ).rejects.toThrow('expired or invalid');
    });

    it('throws for static key without lookup function', async () => {
      const server = createSubscriptionServer({ masterSecret, bucketPeriodSeconds: 30 });
      
      const wrappedKey = {
        keyId: 'article:no-lookup',
        wrappedDek: 'dummydata',
      };
      
      await expect(
        server.unlockForUser(wrappedKey, testKeyPair.publicKeyB64)
      ).rejects.toThrow('not a valid bucket ID');
    });

    it('falls back to bucket key when staticKeyLookup returns null', async () => {
      const server = createSubscriptionServer({ masterSecret, bucketPeriodSeconds: 30 });
      
      const dek = generateDek();
      const bucketKey = server.getBucketKey('premium', '56802240');
      const wrappedDekBuffer = wrapDek(dek, bucketKey);
      
      const wrappedKey = {
        keyId: 'premium:56802240',
        wrappedDek: wrappedDekBuffer.toString('base64'),
      };
      
      // Lookup returns null - should fall back to bucket key
      const staticKeyLookup = vi.fn().mockReturnValue(null);
      
      const result = await server.unlockForUser(
        wrappedKey,
        testKeyPair.publicKeyB64,
        staticKeyLookup
      );
      
      expect(result.keyId).toBe('premium:56802240');
      expect(result.bucketId).toBe('56802240');
    });
  });

  describe('wrapDekForUser', () => {
    it('wraps DEK with user public key', () => {
      const server = createSubscriptionServer({ masterSecret });
      
      const dek = generateDek();
      const expiresAt = new Date(Date.now() + 60000);
      
      const result = server.wrapDekForUser(
        dek,
        testKeyPair.publicKeyB64,
        'premium:56802240',
        expiresAt
      );
      
      expect(result.keyId).toBe('premium:56802240');
      expect(result.bucketId).toBe('56802240');
      expect(typeof result.encryptedDek).toBe('string');
    });

    it('handles static key IDs correctly (no bucketId)', () => {
      const server = createSubscriptionServer({ masterSecret });
      
      const dek = generateDek();
      const expiresAt = new Date(Date.now() + 60000);
      
      const result = server.wrapDekForUser(
        dek,
        testKeyPair.publicKeyB64,
        'article:my-guide',
        expiresAt
      );
      
      expect(result.keyId).toBe('article:my-guide');
      expect(result.bucketId).toBeUndefined();
    });
  });

  describe('getTierKeyForUser', () => {
    it('returns KEK wrapped with user public key', () => {
      const server = createSubscriptionServer({ masterSecret, bucketPeriodSeconds: 30 });
      
      const result = server.getTierKeyForUser(
        'premium',
        '56802240',
        testKeyPair.publicKeyB64
      );
      
      expect(result.keyId).toBe('premium:56802240');
      expect(result.bucketId).toBe('56802240');
      expect(typeof result.encryptedDek).toBe('string');
    });

    it('throws for invalid bucket', () => {
      const server = createSubscriptionServer({ masterSecret, bucketPeriodSeconds: 30 });
      
      expect(() =>
        server.getTierKeyForUser('premium', '56802230', testKeyPair.publicKeyB64)
      ).toThrow('expired or invalid');
    });
  });

  describe('getBucketKey', () => {
    it('returns the derived bucket key', () => {
      const server = createSubscriptionServer({ masterSecret });
      
      const key = server.getBucketKey('premium', '12345');
      
      expect(key).toBeInstanceOf(Buffer);
      expect(key.length).toBe(32);
    });

    it('returns same key for same inputs', () => {
      const server = createSubscriptionServer({ masterSecret });
      
      const key1 = server.getBucketKey('premium', '12345');
      const key2 = server.getBucketKey('premium', '12345');
      
      expect(key1.equals(key2)).toBe(true);
    });
  });
});
