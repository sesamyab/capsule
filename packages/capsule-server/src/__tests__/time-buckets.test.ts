import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import {
  getBucketId,
  getCurrentBucket,
  getNextBucket,
  getPreviousBucket,
  getBucketExpiration,
  isBucketValid,
  deriveBucketKey,
  getBucketKey,
  getBucketKeys,
  hkdf,
} from '../time-buckets';

describe('time-buckets', () => {
  describe('hkdf', () => {
    it('derives deterministic keys', () => {
      const secret = Buffer.from('master-secret');
      const salt = 'test-salt';
      const info = 'test-info';
      
      const key1 = hkdf(secret, salt, info, 32);
      const key2 = hkdf(secret, salt, info, 32);
      
      expect(key1.equals(key2)).toBe(true);
    });

    it('produces different keys with different salts', () => {
      const secret = Buffer.from('master-secret');
      const info = 'test-info';
      
      const key1 = hkdf(secret, 'salt1', info, 32);
      const key2 = hkdf(secret, 'salt2', info, 32);
      
      expect(key1.equals(key2)).toBe(false);
    });

    it('produces different keys with different info', () => {
      const secret = Buffer.from('master-secret');
      const salt = 'test-salt';
      
      const key1 = hkdf(secret, salt, 'info1', 32);
      const key2 = hkdf(secret, salt, 'info2', 32);
      
      expect(key1.equals(key2)).toBe(false);
    });

    it('produces keys of requested length', () => {
      const secret = Buffer.from('master-secret');
      
      expect(hkdf(secret, 'salt', 'info', 16).length).toBe(16);
      expect(hkdf(secret, 'salt', 'info', 32).length).toBe(32);
      expect(hkdf(secret, 'salt', 'info', 64).length).toBe(64);
    });

    it('accepts Buffer for salt and info', () => {
      const secret = Buffer.from('master-secret');
      const salt = Buffer.from('salt');
      const info = Buffer.from('info');
      
      const key = hkdf(secret, salt, info, 32);
      expect(key.length).toBe(32);
    });
  });

  describe('getBucketId', () => {
    it('calculates bucket ID from timestamp', () => {
      // Timestamp: 1704067200000 = 2024-01-01T00:00:00Z
      // With 30s buckets: 1704067200000 / 1000 / 30 = 56802240
      const bucketId = getBucketId(1704067200000, 30);
      expect(bucketId).toBe('56802240');
    });

    it('uses default period when not specified', () => {
      const bucketId = getBucketId(1704067200000);
      expect(bucketId).toBe('56802240'); // Same as with explicit 30
    });

    it('returns same bucket for times within same period', () => {
      const t1 = 1704067200000;
      const t2 = 1704067200000 + 29 * 1000; // 29 seconds later
      
      expect(getBucketId(t1, 30)).toBe(getBucketId(t2, 30));
    });

    it('returns different bucket after period boundary', () => {
      const t1 = 1704067200000;
      const t2 = 1704067200000 + 30 * 1000; // Exactly 30 seconds later
      
      expect(getBucketId(t1, 30)).not.toBe(getBucketId(t2, 30));
    });

    it('respects custom bucket period', () => {
      // With 60s buckets: 1704067200000 / 1000 / 60 = 28401120
      const bucketId = getBucketId(1704067200000, 60);
      expect(bucketId).toBe('28401120');
    });
  });

  describe('getCurrentBucket / getNextBucket / getPreviousBucket', () => {
    beforeEach(() => {
      vi.useFakeTimers();
    });

    afterEach(() => {
      vi.useRealTimers();
    });

    it('getCurrentBucket returns current bucket', () => {
      vi.setSystemTime(1704067200000);
      
      const current = getCurrentBucket(30);
      expect(current).toBe('56802240');
    });

    it('getNextBucket returns bucket after current', () => {
      vi.setSystemTime(1704067200000);
      
      const next = getNextBucket(30);
      expect(next).toBe('56802241');
    });

    it('getPreviousBucket returns bucket before current', () => {
      vi.setSystemTime(1704067200000);
      
      const prev = getPreviousBucket(30);
      expect(prev).toBe('56802239');
    });
  });

  describe('getBucketExpiration', () => {
    it('returns when bucket expires', () => {
      // Bucket 56802240 with 30s period expires at (56802240 + 1) * 30 * 1000
      const expiration = getBucketExpiration('56802240', 30);
      expect(expiration.getTime()).toBe(56802241 * 30 * 1000);
    });
  });

  describe('isBucketValid', () => {
    beforeEach(() => {
      vi.useFakeTimers();
    });

    afterEach(() => {
      vi.useRealTimers();
    });

    it('accepts current bucket', () => {
      vi.setSystemTime(1704067200000);
      
      expect(isBucketValid('56802240', 30)).toBe(true);
    });

    it('accepts next bucket (for grace period)', () => {
      vi.setSystemTime(1704067200000);
      
      expect(isBucketValid('56802241', 30)).toBe(true);
    });

    it('accepts previous bucket (for grace period)', () => {
      vi.setSystemTime(1704067200000);
      
      expect(isBucketValid('56802239', 30)).toBe(true);
    });

    it('rejects old bucket', () => {
      vi.setSystemTime(1704067200000);
      
      expect(isBucketValid('56802238', 30)).toBe(false);
    });

    it('rejects future bucket', () => {
      vi.setSystemTime(1704067200000);
      
      expect(isBucketValid('56802242', 30)).toBe(false);
    });
  });

  describe('deriveBucketKey', () => {
    it('derives deterministic keys', () => {
      const secret = Buffer.from('master-secret-for-testing', 'utf-8');
      
      const key1 = deriveBucketKey(secret, 'premium', '12345');
      const key2 = deriveBucketKey(secret, 'premium', '12345');
      
      expect(key1.equals(key2)).toBe(true);
    });

    it('produces 256-bit keys', () => {
      const secret = Buffer.from('master-secret', 'utf-8');
      
      const key = deriveBucketKey(secret, 'premium', '12345');
      expect(key.length).toBe(32);
    });

    it('produces different keys for different tiers', () => {
      const secret = Buffer.from('master-secret', 'utf-8');
      
      const premiumKey = deriveBucketKey(secret, 'premium', '12345');
      const basicKey = deriveBucketKey(secret, 'basic', '12345');
      
      expect(premiumKey.equals(basicKey)).toBe(false);
    });

    it('produces different keys for different buckets', () => {
      const secret = Buffer.from('master-secret', 'utf-8');
      
      const key1 = deriveBucketKey(secret, 'premium', '12345');
      const key2 = deriveBucketKey(secret, 'premium', '12346');
      
      expect(key1.equals(key2)).toBe(false);
    });

    it('produces different keys for different secrets', () => {
      const secret1 = Buffer.from('secret1', 'utf-8');
      const secret2 = Buffer.from('secret2', 'utf-8');
      
      const key1 = deriveBucketKey(secret1, 'premium', '12345');
      const key2 = deriveBucketKey(secret2, 'premium', '12345');
      
      expect(key1.equals(key2)).toBe(false);
    });
  });

  describe('getBucketKey', () => {
    beforeEach(() => {
      vi.useFakeTimers();
      vi.setSystemTime(1704067200000);
    });

    afterEach(() => {
      vi.useRealTimers();
    });

    it('returns key with metadata', () => {
      const secret = Buffer.from('master-secret', 'utf-8');
      
      const bucketKey = getBucketKey(secret, 'premium', '56802240', 30);
      
      expect(bucketKey.bucketId).toBe('56802240');
      expect(bucketKey.key).toBeInstanceOf(Buffer);
      expect(bucketKey.key.length).toBe(32);
      expect(bucketKey.expiresAt).toBeInstanceOf(Date);
    });
  });

  describe('getBucketKeys', () => {
    beforeEach(() => {
      vi.useFakeTimers();
      vi.setSystemTime(1704067200000);
    });

    afterEach(() => {
      vi.useRealTimers();
    });

    it('returns current and next bucket keys', () => {
      const secret = Buffer.from('master-secret', 'utf-8');
      
      const { current, next } = getBucketKeys(secret, 'premium', 30);
      
      expect(current.bucketId).toBe('56802240');
      expect(next.bucketId).toBe('56802241');
      expect(current.key).not.toEqual(next.key);
    });

    it('uses default period when not specified', () => {
      const secret = Buffer.from('master-secret', 'utf-8');
      
      const { current, next } = getBucketKeys(secret, 'premium');
      
      expect(parseInt(next.bucketId)).toBe(parseInt(current.bucketId) + 1);
    });
  });
});
