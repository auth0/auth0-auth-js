/* eslint-disable @typescript-eslint/no-explicit-any */
import { describe, expect, test, vi, } from 'vitest';
import { DpopStorage } from './storage.js';
import { MemoryAdapter } from './adapters/memory-adapter.js';
import type { StorageAdapter } from './adapters/storage-adapter.js';
import type { KeyPair } from './utils.js';

describe('DpopStorage', () => {
  const mockKeyPair: KeyPair = {
    publicKey: { type: 'public' } as any,
    privateKey: { type: 'private' } as any,
  };

  describe('Constructor', () => {
    test('should create instance with adapter', () => {
      const adapter = new MemoryAdapter();
      const storage = new DpopStorage('test-client', adapter);
      expect(storage).toBeInstanceOf(DpopStorage);
    });
  });

  describe('Key Building', () => {
    test('should build key with default id (auth0)', async () => {
      const adapter = new MemoryAdapter();
      const getSpy = vi.spyOn(adapter, 'get');

      const storage = new DpopStorage('test-client', adapter);
      await storage.findNonce();

      expect(getSpy).toHaveBeenCalledWith('nonce', 'test-client::auth0');
    });

    test('should build key with custom id', async () => {
      const adapter = new MemoryAdapter();
      const getSpy = vi.spyOn(adapter, 'get');

      const storage = new DpopStorage('test-client', adapter);
      await storage.findNonce('custom-id');

      expect(getSpy).toHaveBeenCalledWith('nonce', 'test-client::_custom-id');
    });

    test('should prefix custom id to avoid collisions', async () => {
      const adapter = new MemoryAdapter();
      const storage = new DpopStorage('test-client', adapter);

      // Store with custom id
      await storage.setNonce('nonce-1', 'auth0');
      await storage.setNonce('nonce-2'); // This uses default 'auth0' id

      const nonce1 = await storage.findNonce('auth0');
      const nonce2 = await storage.findNonce();

      // Should be different because 'auth0' custom id gets prefixed with '_'
      expect(nonce1).toBe('nonce-1');
      expect(nonce2).toBe('nonce-2');
    });

    test('should isolate storage by client ID', async () => {
      const adapter = new MemoryAdapter();

      const storage1 = new DpopStorage('client-1', adapter);
      const storage2 = new DpopStorage('client-2', adapter);

      await storage1.setNonce('nonce-1');
      await storage2.setNonce('nonce-2');

      const nonce1 = await storage1.findNonce();
      const nonce2 = await storage2.findNonce();

      expect(nonce1).toBe('nonce-1');
      expect(nonce2).toBe('nonce-2');
    });
  });

  describe('Nonce Storage', () => {
    test('should set and retrieve nonce', async () => {
      const adapter = new MemoryAdapter();
      const storage = new DpopStorage('test-client', adapter);

      await storage.setNonce('test-nonce');
      const nonce = await storage.findNonce();

      expect(nonce).toBe('test-nonce');
    });

    test('should return undefined for non-existent nonce', async () => {
      const adapter = new MemoryAdapter();
      const storage = new DpopStorage('test-client', adapter);

      const nonce = await storage.findNonce();

      expect(nonce).toBeUndefined();
    });

    test('should overwrite existing nonce', async () => {
      const adapter = new MemoryAdapter();
      const storage = new DpopStorage('test-client', adapter);

      await storage.setNonce('old-nonce');
      await storage.setNonce('new-nonce');

      const nonce = await storage.findNonce();

      expect(nonce).toBe('new-nonce');
    });

    test('should handle multiple nonces with different ids', async () => {
      const adapter = new MemoryAdapter();
      const storage = new DpopStorage('test-client', adapter);

      await storage.setNonce('nonce-1', 'id-1');
      await storage.setNonce('nonce-2', 'id-2');
      await storage.setNonce('nonce-3', 'id-3');

      const nonce1 = await storage.findNonce('id-1');
      const nonce2 = await storage.findNonce('id-2');
      const nonce3 = await storage.findNonce('id-3');

      expect(nonce1).toBe('nonce-1');
      expect(nonce2).toBe('nonce-2');
      expect(nonce3).toBe('nonce-3');
    });

    test('should store nonce in correct table', async () => {
      const adapter = new MemoryAdapter();
      const setSpy = vi.spyOn(adapter, 'set');

      const storage = new DpopStorage('test-client', adapter);
      await storage.setNonce('test-nonce');

      expect(setSpy).toHaveBeenCalledWith(
        'nonce',
        'test-client::auth0',
        'test-nonce'
      );
    });
  });

  describe('KeyPair Storage', () => {
    test('should set and retrieve key pair', async () => {
      const adapter = new MemoryAdapter();
      const storage = new DpopStorage('test-client', adapter);

      await storage.setKeyPair(mockKeyPair);
      const keyPair = await storage.findKeyPair();

      expect(keyPair).toEqual(mockKeyPair);
    });

    test('should return undefined for non-existent key pair', async () => {
      const adapter = new MemoryAdapter();
      const storage = new DpopStorage('test-client', adapter);

      const keyPair = await storage.findKeyPair();

      expect(keyPair).toBeUndefined();
    });

    test('should overwrite existing key pair', async () => {
      const adapter = new MemoryAdapter();
      const storage = new DpopStorage('test-client', adapter);

      const oldKeyPair: KeyPair = {
        publicKey: { type: 'old-public' } as any,
        privateKey: { type: 'old-private' } as any,
      };

      await storage.setKeyPair(oldKeyPair);
      await storage.setKeyPair(mockKeyPair);

      const keyPair = await storage.findKeyPair();

      expect(keyPair).toEqual(mockKeyPair);
    });

    test('should store key pair in correct table', async () => {
      const adapter = new MemoryAdapter();
      const setSpy = vi.spyOn(adapter, 'set');

      const storage = new DpopStorage('test-client', adapter);
      await storage.setKeyPair(mockKeyPair);

      expect(setSpy).toHaveBeenCalledWith(
        'keypair',
        'test-client::auth0',
        mockKeyPair
      );
    });

    test('should isolate key pairs by client ID', async () => {
      const adapter = new MemoryAdapter();

      const storage1 = new DpopStorage('client-1', adapter);
      const storage2 = new DpopStorage('client-2', adapter);

      const keyPair1: KeyPair = {
        publicKey: { type: 'public-1' } as any,
        privateKey: { type: 'private-1' } as any,
      };

      const keyPair2: KeyPair = {
        publicKey: { type: 'public-2' } as any,
        privateKey: { type: 'private-2' } as any,
      };

      await storage1.setKeyPair(keyPair1);
      await storage2.setKeyPair(keyPair2);

      const retrieved1 = await storage1.findKeyPair();
      const retrieved2 = await storage2.findKeyPair();

      expect(retrieved1).toEqual(keyPair1);
      expect(retrieved2).toEqual(keyPair2);
    });
  });

  describe('Clear Operations', () => {
    test('should clear all nonces for client', async () => {
      const adapter = new MemoryAdapter();
      const storage = new DpopStorage('test-client', adapter);

      await storage.setNonce('nonce-1', 'id-1');
      await storage.setNonce('nonce-2', 'id-2');
      await storage.setNonce('nonce-3', 'id-3');

      await storage.clearNonces();

      const nonce1 = await storage.findNonce('id-1');
      const nonce2 = await storage.findNonce('id-2');
      const nonce3 = await storage.findNonce('id-3');

      expect(nonce1).toBeUndefined();
      expect(nonce2).toBeUndefined();
      expect(nonce3).toBeUndefined();
    });

    test('should clear all key pairs for client', async () => {
      const adapter = new MemoryAdapter();
      const storage = new DpopStorage('test-client', adapter);

      await storage.setKeyPair(mockKeyPair);

      await storage.clearKeyPairs();

      const keyPair = await storage.findKeyPair();

      expect(keyPair).toBeUndefined();
    });

    test('should only clear data for specific client', async () => {
      const adapter = new MemoryAdapter();

      const storage1 = new DpopStorage('client-1', adapter);
      const storage2 = new DpopStorage('client-2', adapter);

      await storage1.setNonce('nonce-1');
      await storage2.setNonce('nonce-2');

      await storage1.setKeyPair(mockKeyPair);
      await storage2.setKeyPair(mockKeyPair);

      await storage1.clearNonces();
      await storage1.clearKeyPairs();

      const nonce1 = await storage1.findNonce();
      const nonce2 = await storage2.findNonce();
      const keyPair1 = await storage1.findKeyPair();
      const keyPair2 = await storage2.findKeyPair();

      expect(nonce1).toBeUndefined();
      expect(nonce2).toBe('nonce-2');
      expect(keyPair1).toBeUndefined();
      expect(keyPair2).toEqual(mockKeyPair);
    });

    test('should handle clearing empty storage', async () => {
      const adapter = new MemoryAdapter();
      const storage = new DpopStorage('test-client', adapter);

      await expect(storage.clearNonces()).resolves.not.toThrow();
      await expect(storage.clearKeyPairs()).resolves.not.toThrow();
    });
  });

  describe('Error Handling', () => {
    test('should propagate adapter get errors', async () => {
      const failingAdapter: StorageAdapter = {
        get: vi.fn().mockRejectedValue(new Error('Get failed')),
        set: vi.fn().mockResolvedValue(void 0),
        delete: vi.fn().mockResolvedValue(void 0),
        getAllKeys: vi.fn().mockResolvedValue([]),
      };

      const storage = new DpopStorage('test-client', failingAdapter);

      await expect(storage.findNonce()).rejects.toThrow('Get failed');
      await expect(storage.findKeyPair()).rejects.toThrow('Get failed');
    });

    test('should propagate adapter set errors', async () => {
      const failingAdapter: StorageAdapter = {
        get: vi.fn().mockResolvedValue(undefined),
        set: vi.fn().mockRejectedValue(new Error('Set failed')),
        delete: vi.fn().mockResolvedValue(void 0),
        getAllKeys: vi.fn().mockResolvedValue([]),
      };

      const storage = new DpopStorage('test-client', failingAdapter);

      await expect(storage.setNonce('test-nonce')).rejects.toThrow(
        'Set failed'
      );
      await expect(storage.setKeyPair(mockKeyPair)).rejects.toThrow(
        'Set failed'
      );
    });

    test('should propagate adapter delete errors', async () => {
      const failingAdapter: StorageAdapter = new MemoryAdapter();

      vi.spyOn(failingAdapter, 'delete').mockRejectedValue(
        new Error('Delete failed')
      );

      const storage = new DpopStorage('test-client', failingAdapter);

      // First add nonces and keypairs to ensure there is something to delete
      await storage.setNonce('nonce-1', 'id-1');
      await storage.setKeyPair(mockKeyPair);

      await expect(storage.clearNonces()).rejects.toThrow('Delete failed');
      await expect(storage.clearKeyPairs()).rejects.toThrow('Delete failed');
    });

    test('should propagate adapter getAllKeys errors', async () => {
      const failingAdapter: StorageAdapter = {
        get: vi.fn().mockResolvedValue(undefined),
        set: vi.fn().mockResolvedValue(void 0),
        delete: vi.fn().mockResolvedValue(void 0),
        getAllKeys: vi.fn().mockRejectedValue(new Error('GetAllKeys failed')),
      };

      const storage = new DpopStorage('test-client', failingAdapter);

      await expect(storage.clearNonces()).rejects.toThrow('GetAllKeys failed');
      await expect(storage.clearKeyPairs()).rejects.toThrow(
        'GetAllKeys failed'
      );
    });
  });

  describe('Concurrency', () => {
    test('should handle concurrent nonce writes', async () => {
      const adapter = new MemoryAdapter();
      const storage = new DpopStorage('test-client', adapter);

      const operations = [
        storage.setNonce('nonce-1', 'id-1'),
        storage.setNonce('nonce-2', 'id-2'),
        storage.setNonce('nonce-3', 'id-3'),
      ];

      await expect(Promise.all(operations)).resolves.not.toThrow();

      const nonce1 = await storage.findNonce('id-1');
      const nonce2 = await storage.findNonce('id-2');
      const nonce3 = await storage.findNonce('id-3');

      expect(nonce1).toBe('nonce-1');
      expect(nonce2).toBe('nonce-2');
      expect(nonce3).toBe('nonce-3');
    });

    test('should handle concurrent reads', async () => {
      const adapter = new MemoryAdapter();
      const storage = new DpopStorage('test-client', adapter);

      await storage.setNonce('test-nonce');
      await storage.setKeyPair(mockKeyPair);

      const operations = [
        storage.findNonce(),
        storage.findNonce(),
        storage.findKeyPair(),
        storage.findKeyPair(),
      ];

      const results = await Promise.all(operations);

      expect(results[0]).toBe('test-nonce');
      expect(results[1]).toBe('test-nonce');
      expect(results[2]).toEqual(mockKeyPair);
      expect(results[3]).toEqual(mockKeyPair);
    });

    test('should handle concurrent clear operations', async () => {
      const adapter = new MemoryAdapter();
      const storage = new DpopStorage('test-client', adapter);

      await storage.setNonce('nonce-1', 'id-1');
      await storage.setNonce('nonce-2', 'id-2');
      await storage.setKeyPair(mockKeyPair);

      const operations = [storage.clearNonces(), storage.clearKeyPairs()];

      await expect(Promise.all(operations)).resolves.not.toThrow();

      const nonce = await storage.findNonce('id-1');
      const keyPair = await storage.findKeyPair();

      expect(nonce).toBeUndefined();
      expect(keyPair).toBeUndefined();
    });
  });

  describe('Edge Cases', () => {
    test('should handle empty string as nonce', async () => {
      const adapter = new MemoryAdapter();
      const storage = new DpopStorage('test-client', adapter);

      await storage.setNonce('');
      const nonce = await storage.findNonce();

      expect(nonce).toBe('');
    });

    test('should handle special characters in nonce', async () => {
      const adapter = new MemoryAdapter();
      const storage = new DpopStorage('test-client', adapter);

      const specialNonce = 'nonce-with-!@#$%^&*()_+-=[]{}|;:,.<>?';
      await storage.setNonce(specialNonce);
      const nonce = await storage.findNonce();

      expect(nonce).toBe(specialNonce);
    });

    test('should handle unicode characters in nonce', async () => {
      const adapter = new MemoryAdapter();
      const storage = new DpopStorage('test-client', adapter);

      const unicodeNonce = 'nonce-🔐-安全-🎉';
      await storage.setNonce(unicodeNonce);
      const nonce = await storage.findNonce();

      expect(nonce).toBe(unicodeNonce);
    });

    test('should handle very long nonce strings', async () => {
      const adapter = new MemoryAdapter();
      const storage = new DpopStorage('test-client', adapter);

      const longNonce = 'x'.repeat(10000);
      await storage.setNonce(longNonce);
      const nonce = await storage.findNonce();

      expect(nonce).toBe(longNonce);
    });

    test('should handle empty client ID', async () => {
      const adapter = new MemoryAdapter();
      const storage = new DpopStorage('', adapter);

      await storage.setNonce('test-nonce');
      const nonce = await storage.findNonce();

      expect(nonce).toBe('test-nonce');
    });

    test('should handle special characters in client ID', async () => {
      const adapter = new MemoryAdapter();
      const storage = new DpopStorage('client!@#$%', adapter);

      await storage.setNonce('test-nonce');
      const nonce = await storage.findNonce();

      expect(nonce).toBe('test-nonce');
    });
  });

  describe('Cross-Platform Compatibility', () => {
    test('should work with different adapter implementations', async () => {
      const memoryAdapter = new MemoryAdapter();
      const storage = new DpopStorage('test-client', memoryAdapter);

      await storage.setNonce('test-nonce');
      await storage.setKeyPair(mockKeyPair);

      const nonce = await storage.findNonce();
      const keyPair = await storage.findKeyPair();

      expect(nonce).toBe('test-nonce');
      expect(keyPair).toEqual(mockKeyPair);
    });

    test('should serialize and deserialize complex key pair objects', async () => {
      const adapter = new MemoryAdapter();
      const storage = new DpopStorage('test-client', adapter);

      const complexKeyPair: KeyPair = {
        publicKey: {
          type: 'public',
          algorithm: { name: 'ECDSA', namedCurve: 'P-256' },
          extractable: false,
          usages: ['verify'],
        } as any,
        privateKey: {
          type: 'private',
          algorithm: { name: 'ECDSA', namedCurve: 'P-256' },
          extractable: false,
          usages: ['sign'],
        } as any,
      };

      await storage.setKeyPair(complexKeyPair);
      const retrieved = await storage.findKeyPair();

      expect(retrieved).toEqual(complexKeyPair);
    });
  });
});
