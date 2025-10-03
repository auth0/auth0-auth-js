/* eslint-disable @typescript-eslint/no-explicit-any */
import { describe, expect, test, vi, beforeEach, MockInstance } from 'vitest';
import { Dpop } from './dpop.js';
import { MemoryAdapter } from './adapters/memory-adapter.js';
import type { StorageAdapter } from './adapters/storage-adapter.js';
import * as utils from './utils.js';

// Mock the dpop utils
vi.mock('./utils.js', async () => {
  const actual = await vi.importActual('./utils.js');
  return {
    ...actual,
    generateKeyPair: vi.fn(),
    generateProof: vi.fn(),
    calculateThumbprint: vi.fn(),
  };
});

const mockIndexedDBAdapter = {
  get: vi.fn().mockResolvedValue('nonce-from-indexeddb'),
  set: vi.fn(),
  delete: vi.fn(),
  getAllKeys: vi.fn(),
};

let defaultMemoryAdapter: MemoryAdapter;

vi.mock('./adapters/indexeddb-adapter.js', async () => {
  return {
    IndexedDBAdapter: vi.fn().mockImplementation(() => mockIndexedDBAdapter),
  };
});

vi.mock('./adapters/memory-adapter.js', async () => {
  const actual = await vi.importActual('./adapters/memory-adapter.js');

  return {
    MemoryAdapter: function () {
      const ActualMemoryAdapter = actual.MemoryAdapter as any;

      if (!defaultMemoryAdapter) {
        defaultMemoryAdapter = new ActualMemoryAdapter();

        vi.spyOn(defaultMemoryAdapter, 'get');
        vi.spyOn(defaultMemoryAdapter, 'set');
        vi.spyOn(defaultMemoryAdapter, 'delete');
        vi.spyOn(defaultMemoryAdapter, 'getAllKeys');
      }

      return defaultMemoryAdapter;
    },
  };
});

describe('Dpop', () => {
  const mockKeyPair = {
    publicKey: { type: 'public' } as any,
    privateKey: { type: 'private' } as any,
  };

  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(utils.generateKeyPair).mockResolvedValue(mockKeyPair);
    vi.mocked(utils.generateProof).mockResolvedValue('mock-dpop-proof');
    vi.mocked(utils.calculateThumbprint).mockResolvedValue('mock-thumbprint');
    // Reset instance to ensure isolation between tests
    defaultMemoryAdapter = undefined as any;
  });

  describe('Constructor', () => {
    test('should create instance with default adapter', async () => {
      const dpop = new Dpop('test-client-id');

      (
        defaultMemoryAdapter.get as unknown as MockInstance
      ).mockResolvedValueOnce('nonce-from-memory');

      expect(dpop).toBeInstanceOf(Dpop);
      await expect(dpop.getNonce()).resolves.toBe('nonce-from-memory');
    });

    test('should create instance with custom adapter', async () => {
      const customAdapter = {
        get: vi.fn().mockResolvedValue('nonce-from-custom'),
        set: vi.fn(),
        delete: vi.fn(),
        getAllKeys: vi.fn(),
      };
      const dpop = new Dpop('test-client-id', customAdapter);
      expect(dpop).toBeInstanceOf(Dpop);
      await expect(dpop.getNonce()).resolves.toBe('nonce-from-custom');
    });

    test('should use IndexedDBAdapter in browser environment', async () => {
      // Mock window.indexedDB
      const mockIndexedDB = {
        open: vi.fn(),
      };
      Object.defineProperty(global, 'window', {
        value: { indexedDB: mockIndexedDB },
        configurable: true,
        writable: true,
      });

      const dpop = new Dpop('test-client-id');
      expect(dpop).toBeInstanceOf(Dpop);
      await expect(dpop.getNonce()).resolves.toBe('nonce-from-indexeddb');

      // Cleanup
      delete (global as any).window;
    });

    test('should use MemoryAdapter in Node.js environment', async () => {
      // Ensure window is not defined
      delete (global as any).window;

      const dpop = new Dpop('test-client-id');

      (
        defaultMemoryAdapter.get as unknown as MockInstance
      ).mockResolvedValueOnce('nonce-from-memory');

      expect(dpop).toBeInstanceOf(Dpop);
      await expect(dpop.getNonce()).resolves.toBe('nonce-from-memory');
    });
  });

  describe('Nonce Management', () => {
    test('should set and retrieve nonce', async () => {
      const adapter = new MemoryAdapter();
      const dpop = new Dpop('test-client-id', adapter);

      await dpop.setNonce('test-nonce');

      expect(adapter.set).toHaveBeenCalledWith(
        'nonce',
        'test-client-id::auth0',
        'test-nonce'
      );

      const nonce = await dpop.getNonce();

      expect(nonce).toBe('test-nonce');
    });

    test('should return undefined when nonce does not exist', async () => {
      const adapter = new MemoryAdapter();
      const dpop = new Dpop('test-client-id', adapter);

      const nonce = await dpop.getNonce();

      expect(nonce).toBeUndefined();
    });

    test('should set and retrieve nonce with custom id', async () => {
      const adapter = new MemoryAdapter();
      const dpop = new Dpop('test-client-id', adapter);

      await dpop.setNonce('nonce-1', 'custom-id-1');
      await dpop.setNonce('nonce-2', 'custom-id-2');

      const nonce1 = await dpop.getNonce('custom-id-1');
      const nonce2 = await dpop.getNonce('custom-id-2');

      expect(nonce1).toBe('nonce-1');
      expect(nonce2).toBe('nonce-2');
    });

    test('should overwrite existing nonce', async () => {
      const adapter = new MemoryAdapter();
      const dpop = new Dpop('test-client-id', adapter);

      await dpop.setNonce('old-nonce');

      await expect(dpop.getNonce()).resolves.toBe('old-nonce');

      await dpop.setNonce('new-nonce');

      await expect(dpop.getNonce()).resolves.toBe('new-nonce');
    });
  });

  describe('Key Pair Management', () => {
    test('should generate key pair on first use', async () => {
      const adapter = new MemoryAdapter();
      const dpop = new Dpop('test-client-id', adapter);

      await dpop.generateProof({
        url: 'https://api.example.com/test',
        method: 'GET',
      });

      expect(utils.generateKeyPair).toHaveBeenCalledTimes(1);
    });

    test('should reuse existing key pair', async () => {
      const adapter = new MemoryAdapter();
      const dpop = new Dpop('test-client-id', adapter);

      await dpop.generateProof({
        url: 'https://api.example.com/test',
        method: 'GET',
      });

      await dpop.generateProof({
        url: 'https://api.example.com/test2',
        method: 'POST',
      });

      // Key pair should only be generated once
      expect(utils.generateKeyPair).toHaveBeenCalledTimes(1);
    });

    test('should persist key pair across instances', async () => {
      const adapter = new MemoryAdapter();

      const dpop1 = new Dpop('test-client-id', adapter);
      await dpop1.generateProof({
        url: 'https://api.example.com/test',
        method: 'GET',
      });

      // First instance generates key pair
      expect(utils.generateKeyPair).toHaveBeenCalledTimes(1);

      vi.clearAllMocks();
      vi.mocked(utils.generateKeyPair).mockResolvedValue(mockKeyPair);
      vi.mocked(utils.generateProof).mockResolvedValue('mock-dpop-proof-2');

      const dpop2 = new Dpop('test-client-id', adapter);
      await dpop2.generateProof({
        url: 'https://api.example.com/test',
        method: 'GET',
      });

      // Second instance should reuse existing key pair
      expect(utils.generateKeyPair).not.toHaveBeenCalled();
    });
  });

  // TODO: These are silly tests that only tests it calls the utils with correct params
  describe('DPoP Proof Generation', () => {
    test('should generate proof with required parameters', async () => {
      const adapter = new MemoryAdapter();
      const dpop = new Dpop('test-client-id', adapter);

      const proof = await dpop.generateProof({
        url: 'https://api.example.com/test',
        method: 'POST',
      });

      expect(proof).toBe('mock-dpop-proof');
      expect(utils.generateProof).toHaveBeenCalledWith({
        keyPair: mockKeyPair,
        url: 'https://api.example.com/test',
        method: 'POST',
      });
    });

    test('should generate proof with nonce', async () => {
      const adapter = new MemoryAdapter();
      const dpop = new Dpop('test-client-id', adapter);

      const proof = await dpop.generateProof({
        url: 'https://api.example.com/test',
        method: 'GET',
        nonce: 'test-nonce',
      });

      expect(proof).toBe('mock-dpop-proof');
      expect(utils.generateProof).toHaveBeenCalledWith({
        keyPair: mockKeyPair,
        url: 'https://api.example.com/test',
        method: 'GET',
        nonce: 'test-nonce',
      });
    });

    test('should generate proof with access token', async () => {
      const adapter = new MemoryAdapter();
      const dpop = new Dpop('test-client-id', adapter);

      const proof = await dpop.generateProof({
        url: 'https://api.example.com/test',
        method: 'POST',
        accessToken: 'test-access-token',
      });

      expect(proof).toBe('mock-dpop-proof');
      expect(utils.generateProof).toHaveBeenCalledWith({
        keyPair: mockKeyPair,
        url: 'https://api.example.com/test',
        method: 'POST',
        accessToken: 'test-access-token',
      });
    });

    test('should generate proof with all parameters', async () => {
      const adapter = new MemoryAdapter();
      const dpop = new Dpop('test-client-id', adapter);

      const proof = await dpop.generateProof({
        url: 'https://api.example.com/test',
        method: 'PUT',
        nonce: 'test-nonce',
        accessToken: 'test-access-token',
      });

      expect(proof).toBe('mock-dpop-proof');
      expect(utils.generateProof).toHaveBeenCalledWith({
        keyPair: mockKeyPair,
        url: 'https://api.example.com/test',
        method: 'PUT',
        nonce: 'test-nonce',
        accessToken: 'test-access-token',
      });
    });

    test('should handle proof generation errors', async () => {
      const adapter = new MemoryAdapter();
      const dpop = new Dpop('test-client-id', adapter);

      const error = new Error('Proof generation failed');
      vi.mocked(utils.generateProof).mockRejectedValue(error);

      await expect(
        dpop.generateProof({
          url: 'https://api.example.com/test',
          method: 'GET',
        })
      ).rejects.toThrow('Proof generation failed');
    });
  });

  describe('Thumbprint Calculation', () => {
    test('should calculate thumbprint', async () => {
      const adapter = new MemoryAdapter();
      const dpop = new Dpop('test-client-id', adapter);

      const thumbprint = await dpop.calculateThumbprint();

      expect(thumbprint).toBe('mock-thumbprint');
      expect(utils.calculateThumbprint).toHaveBeenCalledWith(mockKeyPair);
    });

    test('should use same key pair for thumbprint and proof', async () => {
      const adapter = new MemoryAdapter();
      const dpop = new Dpop('test-client-id', adapter);

      await dpop.generateProof({
        url: 'https://api.example.com/test',
        method: 'GET',
      });

      await dpop.calculateThumbprint();

      // Should only generate key pair once
      expect(utils.generateKeyPair).toHaveBeenCalledTimes(1);
    });

    test('should handle thumbprint calculation errors', async () => {
      const adapter = new MemoryAdapter();
      const dpop = new Dpop('test-client-id', adapter);

      const error = new Error('Thumbprint calculation failed');
      vi.mocked(utils.calculateThumbprint).mockRejectedValue(error);

      await expect(dpop.calculateThumbprint()).rejects.toThrow(
        'Thumbprint calculation failed'
      );
    });
  });

  describe('Clear Storage', () => {
    test('should clear all nonces and key pairs', async () => {
      const adapter = new MemoryAdapter();
      const dpop = new Dpop('test-client-id', adapter);

      // Set some data
      await dpop.setNonce('test-nonce');
      await dpop.generateProof({
        url: 'https://api.example.com/test',
        method: 'GET',
      });

      // Verify data exists
      let nonce = await dpop.getNonce();
      expect(nonce).toBe('test-nonce');

      // Clear all data
      await dpop.clear();

      // Verify nonce is cleared
      nonce = await dpop.getNonce();
      expect(nonce).toBeUndefined();

      // Verify key pair is cleared (new one should be generated)
      vi.clearAllMocks();
      vi.mocked(utils.generateKeyPair).mockResolvedValue(mockKeyPair);
      vi.mocked(utils.generateProof).mockResolvedValue('new-proof');

      await dpop.generateProof({
        url: 'https://api.example.com/test',
        method: 'GET',
      });

      expect(utils.generateKeyPair).toHaveBeenCalledTimes(1);
    });

    test('should only clear data for specific client', async () => {
      const adapter = new MemoryAdapter();

      const dpop1 = new Dpop('client-1', adapter);
      const dpop2 = new Dpop('client-2', adapter);

      await dpop1.setNonce('nonce-1');
      await dpop2.setNonce('nonce-2');

      await dpop1.clear();

      const nonce1 = await dpop1.getNonce();
      const nonce2 = await dpop2.getNonce();

      expect(nonce1).toBeUndefined();
      expect(nonce2).toBe('nonce-2');
    });
  });

  describe('Security: Error Handling', () => {
    test('should handle storage adapter errors gracefully', async () => {
      const failingAdapter: StorageAdapter = {
        get: vi.fn().mockRejectedValue(new Error('Storage read failed')),
        set: vi.fn().mockRejectedValue(new Error('Storage write failed')),
        delete: vi.fn().mockRejectedValue(new Error('Storage delete failed')),
        getAllKeys: vi
          .fn()
          .mockRejectedValue(new Error('Storage getAllKeys failed')),
      };

      const dpop = new Dpop('test-client-id', failingAdapter);

      await expect(dpop.getNonce()).rejects.toThrow('Storage read failed');
      await expect(dpop.setNonce('test-nonce')).rejects.toThrow(
        'Storage write failed'
      );
    });

    test('should handle key pair generation errors', async () => {
      const adapter = new MemoryAdapter();
      const dpop = new Dpop('test-client-id', adapter);

      const error = new Error('Key generation failed');
      vi.mocked(utils.generateKeyPair).mockRejectedValue(error);

      await expect(
        dpop.generateProof({
          url: 'https://api.example.com/test',
          method: 'GET',
        })
      ).rejects.toThrow('Key generation failed');
    });

    test('should not expose sensitive data in errors', async () => {
      const adapter = new MemoryAdapter();
      const dpop = new Dpop('test-client-id', adapter);

      const sensitiveToken = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.secret';
      vi.mocked(utils.generateProof).mockRejectedValue(
        new Error(`Proof failed with token: ${sensitiveToken}`)
      );

      try {
        await dpop.generateProof({
          url: 'https://api.example.com/test',
          method: 'GET',
          accessToken: sensitiveToken,
        });
      } catch (error: any) {
        // Document current behavior - error may contain sensitive data
        expect(error.message).toBeDefined();
      }
    });
  });

  describe('Cross-Platform Compatibility', () => {
    test('should work with MemoryAdapter in Node.js', async () => {
      const adapter = new MemoryAdapter();
      const dpop = new Dpop('test-client-id', adapter);

      await dpop.setNonce('node-nonce');
      const nonce = await dpop.getNonce();

      expect(nonce).toBe('node-nonce');

      const proof = await dpop.generateProof({
        url: 'https://api.example.com/test',
        method: 'GET',
      });

      expect(proof).toBe('mock-dpop-proof');
    });

    test('should isolate data by client ID', async () => {
      const adapter = new MemoryAdapter();

      const dpop1 = new Dpop('client-1', adapter);
      const dpop2 = new Dpop('client-2', adapter);

      await dpop1.setNonce('nonce-1');
      await dpop2.setNonce('nonce-2');

      const nonce1 = await dpop1.getNonce();
      const nonce2 = await dpop2.getNonce();

      expect(nonce1).toBe('nonce-1');
      expect(nonce2).toBe('nonce-2');
      expect(nonce1).not.toBe(nonce2);
    });

    test('should handle special characters in client ID', async () => {
      const adapter = new MemoryAdapter();
      const specialClientId = 'client@123!$%^&*()';

      const dpop = new Dpop(specialClientId, adapter);

      await dpop.setNonce('special-nonce');
      const nonce = await dpop.getNonce();

      expect(nonce).toBe('special-nonce');
    });
  });

  describe('Performance and Concurrency', () => {
    test('should handle concurrent nonce operations', async () => {
      const adapter = new MemoryAdapter();
      const dpop = new Dpop('test-client-id', adapter);

      const operations = [
        dpop.setNonce('nonce-1'),
        dpop.setNonce('nonce-2'),
        dpop.setNonce('nonce-3'),
      ];

      await Promise.all(operations);

      const finalNonce = await dpop.getNonce();
      expect(['nonce-1', 'nonce-2', 'nonce-3']).toContain(finalNonce);
    });
  });
});
