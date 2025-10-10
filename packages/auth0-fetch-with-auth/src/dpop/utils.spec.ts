import { describe, expect, test, vi, beforeEach } from 'vitest';
import { generateProof, DPOP_NONCE_HEADER, type KeyPair } from './utils.js';
import * as dpopLib from 'dpop';

vi.mock('dpop');

describe('DPoP Utils', () => {
  describe('DPOP_NONCE_HEADER', () => {
    test('should be defined as dpop-nonce', () => {
      expect(DPOP_NONCE_HEADER).toBe('dpop-nonce');
    });
  });

  describe('generateProof', () => {
    let mockKeyPair: KeyPair;
    let mockGenerateProof: ReturnType<typeof vi.fn>;

    beforeEach(() => {
      mockKeyPair = {
        privateKey: {} as CryptoKey,
        publicKey: {} as CryptoKey,
      } as KeyPair;
      mockGenerateProof = vi.fn().mockResolvedValue('mock-proof-token');
      vi.mocked(dpopLib.generateProof).mockImplementation(mockGenerateProof);
    });

    test('should call dpopLib.generateProof with normalized URL', async () => {
      const url = 'https://example.com/path?query=value#hash';
      const method = 'POST';

      await generateProof({ keyPair: mockKeyPair, url, method });

      expect(mockGenerateProof).toHaveBeenCalledWith(
        mockKeyPair,
        'https://example.com/path',
        method,
        undefined,
        undefined
      );
    });

    test('should remove query parameters from URL', async () => {
      const url = 'https://example.com/api/resource?foo=bar&baz=qux';
      const method = 'GET';

      await generateProof({ keyPair: mockKeyPair, url, method });

      expect(mockGenerateProof).toHaveBeenCalledWith(
        mockKeyPair,
        'https://example.com/api/resource',
        method,
        undefined,
        undefined
      );
    });

    test('should remove hash fragment from URL', async () => {
      const url = 'https://example.com/path#section';
      const method = 'GET';

      await generateProof({ keyPair: mockKeyPair, url, method });

      expect(mockGenerateProof).toHaveBeenCalledWith(
        mockKeyPair,
        'https://example.com/path',
        method,
        undefined,
        undefined
      );
    });

    test('should remove both query and hash from URL', async () => {
      const url = 'https://example.com/path?query=value#hash';
      const method = 'DELETE';

      await generateProof({ keyPair: mockKeyPair, url, method });

      expect(mockGenerateProof).toHaveBeenCalledWith(
        mockKeyPair,
        'https://example.com/path',
        method,
        undefined,
        undefined
      );
    });

    test('should pass nonce when provided', async () => {
      const url = 'https://example.com/path';
      const method = 'POST';
      const nonce = 'test-nonce-123';

      await generateProof({ keyPair: mockKeyPair, url, method, nonce });

      expect(mockGenerateProof).toHaveBeenCalledWith(
        mockKeyPair,
        'https://example.com/path',
        method,
        nonce,
        undefined
      );
    });

    test('should pass accessToken when provided', async () => {
      const url = 'https://example.com/path';
      const method = 'POST';
      const accessToken = 'test-access-token';

      await generateProof({
        keyPair: mockKeyPair,
        url,
        method,
        accessToken,
      });

      expect(mockGenerateProof).toHaveBeenCalledWith(
        mockKeyPair,
        'https://example.com/path',
        method,
        undefined,
        accessToken
      );
    });

    test('should pass both nonce and accessToken when provided', async () => {
      const url = 'https://example.com/path?query=value';
      const method = 'PUT';
      const nonce = 'test-nonce-456';
      const accessToken = 'test-access-token-789';

      await generateProof({
        keyPair: mockKeyPair,
        url,
        method,
        nonce,
        accessToken,
      });

      expect(mockGenerateProof).toHaveBeenCalledWith(
        mockKeyPair,
        'https://example.com/path',
        method,
        nonce,
        accessToken
      );
    });

    test('should return the proof token from dpopLib', async () => {
      mockGenerateProof.mockResolvedValue('expected-proof-token');

      const result = await generateProof({
        keyPair: mockKeyPair,
        url: 'https://example.com/path',
        method: 'GET',
      });

      expect(result).toBe('expected-proof-token');
    });

    test('should handle URLs with port numbers', async () => {
      const url = 'https://example.com:8080/path?query=value';
      const method = 'GET';

      await generateProof({ keyPair: mockKeyPair, url, method });

      expect(mockGenerateProof).toHaveBeenCalledWith(
        mockKeyPair,
        'https://example.com:8080/path',
        method,
        undefined,
        undefined
      );
    });

    test('should handle URLs with authentication credentials', async () => {
      const url = 'https://user:pass@example.com/path?query=value';
      const method = 'POST';

      await generateProof({ keyPair: mockKeyPair, url, method });

      expect(mockGenerateProof).toHaveBeenCalledWith(
        mockKeyPair,
        'https://user:pass@example.com/path',
        method,
        undefined,
        undefined
      );
    });

    test('should handle URLs with trailing slash', async () => {
      const url = 'https://example.com/path/?query=value';
      const method = 'GET';

      await generateProof({ keyPair: mockKeyPair, url, method });

      expect(mockGenerateProof).toHaveBeenCalledWith(
        mockKeyPair,
        'https://example.com/path/',
        method,
        undefined,
        undefined
      );
    });

    test('should handle root URLs', async () => {
      const url = 'https://example.com/?query=value#hash';
      const method = 'GET';

      await generateProof({ keyPair: mockKeyPair, url, method });

      expect(mockGenerateProof).toHaveBeenCalledWith(
        mockKeyPair,
        'https://example.com/',
        method,
        undefined,
        undefined
      );
    });

    test('should handle different HTTP methods', async () => {
      const url = 'https://example.com/path';
      const methods = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD'];

      for (const method of methods) {
        mockGenerateProof.mockClear();
        await generateProof({ keyPair: mockKeyPair, url, method });

        expect(mockGenerateProof).toHaveBeenCalledWith(
          mockKeyPair,
          'https://example.com/path',
          method,
          undefined,
          undefined
        );
      }
    });

    test('should handle URLs with encoded characters', async () => {
      const url = 'https://example.com/path%20with%20spaces?query=value%20encoded';
      const method = 'GET';

      await generateProof({ keyPair: mockKeyPair, url, method });

      expect(mockGenerateProof).toHaveBeenCalledWith(
        mockKeyPair,
        'https://example.com/path%20with%20spaces',
        method,
        undefined,
        undefined
      );
    });

    test('should propagate errors from dpopLib.generateProof', async () => {
      const error = new Error('DPoP generation failed');
      mockGenerateProof.mockRejectedValue(error);

      await expect(
        generateProof({
          keyPair: mockKeyPair,
          url: 'https://example.com/path',
          method: 'GET',
        })
      ).rejects.toThrow('DPoP generation failed');
    });

    test('should handle empty query string', async () => {
      const url = 'https://example.com/path?';
      const method = 'GET';

      await generateProof({ keyPair: mockKeyPair, url, method });

      expect(mockGenerateProof).toHaveBeenCalledWith(
        mockKeyPair,
        'https://example.com/path',
        method,
        undefined,
        undefined
      );
    });

    test('should handle empty hash fragment', async () => {
      const url = 'https://example.com/path#';
      const method = 'GET';

      await generateProof({ keyPair: mockKeyPair, url, method });

      expect(mockGenerateProof).toHaveBeenCalledWith(
        mockKeyPair,
        'https://example.com/path',
        method,
        undefined,
        undefined
      );
    });

    test('should handle complex path with multiple segments', async () => {
      const url = 'https://api.example.com/v1/users/123/posts/456?include=comments#top';
      const method = 'GET';

      await generateProof({ keyPair: mockKeyPair, url, method });

      expect(mockGenerateProof).toHaveBeenCalledWith(
        mockKeyPair,
        'https://api.example.com/v1/users/123/posts/456',
        method,
        undefined,
        undefined
      );
    });
  });
});
