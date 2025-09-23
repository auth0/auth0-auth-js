import { describe, expect, test, vi } from 'vitest';
import { Fetcher } from './fetcher.js';
import type { FetcherConfig, FetcherHooks, CustomFetchMinimalOutput } from './types.js';

// Mock Response for testing
class MockResponse implements CustomFetchMinimalOutput {
  status: number;
  headers: Record<string, string>;

  constructor(status: number = 200, headers: Record<string, string> = {}) {
    this.status = status;
    this.headers = headers;
  }
}

describe('Fetcher', () => {
  const mockConfig: FetcherConfig<MockResponse> = {
    fetch: vi.fn().mockResolvedValue(new MockResponse(200)),
    baseUrl: 'https://api.example.com',
  };

  const mockHooks: FetcherHooks<unknown> = {
    isDpopEnabled: vi.fn().mockReturnValue(false),
    getAccessToken: vi.fn().mockResolvedValue('mock-access-token'),
    getDpopNonce: vi.fn().mockResolvedValue(undefined),
    setDpopNonce: vi.fn().mockResolvedValue(undefined),
    generateDpopProof: vi.fn().mockResolvedValue('mock-dpop-proof'),
  };

  test('should create an instance of Fetcher', () => {
    const fetcher = new Fetcher(mockConfig, mockHooks);
    expect(fetcher).toBeInstanceOf(Fetcher);
  });

  test('should build base request correctly with relative URL', () => {
    const fetcher = new Fetcher(mockConfig, mockHooks);
    
    // Access the protected method for testing
    const buildBaseRequest = (fetcher as any).buildBaseRequest.bind(fetcher);
    
    const request = buildBaseRequest('/test', { method: 'GET' });
    
    expect(request).toBeInstanceOf(Request);
    expect(request.url).toBe('https://api.example.com/test');
    expect(request.method).toBe('GET');
  });

  test('should build base request correctly with absolute URL', () => {
    const fetcher = new Fetcher(mockConfig, mockHooks);
    
    const buildBaseRequest = (fetcher as any).buildBaseRequest.bind(fetcher);
    
    const request = buildBaseRequest('https://other-api.com/endpoint', { method: 'POST' });
    
    expect(request).toBeInstanceOf(Request);
    expect(request.url).toBe('https://other-api.com/endpoint');
    expect(request.method).toBe('POST');
  });

  test('should build base request without baseUrl', () => {
    const configWithoutBaseUrl = { ...mockConfig, baseUrl: undefined };
    const fetcher = new Fetcher(configWithoutBaseUrl, mockHooks);
    
    const buildBaseRequest = (fetcher as any).buildBaseRequest.bind(fetcher);
    
    const request = buildBaseRequest('https://api.test.com/endpoint', { method: 'POST' });
    
    expect(request).toBeInstanceOf(Request);
    expect(request.url).toBe('https://api.test.com/endpoint');
    expect(request.method).toBe('POST');
  });

  test('should handle Request object with relative URL when baseUrl is present', () => {
    const fetcher = new Fetcher(mockConfig, mockHooks);
    
    const buildBaseRequest = (fetcher as any).buildBaseRequest.bind(fetcher);
    
    // Create a mock request object that would normally have a relative URL
    // Since we can't create a Request with relative URL in Node.js, we'll test the string path
    const request = buildBaseRequest('/api/data', { method: 'GET', headers: { 'Content-Type': 'application/json' } });
    
    expect(request).toBeInstanceOf(Request);
    expect(request.url).toBe('https://api.example.com/api/data');
    expect(request.method).toBe('GET');
    expect(request.headers.get('Content-Type')).toBe('application/json');
  });

  test('should set authorization header correctly', async () => {
    const fetcher = new Fetcher(mockConfig, mockHooks);
    
    const request = new Request('https://api.example.com/test');
    const setAuthorizationHeader = (fetcher as any).setAuthorizationHeader.bind(fetcher);
    
    await setAuthorizationHeader(request, 'test-token');
    
    expect(request.headers.get('authorization')).toBe('Bearer test-token');
  });

  test('should use DPoP authorization when dpopNonceId is provided', async () => {
    const dpopConfig = { ...mockConfig, dpopNonceId: 'test-dpop-id' };
    const fetcher = new Fetcher(dpopConfig, mockHooks);
    
    const request = new Request('https://api.example.com/test');
    const setAuthorizationHeader = (fetcher as any).setAuthorizationHeader.bind(fetcher);
    
    await setAuthorizationHeader(request, 'test-token');
    
    expect(request.headers.get('authorization')).toBe('DPoP test-token');
  });

  test('fetchWithAuth should call the configured fetch function', async () => {
    const mockFetch = vi.fn().mockResolvedValue(new MockResponse(200, { 'content-type': 'application/json' }));
    const config = { ...mockConfig, fetch: mockFetch };
    const fetcher = new Fetcher(config, mockHooks);

    const request = new Request('https://api.example.com/test');
    await fetcher.fetchWithAuth(request);

    expect(mockFetch).toHaveBeenCalledTimes(1);
    expect(mockHooks.getAccessToken).toHaveBeenCalledTimes(1);
  });

  test('should handle fetch errors gracefully', async () => {
    const mockFetch = vi.fn().mockRejectedValue(new Error('Network error'));
    const config = { ...mockConfig, fetch: mockFetch };
    const fetcher = new Fetcher(config, mockHooks);
    const request = new Request('https://api.example.com/test');

    await expect(fetcher.fetchWithAuth(request)).rejects.toThrow('Network error');
  });
});
