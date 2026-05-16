import { describe, expect, test } from 'vitest';
import { parseRequest, success, error, errorForParseFailure, JsonRpcParseError } from './json-rpc.js';

describe('parseRequest', () => {
  test('parses valid request', () => {
    const result = parseRequest({
      jsonrpc: '2.0',
      id: 1,
      method: 'tools/list',
      params: { cursor: 'abc' },
    });

    expect(result.jsonrpc).toBe('2.0');
    expect(result.id).toBe(1);
    expect(result.method).toBe('tools/list');
    expect(result.params).toEqual({ cursor: 'abc' });
  });

  test('handles missing id (notification)', () => {
    const result = parseRequest({
      jsonrpc: '2.0',
      method: 'notifications/initialized',
    });

    expect(result.id).toBeNull();
    expect(result.method).toBe('notifications/initialized');
  });

  test('handles null id', () => {
    const result = parseRequest({
      jsonrpc: '2.0',
      id: null,
      method: 'test',
    });

    expect(result.id).toBeNull();
  });

  test('handles string id', () => {
    const result = parseRequest({
      jsonrpc: '2.0',
      id: 'req-uuid',
      method: 'test',
    });

    expect(result.id).toBe('req-uuid');
  });

  test('throws on non-object body', () => {
    expect(() => parseRequest(null)).toThrow(JsonRpcParseError);
    expect(() => parseRequest('string')).toThrow(JsonRpcParseError);
    expect(() => parseRequest(42)).toThrow(JsonRpcParseError);
  });

  test('throws on missing jsonrpc field', () => {
    expect(() => parseRequest({ method: 'test' })).toThrow(JsonRpcParseError);
  });

  test('throws on wrong jsonrpc version', () => {
    expect(() => parseRequest({ jsonrpc: '1.0', method: 'test' })).toThrow(JsonRpcParseError);
  });

  test('throws on missing method', () => {
    expect(() => parseRequest({ jsonrpc: '2.0' })).toThrow(JsonRpcParseError);
  });

  test('throws on non-string method', () => {
    expect(() => parseRequest({ jsonrpc: '2.0', method: 123 })).toThrow(JsonRpcParseError);
  });

  test('throws on non-object params', () => {
    expect(() => parseRequest({ jsonrpc: '2.0', method: 'test', params: 'bad' })).toThrow(JsonRpcParseError);
  });

  test('allows undefined params', () => {
    const result = parseRequest({ jsonrpc: '2.0', method: 'test' });
    expect(result.params).toBeUndefined();
  });
});

describe('success', () => {
  test('creates success response', () => {
    const res = success(1, { tools: [] });
    expect(res).toEqual({
      jsonrpc: '2.0',
      id: 1,
      result: { tools: [] },
    });
  });

  test('handles null id', () => {
    const res = success(null, 'ok');
    expect(res.id).toBeNull();
  });
});

describe('error', () => {
  test('creates error response without data', () => {
    const res = error(1, -32601, 'Method not found');
    expect(res).toEqual({
      jsonrpc: '2.0',
      id: 1,
      error: { code: -32601, message: 'Method not found' },
    });
  });

  test('creates error response with data', () => {
    const res = error(1, -32003, 'Forbidden', { missingScopes: ['admin'] });
    expect(res.error.data).toEqual({ missingScopes: ['admin'] });
  });
});

describe('errorForParseFailure', () => {
  test('creates parse error with null id', () => {
    const res = errorForParseFailure('Bad request');
    expect(res.id).toBeNull();
    expect(res.error.code).toBe(-32700);
    expect(res.error.message).toBe('Bad request');
  });
});
