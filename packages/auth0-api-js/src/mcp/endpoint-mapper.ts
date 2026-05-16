import type { ToolDefinition, ToolAuthContext, ApiUpstreamOptions, MappedRequest } from './types.js';
import { McpUpstreamError } from './errors.js';

export function buildUpstreamRequest(
  tool: ToolDefinition,
  input: Record<string, unknown>,
  auth: ToolAuthContext,
  upstream: ApiUpstreamOptions
): { url: string; init: RequestInit } {
  let mapped: MappedRequest;

  if (tool.mapInput) {
    mapped = tool.mapInput({ input, auth });
  } else {
    mapped = autoMap(tool, input);
  }

  let path = tool.endpoint.path;
  if (mapped.pathParams) {
    for (const [key, value] of Object.entries(mapped.pathParams)) {
      path = path.replace(`{${key}}`, encodeURIComponent(value));
    }
  }

  const baseUrl = upstream.baseUrl.replace(/\/+$/, '');
  let url = `${baseUrl}${path}`;

  if (mapped.query) {
    const params = new URLSearchParams();
    for (const [k, v] of Object.entries(mapped.query)) {
      if (v !== undefined && v !== null && v !== '') {
        params.set(k, v);
      }
    }
    const qs = params.toString();
    if (qs) {
      url += `?${qs}`;
    }
  }

  const headers: Record<string, string> = {
    authorization: `Bearer ${auth.token}`,
    ...(mapped.headers ?? {}),
  };

  const init: RequestInit = {
    method: tool.endpoint.method,
    headers,
  };

  if (mapped.body !== undefined && tool.endpoint.method !== 'GET' && tool.endpoint.method !== 'DELETE') {
    headers['content-type'] = 'application/json';
    init.body = JSON.stringify(mapped.body);
  }

  return { url, init };
}

export async function executeUpstreamRequest(
  url: string,
  init: RequestInit,
  fetchFn: typeof fetch
): Promise<{ body: string; contentType: string | null; status: number }> {
  const response = await fetchFn(url, init);
  const body = await response.text();
  const contentType = response.headers.get('content-type');

  if (!response.ok) {
    throw new McpUpstreamError(response.status, body);
  }

  return { body, contentType, status: response.status };
}

function autoMap(tool: ToolDefinition, input: Record<string, unknown>): MappedRequest {
  const pathParamNames = extractPathParams(tool.endpoint.path);
  const pathParams: Record<string, string> = {};
  const remaining: Record<string, unknown> = {};

  for (const [key, value] of Object.entries(input)) {
    if (pathParamNames.has(key)) {
      pathParams[key] = String(value);
    } else {
      remaining[key] = value;
    }
  }

  const method = tool.endpoint.method;
  if (method === 'GET' || method === 'DELETE') {
    const query: Record<string, string> = {};
    for (const [k, v] of Object.entries(remaining)) {
      if (v !== undefined && v !== null) {
        query[k] = String(v);
      }
    }
    return { pathParams, query };
  }

  return { pathParams, body: remaining };
}

function extractPathParams(path: string): Set<string> {
  const params = new Set<string>();
  const regex = /\{(\w+)\}/g;
  let match: RegExpExecArray | null;
  while ((match = regex.exec(path)) !== null) {
    params.add(match[1]!);
  }
  return params;
}
