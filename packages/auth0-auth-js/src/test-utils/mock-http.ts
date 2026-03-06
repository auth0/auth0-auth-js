import type { RequestHandler } from 'msw';

export interface MockHttpServer {
  listen: () => void;
  close: () => void;
  resetHandlers: () => void;
  use: (...handlers: RequestHandler[]) => void;
}

/**
 * Sets up a mock HTTP server by patching globalThis.fetch and routing requests
 * through MSW handler.run(). This works across all runtimes (Node.js, Bun,
 * Deno, Cloudflare Workers) because auth0-auth-js exclusively uses fetch for
 * HTTP, so no Node.js HTTP interceptors are needed.
 */
export function setupServer(...initialHandlers: Array<RequestHandler>): MockHttpServer {
  let handlers: RequestHandler[] = [...initialHandlers];
  let originalFetch: typeof globalThis.fetch;

  return {
    listen() {
      originalFetch = globalThis.fetch;
      globalThis.fetch = async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
        const request = new Request(input, init);
        for (const handler of handlers) {
          const result = await handler.run({
            request: request.clone(),
            requestId: crypto.randomUUID(),
          });
          if (result?.response) {
            return result.response;
          }
        }
        throw new Error(`[msw] No handler matched: ${request.method} ${request.url}`);
      };
    },
    close() {
      globalThis.fetch = originalFetch;
    },
    resetHandlers(...nextHandlers: RequestHandler[]) {
      handlers = nextHandlers.length ? nextHandlers : [...initialHandlers];
    },
    use(...nextHandlers: RequestHandler[]) {
      handlers = [...nextHandlers, ...handlers];
    },
  };
}
