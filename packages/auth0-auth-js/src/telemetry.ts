export interface TelemetryData {
  /**
   * Override the package name in the telemetry header.
   */
  name: string;
  /**
   * Override the package version in the telemetry header.
   */
  version: string;
}

export type TelemetryConfig = { enabled: false } | ({ enabled?: true } & TelemetryData);

/**
 * Creates a fetch wrapper that adds the Auth0-Client telemetry header to all requests.
 *
 * @param baseFetch The base fetch implementation to wrap
 * @param config telemetry configuration
 * @returns A wrapped fetch function that adds the Auth0-Client header
 */
export function createTelemetryFetch(baseFetch: typeof fetch, config: TelemetryConfig): typeof fetch {
  // If telemetry disabled, return original fetch
  if (config.enabled === false) {
    return baseFetch;
  }

  // Create header value
  const telemetryData = {
    name: config.name,
    version: config.version,
  };

  const headerValue = Buffer.from(JSON.stringify(telemetryData)).toString('base64');

  // Return wrapped fetch that adds header
  return async (input: RequestInfo | URL, init?: RequestInit) => {
    // Start with headers from Request object if input is a Request
    const headers = input instanceof Request ? new Headers(input.headers) : new Headers();

    // Merge headers from init (these override Request headers)
    if (init?.headers) {
      const initHeaders = new Headers(init.headers);
      initHeaders.forEach((value, key) => {
        headers.set(key, value);
      });
    }

    // Add telemetry header
    headers.set('Auth0-Client', headerValue);

    return baseFetch(input, { ...init, headers });
  };
}

// These constants are injected at build time via tsup
declare const __AUTH0_AUTH_JS_PACKAGE_NAME__: string;
declare const __AUTH0_AUTH_JS_PACKAGE_VERSION__: string;

export function getTelemetryConfig(config?: TelemetryConfig): TelemetryConfig {
  if (config?.enabled === false) {
    return config;
  }

  return {
    enabled: true,
    name: config?.name ?? __AUTH0_AUTH_JS_PACKAGE_NAME__,
    version: config?.version ?? __AUTH0_AUTH_JS_PACKAGE_VERSION__,
  };
}
