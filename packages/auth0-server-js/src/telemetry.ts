import { TelemetryConfig } from '@auth0/auth0-auth-js';

// These constants are injected at build time via tsup
declare const __AUTH0_SERVER_JS_PACKAGE_NAME__: string;
declare const __AUTH0_SERVER_JS_PACKAGE_VERSION__: string;

export function getTelemetryConfig(config?: TelemetryConfig): TelemetryConfig {
  if (config?.enabled === false) {
    return config;
  }

  return {
    enabled: true,
    name: config?.name ?? __AUTH0_SERVER_JS_PACKAGE_NAME__,
    version: config?.version ?? __AUTH0_SERVER_JS_PACKAGE_VERSION__,
  };
}
