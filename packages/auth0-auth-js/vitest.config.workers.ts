import { defineConfig } from 'vitest/config';
import { readFileSync } from 'node:fs';

const packageJson = JSON.parse(readFileSync('./package.json', 'utf-8'));

export default defineConfig({
  define: {
    __AUTH0_AUTH_JS_PACKAGE_NAME__: JSON.stringify(packageJson.name),
    __AUTH0_AUTH_JS_PACKAGE_VERSION__: JSON.stringify(packageJson.version),
  },
  test: {
    pool: '@cloudflare/vitest-pool-workers',
    poolOptions: {
      workers: {
        wrangler: { configPath: './wrangler.toml' },
      },
    },
    setupFiles: ['./src/test-utils/workers-polyfills.ts'],
    include: ['src/**/*.spec.ts'],
  },
});
