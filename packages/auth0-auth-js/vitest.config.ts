import { defineConfig, configDefaults } from 'vitest/config';
import { readFileSync } from 'node:fs';

const packageJson = JSON.parse(readFileSync('./package.json', 'utf-8'));

export default defineConfig({
  test: {
    setupFiles: ['@auth0/test-utils/localstorage-polyfill'],
    exclude: [...configDefaults.exclude, 'src/**/*.workers.spec.ts'],
    coverage: {
      provider: 'v8',
    },
  },
  define: {
    __AUTH0_AUTH_JS_PACKAGE_NAME__: JSON.stringify(packageJson.name),
    __AUTH0_AUTH_JS_PACKAGE_VERSION__: JSON.stringify(packageJson.version),
  },
});
