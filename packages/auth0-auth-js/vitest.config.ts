import { defineConfig } from 'vitest/config';
import { readFileSync } from 'fs';

const packageJson = JSON.parse(readFileSync('./package.json', 'utf-8'));

export default defineConfig({
  test: {
    coverage: {
      provider: 'v8',
    },
  },
  define: {
    __AUTH0_AUTH_JS_PACKAGE_NAME__: JSON.stringify(packageJson.name),
    __AUTH0_AUTH_JS_PACKAGE_VERSION__: JSON.stringify(packageJson.version),
  },
});
