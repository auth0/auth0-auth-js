import { defineConfig, configDefaults } from 'vitest/config';

export default defineConfig({
  test: {
    setupFiles: ['@auth0/test-utils/localstorage-polyfill'],
    exclude: [...configDefaults.exclude, 'src/**/*.workers.spec.ts'],
    coverage: {
      provider: 'v8',
    },
  },
});
