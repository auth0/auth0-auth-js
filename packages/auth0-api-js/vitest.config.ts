import { defineConfig, configDefaults } from 'vitest/config';

export default defineConfig({
  test: {
    exclude: [...configDefaults.exclude, 'src/**/*.workers.spec.ts'],
    coverage: {
      provider: 'v8',
    },
  },
});
