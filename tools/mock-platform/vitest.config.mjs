import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    include: ['test/**/*.test.mjs'],
    environment: 'node',
    testTimeout: 30000,
    fileParallelism: false,
  },
});
