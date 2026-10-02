import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    include: ['test/**/*.test.mjs', 'test/**/*.test.ts'],
    environment: 'node',
    testTimeout: 30000,
    fileParallelism: false,
  },
});
