import { defineConfig } from 'tsup';

export default defineConfig({
  entry: ['src/index.ts'],
  format: ['esm', 'cjs'],
  dts: true,
  clean: true,
  sourcemap: false,
  target: 'node20',
  platform: 'node',
  external: ['@ever-co/connect-contracts', 'ajv'],
});
