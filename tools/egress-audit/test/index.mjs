// `node --test tools/egress-audit/test/` runs this directory as one module (package.json "main"):
// every *.test.mjs file here. `pnpm test` in tools/egress-audit runs the same files by glob.
import { readdirSync } from 'node:fs';

for (const file of readdirSync(new URL('.', import.meta.url))
  .filter((f) => f.endsWith('.test.mjs'))
  .sort())
  await import(new URL(file, import.meta.url));
