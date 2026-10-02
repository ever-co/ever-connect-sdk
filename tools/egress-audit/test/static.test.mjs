// The static helpers: no Ever host outside the allowed directories, and no module that guesses
// where it runs.
import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { scanInference } from '../cloud-inference.mjs';
import { allowed, scanHostnames } from '../static-hostnames.mjs';

function tree(files) {
  const root = mkdtempSync(join(tmpdir(), 'ever-static-'));
  for (const [path, text] of Object.entries(files)) {
    mkdirSync(join(root, path, '..'), { recursive: true });
    writeFileSync(join(root, path), text);
  }
  return root;
}

test('static-hostnames: an Ever host outside the allowed directories is found', () => {
  const root = tree({
    'packages/ever-connect/src/client.ts': "const base = 'https://api.ever.co';\n",
    'apps/api/src/telemetry.ts': "fetch('https://api.ever.co/v1/x');\n",
    'apps/api/src/telemetry.test.ts': "expect(url).toBe('https://api.ever.co');\n",
    'apps/api/.env.example': 'EVER_PLATFORM_API_URL=\n',
    'docs/guide.md': 'see https://app.ever.co\n',
    'README.txt': 'api.ever.co\n',
  });
  const findings = scanHostnames(root, ['packages/ever-connect', '**/*.test.*']);
  assert.deepEqual(findings.sort(), ['apps/api/.env.example:1', 'apps/api/src/telemetry.ts:1']);
});

test('static-hostnames: the allow patterns', () => {
  assert.ok(allowed('packages/ever-connect/src/a.ts', ['packages/ever-connect/']));
  assert.ok(allowed('apps/api/src/a.test.ts', ['**/*.test.*']));
  assert.ok(allowed('a.test.ts', ['**/*.test.*']));
  assert.ok(!allowed('apps/api/src/a.ts', ['**/*.test.*', 'packages/ever-connect']));
  assert.ok(!allowed('packages/ever-connector/a.ts', ['packages/ever-connect']));
});

test('cloud-inference: every rule fires inside a module, tests excepted', () => {
  const root = tree({
    'module/src/a.ts': [
      'const k = process.env.STRIPE_SECRET_KEY;',
      'if (process.env.DEMO) {}',
      'const p = process.env.CLOUD_PROVIDER;',
      "const d = '/srv/gauzy/data';",
      'if (process.env.IS_ELECTRON) {}',
      'const h = os.hostname();',
      "const ok = process.env.EVER_INSTALL_SOURCE ?? 'self-hosted';",
    ].join('\n'),
    'module/src/a.test.ts': 'process.env.STRIPE_SECRET_KEY',
  });
  const findings = scanInference(['module'], root).map((f) => f.split(': ')[1]);
  assert.deepEqual(findings, ['payment-secret', 'demo-flag', 'cloud-provider', 'deployment-path', 'desktop-flag', 'host-name']);
});
