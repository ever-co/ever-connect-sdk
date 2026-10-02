// Copies the contract files this package ships (fixtures, schemas, integration definitions) from
// the repository's contracts/ directory into the package, so the `./fixtures/*`, `./schemas/*`
// and `./integrations/*` exports resolve. The copies are build output and git-ignored.
import { cpSync, rmSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const pkg = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const contracts = resolve(pkg, '..', '..', '..', 'contracts');
for (const dir of ['fixtures', 'schemas', 'integrations']) {
  rmSync(join(pkg, dir), { recursive: true, force: true });
  cpSync(join(contracts, dir), join(pkg, dir), { recursive: true });
}
for (const tooling of ['overrides.json', 'scope-versions.lock.json']) rmSync(join(pkg, 'integrations', tooling), { force: true });
