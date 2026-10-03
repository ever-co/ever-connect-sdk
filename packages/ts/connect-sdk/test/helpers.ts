// Shared test helpers: the fixture paths and TEST keys derived from public seeds (they sign nothing
// anyone trusts; the fixtures are built from the same seeds).
import { createHash, createPrivateKey, sign } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

export const REPO = join(dirname(fileURLToPath(import.meta.url)), '..', '..', '..', '..');
export const FIXTURES = join(REPO, 'contracts', 'fixtures');
// biome-ignore lint/suspicious/noExplicitAny: fixtures are JSON of many shapes; each test names the one it reads.
export const fixture = <T = any>(path: string): T => JSON.parse(readFileSync(join(FIXTURES, path), 'utf8'));
export const fixtureText = (path: string): string => readFileSync(join(FIXTURES, path), 'utf8');

const PKCS8_ED25519 = Buffer.from('302e020100300506032b657004220420', 'hex');

/** The private key of a TEST key: seed = sha256("ever-connect-sdk/<label>"). */
export function testPrivateKey(label: string) {
  const seed = createHash('sha256').update(`ever-connect-sdk/${label}`).digest();
  return createPrivateKey({ key: Buffer.concat([PKCS8_ED25519, seed]), format: 'der', type: 'pkcs8' });
}

export const b64 = (v: unknown) => Buffer.from(typeof v === 'string' ? v : JSON.stringify(v)).toString('base64url');

/** A compact JWS with an exact header (no defaults added), signed by a TEST key. */
export function signRaw(label: string, header: Record<string, unknown>, payload: Record<string, unknown>): string {
  const input = `${b64(header)}.${b64(payload)}`;
  return `${input}.${sign(null, Buffer.from(input), testPrivateKey(label)).toString('base64url')}`;
}
