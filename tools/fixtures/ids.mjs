// Deterministic identifiers for fixtures: the same label always gives the same id.
import { createHash } from 'node:crypto';

const CROCKFORD = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
const digest = (label) => createHash('sha256').update(`ever-connect-sdk/fixture/${label}`).digest();

/** A ULID-shaped id (26 Crockford base32 characters) derived from a label. */
export function ulid(label) {
  const bytes = digest(label);
  let out = '01J';
  for (let i = 0; out.length < 26; i += 1) out += CROCKFORD[bytes[i] % 32];
  return out;
}

/** A UUID v4-shaped id derived from a label. */
export function uuid(label) {
  const b = Buffer.from(digest(label).subarray(0, 16));
  b[6] = (b[6] & 0x0f) | 0x40;
  b[8] = (b[8] & 0x3f) | 0x80;
  const h = b.toString('hex');
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
}

/** A hex SHA-256 of a label (stands in for salted hashes). */
export const hex64 = (label) => digest(label).toString('hex');

/** The fixed clock of every fixture: 2026-11-02T10:00:00Z. */
export const NOW = Date.UTC(2026, 10, 2, 10, 0, 0) / 1000;

export const iso = (seconds) => new Date(seconds * 1000).toISOString().replace(/\.\d{3}Z$/, 'Z');
