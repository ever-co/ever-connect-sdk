// The seeded mutation corpus of the entitlement verifiers: every case is a valid fixture document
// with exactly one bit flipped in the decoded bytes of its header, payload or signature, encoded
// back as canonical base64url. No case can verify (each changes the signed bytes), and every
// verifier must answer the same code for each case. The Rust crate carries the same generator
// (crates/ever-connect-sdk/tests/verifier_differential.rs): the same seed gives the same corpus,
// which `corpus_sha256` in contracts/fixtures/entitlement/mutations.json pins.
import { createHash } from 'node:crypto';

export const MUTATION_SEED = 0x2e16_5eed;
export const MUTATION_COUNT = 10000;
/** The base documents, in order (case i mutates BASES[i % 2]). */
export const MUTATION_BASES = ['valid/instance.jws', 'valid/link.jws'];

/** One letter per verification code (the committed answers are one string). */
export const CODE_LETTERS = {
  malformed: 'm',
  bad_typ: 't',
  bad_alg: 'a',
  unknown_kid: 'k',
  bad_signature: 's',
  schema_violation: 'v',
  issuer_mismatch: 'i',
  audience_mismatch: 'u',
  instance_mismatch: 'n',
  subject_mismatch: 'b',
  iat_in_future: 'f',
  nbf_in_future: 'g',
  entitlement_stale: 'e',
};

/** mulberry32: a 32-bit generator simple enough to write the same way in every language. */
export function mulberry32(seed) {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1) >>> 0;
    t = ((t + Math.imul(t ^ (t >>> 7), t | 61)) ^ t) >>> 0;
    return (t ^ (t >>> 14)) >>> 0;
  };
}

/** The corpus: `[{base, jws}]` for the given base documents (texts, in MUTATION_BASES order). */
export function mutationCorpus(baseTexts, count = MUTATION_COUNT, seed = MUTATION_SEED) {
  const next = mulberry32(seed);
  const out = [];
  for (let i = 0; i < count; i += 1) {
    const base = i % baseTexts.length;
    const parts = baseTexts[base].split('.');
    const part = next() % 3;
    const bytes = Buffer.from(parts[part], 'base64url');
    const bit = next() % (bytes.length * 8);
    bytes[bit >> 3] ^= 1 << (bit & 7);
    parts[part] = bytes.toString('base64url');
    out.push({ base, jws: parts.join('.') });
  }
  return out;
}

/** sha256 of the corpus: every document followed by a line feed. */
export const corpusSha256 = (corpus) =>
  createHash('sha256')
    .update(corpus.map((c) => `${c.jws}\n`).join(''))
    .digest('hex');
