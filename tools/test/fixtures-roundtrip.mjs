#!/usr/bin/env node
/**
 * Fixture round trip, TypeScript side: validates every schema-bound fixture of
 * contracts/fixtures/index.json with ajv (strict for the JSON Schemas; the OpenAPI component
 * schemas carry OpenAPI-only keywords, so they compile non-strict), re-serializes the valid ones,
 * writes target/fixture-verdicts/ts.json, and compares with the verdicts of the Rust side
 * (target/fixture-verdicts/rust.json, written by `cargo test -p ever-connect-contracts --test
 * fixtures_roundtrip`; this script runs that test when the file is missing). Any disagreement
 * fails.
 */
import { execFileSync } from 'node:child_process';
import { existsSync, mkdirSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import Ajv2020 from 'ajv/dist/2020.js';
import addFormats from 'ajv-formats';
import { REPO } from '../lib/common.mjs';

const read = (p) => JSON.parse(readFileSync(join(REPO, p), 'utf8'));
const CONTRACT = 'https://ever-connect-sdk.invalid/contract.json';

function validators() {
  const strict = new Ajv2020({ strict: true, strictTypes: false, allErrors: true, allowUnionTypes: true });
  const loose = new Ajv2020({ strict: false, allErrors: true, allowUnionTypes: true });
  for (const ajv of [strict, loose]) addFormats(ajv);
  const docs = {};
  for (const [key, file] of [
    ['stats', 'ever.stats.v1.json'],
    ['entitlement', 'ever.entitlement.v1.json'],
    ['consent', 'ever.consent.v1.json'],
    ['keyManifest', 'ever.key-manifest.v1.json'],
  ]) {
    const schema = read(`contracts/schemas/${file}`);
    strict.addSchema(schema);
    docs[key] = schema.$id;
  }
  const events = {};
  let envelope = null;
  for (const file of readdirSync(join(REPO, 'contracts/schemas/events')).sort()) {
    const schema = read(`contracts/schemas/events/${file}`);
    strict.addSchema(schema);
    if (file === 'envelope.schema.json') envelope = schema.$id;
    else if (file.endsWith('.v1.schema.json')) events[file.slice(0, -'.v1.schema.json'.length)] = schema.$id;
  }
  const spec = read('contracts/generated/ever-platform.v1.json');
  loose.addSchema({ $id: CONTRACT, components: { schemas: spec.components.schemas } });
  const pending = {};
  for (const op of read('contracts/openapi/pending-upstream.json').operations)
    if (op.request) pending[op.operation_id] = strict.compile(op.request);
  return {
    component: (name) => loose.getSchema(`${CONTRACT}#/components/schemas/${name}`),
    pending: (id) => pending[id],
    doc: (key) => strict.getSchema(docs[key]),
    envelope: () => strict.getSchema(envelope),
    event: (type) => strict.getSchema(events[type]),
  };
}

export function tsVerdicts() {
  const v = validators();
  const verdicts = {};
  const problems = [];
  for (const entry of read('contracts/fixtures/index.json').fixtures) {
    const text = readFileSync(join(REPO, 'contracts/fixtures', entry.file), 'utf8');
    const doc = JSON.parse(text);
    let valid;
    if (entry.kind === 'component') valid = v.component(entry.schema)(doc);
    else if (entry.kind === 'pending') valid = v.pending(entry.schema)(doc);
    else if (entry.kind === 'schema') valid = v.doc(entry.schema)(doc);
    else if (entry.kind === 'feed')
      valid = v.component('FeedResponse')(doc) && doc.events.every((e) => v.envelope()(e) && v.event(entry.schema)(e.data));
    else throw new Error(`${entry.file}: unknown kind ${entry.kind}`);
    verdicts[entry.file] = valid;
    if (valid !== entry.valid) problems.push(`${entry.file}: ajv says valid=${valid}, the index says ${entry.valid}`);
    if (valid && entry.typed && JSON.stringify(JSON.parse(JSON.stringify(doc))) !== JSON.stringify(doc))
      problems.push(`${entry.file}: does not survive a JSON round trip`);
  }
  return { verdicts, problems };
}

function main() {
  const { verdicts, problems } = tsVerdicts();
  const out = join(REPO, 'target', 'fixture-verdicts');
  mkdirSync(out, { recursive: true });
  writeFileSync(join(out, 'ts.json'), `${JSON.stringify(verdicts, null, 2)}\n`);
  const rustPath = join(out, 'rust.json');
  if (!existsSync(rustPath) || process.argv.includes('--run-cargo')) {
    execFileSync(
      process.env.CARGO ?? 'cargo',
      ['test', '--quiet', '--locked', '-p', 'ever-connect-contracts', '--test', 'fixtures_roundtrip'],
      { cwd: REPO, stdio: 'inherit' },
    );
  }
  const rust = JSON.parse(readFileSync(rustPath, 'utf8'));
  for (const file of new Set([...Object.keys(verdicts), ...Object.keys(rust)])) {
    if (rust[file] !== verdicts[file]) problems.push(`${file}: TypeScript says ${verdicts[file]}, Rust says ${rust[file]}`);
  }
  if (problems.length > 0) {
    process.stderr.write(`fixtures-roundtrip: ${problems.length} disagreement(s):\n  ${problems.join('\n  ')}\n`);
    process.exit(1);
  }
  const count = Object.keys(verdicts).length;
  const valid = Object.values(verdicts).filter(Boolean).length;
  process.stdout.write(`fixtures-roundtrip: ok (${count} fixtures, ${valid} valid, ${count - valid} invalid; TypeScript and Rust agree)\n`);
}

if (process.argv[1]?.endsWith('fixtures-roundtrip.mjs')) main();
