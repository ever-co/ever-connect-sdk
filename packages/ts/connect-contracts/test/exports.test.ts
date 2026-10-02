import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import Ajv2020 from 'ajv/dist/2020.js';
import addFormats from 'ajv-formats';
import { describe, expect, it } from 'vitest';

const pkgDir = join(dirname(fileURLToPath(import.meta.url)), '..');
const pkg = JSON.parse(readFileSync(join(pkgDir, 'package.json'), 'utf8'));
const require = createRequire(import.meta.url);

describe('@ever-co/connect-contracts', () => {
  it('has no runtime dependencies and no side effects', () => {
    expect(Object.keys(pkg.dependencies ?? {})).toEqual([]);
    expect(Object.keys(pkg.peerDependencies ?? {})).toEqual([]);
    expect(pkg.sideEffects).toBe(false);
  });

  it('resolves through import (ESM) and require (CJS)', async () => {
    const esm = await import('@ever-co/connect-contracts');
    const cjs = require('@ever-co/connect-contracts');
    for (const mod of [esm, cjs]) {
      expect(mod.SCHEMAS.stats.$id).toBe('https://api.ever.co/v1/stats/schema/ever.stats.v1');
      expect(mod.INTEGRATIONS.stats_link.key).toBe('stats_link');
      expect(mod.CONSTANTS.stats_headers.key).toBe('Ever-Stats-Key');
      expect(mod.ROWS).toHaveLength(34);
      expect(mod.PROBLEM_CODES).toContain('code_invalid');
    }
  });

  it('ships fixtures and schemas as files that resolve through the exports map', () => {
    const gauzy = fileURLToPath(import.meta.resolve('@ever-co/connect-contracts/fixtures/stats/valid/gauzy.json'));
    expect(JSON.parse(readFileSync(gauzy, 'utf8')).product).toBe('gauzy');
    const schema = fileURLToPath(import.meta.resolve('@ever-co/connect-contracts/schemas/ever.consent.v1.json'));
    expect(JSON.parse(readFileSync(schema, 'utf8')).title).toMatch(/consent record/);
    const def = fileURLToPath(import.meta.resolve('@ever-co/connect-contracts/integrations/stats_link.json'));
    expect(JSON.parse(readFileSync(def, 'utf8')).key).toBe('stats_link');
  });

  it('never exposes a hidden catalog key', async () => {
    const { INTEGRATIONS, INTEGRATION_KEYS, CONSTANTS } = await import('@ever-co/connect-contracts');
    expect(Object.keys(INTEGRATIONS)).not.toContain('ever_agent');
    expect(INTEGRATION_KEYS).not.toContain('ever_agent');
    expect(CONSTANTS.integration_keys).not.toContain('ever_agent');
  });

  it('validates the redeem fixture against the contract schema the package exports', async () => {
    const ajv = new Ajv2020({ strict: false, allErrors: true });
    addFormats(ajv);
    const spec = JSON.parse(readFileSync(join(pkgDir, '..', '..', '..', 'contracts/generated/ever-platform.v1.json'), 'utf8'));
    ajv.addSchema({ $id: 'https://ever-connect-sdk.invalid/contract.json', components: { schemas: spec.components.schemas } });
    const validate = ajv.getSchema('https://ever-connect-sdk.invalid/contract.json#/components/schemas/RedeemRequest');
    const fixture = (name: string) =>
      JSON.parse(readFileSync(fileURLToPath(import.meta.resolve(`@ever-co/connect-contracts/fixtures/requests/${name}`)), 'utf8'));
    expect(validate?.(fixture('redeem.json'))).toBe(true);
    expect(validate?.(fixture('redeem.invalid-null-id.json'))).toBe(false);
    expect(validate?.errors?.some((e) => e.instancePath === '/tenant/product_org_id')).toBe(true);
  });

  it('isProblem recognises a problem document with a contract code', async () => {
    const { isProblem, problemType } = await import('@ever-co/connect-contracts');
    expect(
      isProblem({
        type: problemType('code_invalid'),
        title: 'Unprocessable Content',
        status: 422,
        code: 'code_invalid',
        detail: 'code_invalid: the code is not valid',
      }),
    ).toBe(true);
    expect(isProblem({ type: 'x', title: 'y', status: 422, code: 'made_up', detail: 'z' })).toBe(false);
  });
});

describe('in-product consent (step-up)', () => {
  it('a sign-in at most 300 s old is fresh; 301 s is not', async () => {
    const { isStepUpFresh, STEP_UP_MAX_AGE_S } = await import('@ever-co/connect-contracts');
    const now = 1_793_613_600;
    expect(STEP_UP_MAX_AGE_S).toBe(300);
    expect(isStepUpFresh({ auth_time: now - 300 }, now)).toBe(true);
    expect(isStepUpFresh({ auth_time: now - 301 }, now)).toBe(false);
    expect(isStepUpFresh({ auth_time: now + 120 }, now)).toBe(false);
  });

  it('instance_url and counterparty_discoverable never take an in-product consent', async () => {
    const { stepUpAllowed, INTEGRATION_KEYS } = await import('@ever-co/connect-contracts');
    expect(stepUpAllowed('instance_url')).toBe(false);
    expect(stepUpAllowed('counterparty_discoverable')).toBe(false);
    for (const key of INTEGRATION_KEYS.filter((k) => !['instance_url', 'counterparty_discoverable'].includes(k)))
      expect(stepUpAllowed(key)).toBe(true);
  });

  it('the consent schema accepts product_ui and the grant fixture validates', async () => {
    const { SCHEMAS } = await import('@ever-co/connect-contracts');
    const ajv = new Ajv2020({ strict: false, allErrors: true });
    addFormats(ajv);
    const validate = ajv.compile(SCHEMAS.consent);
    const record = JSON.parse(
      readFileSync(fileURLToPath(import.meta.resolve('@ever-co/connect-contracts/fixtures/consent/valid/product-ui.json')), 'utf8'),
    );
    expect(record.consent_source).toBe('product_ui');
    expect(validate(record)).toBe(true);
    expect(validate({ ...record, integration_key: 'instance_url' })).toBe(false);
  });

  it('every consent screen renders the seven blocks from the definition data', async () => {
    const { INTEGRATION_KEYS, INTEGRATIONS } = await import('@ever-co/connect-contracts');
    for (const key of INTEGRATION_KEYS) {
      const screen = JSON.parse(
        readFileSync(fileURLToPath(import.meta.resolve(`@ever-co/connect-contracts/fixtures/consent-screen/${key}.json`)), 'utf8'),
      );
      const blocks = Object.keys(screen.blocks);
      for (const b of [
        'title',
        'purpose',
        'leaves_installation',
        'platform_keeps',
        'how_often',
        'where_to_change',
        'legal',
        'authorisation',
      ])
        expect(blocks).toContain(b);
      expect(screen.blocks.purpose).toBe(INTEGRATIONS[key].description);
    }
  });
});
