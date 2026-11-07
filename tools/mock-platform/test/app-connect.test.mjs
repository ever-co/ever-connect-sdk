// An App outside the six products connects as the platform lets it: product `app:<app id>` with
// `kind: app`, no served product, with a code minted for that App; its documents name no product.
import { describe, expect, test } from 'vitest';
import { testKey } from '../src/keys.mjs';
import { expectOk, expectProblem, startMock } from './helpers.mjs';

const APP = 'app:01JMQCK0APP0000000000000A1';
const OTHER_APP = 'app:01JMQCK0APP0000000000000B2';

const redeem = (code, extra = {}) => ({
  code,
  product: APP,
  kind: 'app',
  version: '1.4.0',
  install_source: 'self-hosted',
  public_jwk: { kty: 'OKP', crv: 'Ed25519', x: testKey('connectNext').x },
  ...extra,
});

describe('an App connects', () => {
  test('as kind app with its own code, serving no product', async () => {
    const env = await startMock();
    try {
      await env.admin('codes', { code: 'EVC-APPS-0000-0001', product: APP });
      const post = (body, key) => env.call('POST', '/v1/connect/redeem', { body, headers: { 'idempotency-key': key } });
      // The kind and the served products must fit an App; nothing is consumed by these.
      const asSelfHosted = await post(redeem('EVC-APPS-0000-0001', { kind: 'self_hosted' }), 'a1');
      expectProblem(expect, asSelfHosted, 422, 'validation_failed');
      expect(asSelfHosted.body.errors[0].path).toBe('/kind');
      const serving = await post(redeem('EVC-APPS-0000-0001', { serves_products: ['gauzy'] }), 'a2');
      expectProblem(expect, serving, 422, 'validation_failed');
      expect(serving.body.errors[0].path).toBe('/serves_products');
      const productAsApp = await post(redeem('EVC-TEST-0000-0001', { product: 'gauzy' }), 'a3');
      expectProblem(expect, productAsApp, 422, 'validation_failed');
      expect(productAsApp.body.errors[0].path).toBe('/kind');
      // A code minted for another App.
      const mismatch = await post(redeem('EVC-APPS-0000-0001', { product: OTHER_APP }), 'a4');
      expectProblem(expect, mismatch, 422, 'product_mismatch');
      // The App connects, with its first link.
      const connected = await post(
        redeem('EVC-APPS-0000-0001', { tenant: { product_tenant_id: 'workspace-1', display_name: 'Front desk' } }),
        'a5',
      );
      expectOk(expect, connected, 201, 'connectRedeem');
      const instance = env.state.instance(connected.body.instance_id);
      expect(instance.kind).toBe('app');
      expect(instance.product).toBe(APP);
      expect(instance.serves_products).toEqual([]);
      expect(connected.body.link.product).toBe(APP);
    } finally {
      await env.close();
    }
  });
});
