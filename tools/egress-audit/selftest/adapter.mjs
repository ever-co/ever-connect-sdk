// The self-test's adapter. A product adapter signs in, creates what a user would create and opens
// the pages that render the module UI; the fixture products have only a health endpoint, so the
// hooks check that the product answers from inside the sealed network.
export default {
  async login(ctx) {
    const res = await ctx.fetch(`${ctx.baseUrl}/healthz`);
    if (res.status !== 200) throw new Error(`health answered ${res.status}`);
    return {};
  },
  async openSettings(ctx) {
    await ctx.fetch(`${ctx.baseUrl}/healthz`, { headers: ctx.headers });
  },
};
