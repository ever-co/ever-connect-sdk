// The self-test's adapter with a sign-in that fails: the API hooks of adapter.mjs, and a uiLogin
// that submits a wrong password and returns without checking where it ended (the mistake a product
// adapter can make). Every route then lands on the sign-in page, so the run must fault (exit 2).
export default {
  async login(ctx) {
    const res = await ctx.fetch(`${ctx.baseUrl}/healthz`);
    if (res.status !== 200) throw new Error(`health answered ${res.status}`);
    return {};
  },
  async createFixtures() {
    return { item: 'one' };
  },
  async openSettings(ctx) {
    await ctx.fetch(`${ctx.baseUrl}/healthz`, { headers: ctx.headers });
  },
  async uiLogin(page, ctx) {
    await page.goto(`${ctx.baseUrl}/sign-in`);
    await page.fill('input[name=email]', 'admin@example.test');
    await page.fill('input[name=password]', 'not-the-password');
    await page.click('button[type=submit]');
    await page.waitForLoadState('load');
  },
  async routeParams(ctx) {
    return { id: ctx.fixtures?.item ?? 'missing' };
  },
};
