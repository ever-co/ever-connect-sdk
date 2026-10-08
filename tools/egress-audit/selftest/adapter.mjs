// The self-test's adapter. A product adapter signs in, creates what a user would create and opens
// the pages that render the module UI; the fixture products have only a health endpoint (and the
// web fixtures a sign-in page), so the API hooks check that the product answers from inside the
// sealed network, and the browser hooks sign in through the web fixture's form.
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
  // Browser leg: the real sign-in form, as a person would use it.
  async uiLogin(page, ctx) {
    await page.goto(`${ctx.baseUrl}/sign-in`);
    await page.fill('input[name=email]', 'admin@example.test');
    await page.fill('input[name=password]', 'selftest-password-0e6a');
    await Promise.all([page.waitForURL(`${ctx.baseUrl}/`), page.click('button[type=submit]')]);
  },
  // A value only the run knows (here: what createFixtures answered).
  async routeParams(ctx) {
    return { id: ctx.fixtures?.item ?? 'missing' };
  },
};
