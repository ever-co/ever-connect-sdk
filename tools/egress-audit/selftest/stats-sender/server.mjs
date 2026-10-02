// Fixture product "stats-sender": with statistics on, it posts one signed fixture report (a golden
// of the statistics schema, report.json) to EVER_STATS_API_URL, signed with a statistics key it
// generates at start. The positive_stats mode must pass it with the mock platform, and fail it
// without one.
import { generateKeyPairSync, sign } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { log, serve, sleep, USER_AGENT } from '../lib/fixture.mjs';

serve();

const base = process.env.EVER_STATS_API_URL;
if (process.env.EVER_STATS_ENABLED === 'true' && base) {
  await sleep(Number(process.env.EVER_STATS_SEND_INTERVAL_S ?? 5) * 1000);
  const body = readFileSync(new URL('./report.json', import.meta.url));
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const headers = {
    'content-type': 'application/json',
    'user-agent': USER_AGENT,
    'ever-stats-key': publicKey.export({ format: 'jwk' }).x,
    'ever-stats-signature': `ed25519=${sign(null, body, privateKey).toString('base64url')}`,
  };
  for (let attempt = 1; attempt <= 3; attempt += 1) {
    try {
      const res = await fetch(`${base}/v1/stats/reports`, { method: 'POST', headers, body });
      log(`statistics report: ${res.status}`);
      break;
    } catch (error) {
      log(`statistics report failed: ${error.cause?.message ?? error.message}`);
      await sleep(2000);
    }
  }
}
