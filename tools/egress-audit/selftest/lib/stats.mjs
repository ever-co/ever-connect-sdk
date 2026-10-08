// The statistics report of the fixture products: with statistics on, one signed golden report (a
// fixture of the statistics schema) posted to EVER_STATS_API_URL, signed with a statistics key
// generated at start.
import { generateKeyPairSync, sign } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { log, sleep, USER_AGENT } from './fixture.mjs';

export async function sendGoldenReport(reportFile) {
  const base = process.env.EVER_STATS_API_URL;
  if (process.env.EVER_STATS_ENABLED !== 'true' || !base) return;
  await sleep(Number(process.env.EVER_STATS_SEND_INTERVAL_S ?? 5) * 1000);
  const body = readFileSync(reportFile);
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
      return;
    } catch (error) {
      log(`statistics report failed: ${error.cause?.message ?? error.message}`);
      await sleep(2000);
    }
  }
}
