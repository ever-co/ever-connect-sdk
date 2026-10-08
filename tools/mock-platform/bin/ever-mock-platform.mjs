#!/usr/bin/env node
// ever-mock-platform: the Ever Platform API mock for product CI.
//
//   ever-mock-platform [--port 8080] [--host 0.0.0.0] [--config mock.config.json]
//                      [--record requests.jsonl] [--state-out state.json] [--fixed-clock]
//
// The clock follows real time from start, so products can sign with their own clock; a config
// with a `clock` entry, or --fixed-clock, keeps the deterministic clock of the tests instead.
//
// Controls: GET /__mock/requests, GET /__mock/state, POST /__mock/reset, POST /__mock/clock and the
// other /__mock/* routes (see docs/mock-platform.md).
import { readFileSync, writeFileSync } from 'node:fs';
import { createMockPlatform } from '../src/server.mjs';

const args = process.argv.slice(2);
const arg = (name, fallback) => {
  const i = args.indexOf(`--${name}`);
  return i >= 0 ? args[i + 1] : fallback;
};
if (args.includes('--help') || args.includes('-h')) {
  process.stdout.write(
    'ever-mock-platform [--port 8080] [--host 0.0.0.0] [--config <file>] [--record <file.jsonl>] [--state-out <file.json>] [--fixed-clock]\n' +
      'Answers every outbound call of the Ever Platform modules with the platform contract; controls under /__mock/*.\n',
  );
  process.exit(0);
}
// The configuration comes from --config <file>, or from EVER_MOCK_CONFIG_JSON (containers that get
// no mounted file, such as the egress harness overlay).
const config = arg('config')
  ? JSON.parse(readFileSync(arg('config'), 'utf8'))
  : process.env.EVER_MOCK_CONFIG_JSON
    ? JSON.parse(process.env.EVER_MOCK_CONFIG_JSON)
    : {};
if (config.clock === undefined && !args.includes('--fixed-clock')) config.clock = { real: true };
const mock = createMockPlatform({ config, record: arg('record', null), log: (m) => process.stderr.write(`${m}\n`) });
const port = Number(arg('port', process.env.PORT ?? 8080));
const host = arg('host', process.env.HOST ?? '0.0.0.0');
const { url } = await mock.listen(port, host);
process.stdout.write(`ever-mock-platform: listening on ${url} (issuer ${mock.config.issuer})\n`);
if (!String(mock.config.issuer).startsWith('https://'))
  process.stderr.write(
    `ever-mock-platform: the issuer ${mock.config.issuer} is not https: no entitlement document it signs verifies (the schema takes https issuers only)\n`,
  );
const stateOut = arg('state-out', null);
const stop = async () => {
  if (stateOut) {
    const res = await fetch(`http://127.0.0.1:${port}/__mock/state`).catch(() => null);
    if (res) writeFileSync(stateOut, `${JSON.stringify(await res.json(), null, 2)}\n`);
  }
  await mock.close();
  process.exit(0);
};
process.on('SIGTERM', stop);
process.on('SIGINT', stop);
