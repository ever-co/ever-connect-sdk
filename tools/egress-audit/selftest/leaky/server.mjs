// Fixture product "leaky", the failing control: at boot it looks up api.ever.co, opens a socket to
// 203.0.113.10 (a documentation address), sends a UDP datagram to the same address (a QUIC-style
// attempt) and sends a DNS question straight to 198.51.100.53 (another documentation address),
// bypassing the system resolver with a type the decoder lists rarely: what a module switched off
// must never do. The off mode must fail it, and must see the DNS query, the SYN and both datagrams.
import { createSocket } from 'node:dgram';
import { lookup } from 'node:dns/promises';
import { connect } from 'node:net';
import { log, serve } from '../lib/fixture.mjs';

/** A DNS question for `name` of type `qtype` (10 = NULL), recursion desired. */
function dnsQuestion(name, qtype) {
  const labels = name.split('.').map((l) => Buffer.concat([Buffer.from([l.length]), Buffer.from(l)]));
  return Buffer.concat([
    Buffer.from([0x45, 0x56, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]),
    ...labels,
    Buffer.from([0, qtype >> 8, qtype & 0xff, 0, 1]),
  ]);
}

function datagram(payload, port, host) {
  return new Promise((resolve) => {
    const socket = createSocket('udp4');
    socket.on('error', (error) => {
      log(`udp ${host}:${port}: ${error.code ?? error.message}`);
      socket.close();
      resolve();
    });
    socket.send(payload, port, host, () => {
      socket.close();
      resolve();
    });
  });
}

try {
  await lookup('api.ever.co');
} catch (error) {
  log(error.message);
}
await new Promise((resolve) => {
  const socket = connect({ host: '203.0.113.10', port: 443, timeout: 3000 });
  socket.on('connect', () => {
    socket.destroy();
    resolve();
  });
  socket.on('timeout', () => {
    log('connect 203.0.113.10:443 timed out');
    socket.destroy();
    resolve();
  });
  socket.on('error', (error) => {
    log(error.message);
    resolve();
  });
});
await datagram(Buffer.from('ever-audit-selftest'), 443, '203.0.113.10');
await datagram(dnsQuestion('api.ever.co', 10), 53, '198.51.100.53');
serve();
