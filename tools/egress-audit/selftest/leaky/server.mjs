// Fixture product "leaky", the failing control: at boot it looks up api.ever.co and opens a socket
// to 203.0.113.10 (a documentation address), what a module switched off must never do. The off mode
// must fail it, and must see both the DNS query and the connection attempt.
import { lookup } from 'node:dns/promises';
import { connect } from 'node:net';
import { log, serve } from '../lib/fixture.mjs';

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
serve();
