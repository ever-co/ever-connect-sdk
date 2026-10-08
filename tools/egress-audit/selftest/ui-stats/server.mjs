// Fixture product "ui-stats", the browser leg's positive control: the toy web app whose page reads
// the statistics status route (GET /api/ever-stats/status), and, with statistics on, the golden
// statistics report posted like stats-sender, so the API leg of positive_stats passes too.
import { sendGoldenReport } from '../lib/stats.mjs';
import { serveWeb } from '../lib/web.mjs';

serveWeb(new URL('./index.html', import.meta.url));
await sendGoldenReport(new URL('../lib/stats-report.json', import.meta.url));
