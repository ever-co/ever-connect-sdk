// Fixture product "stats-sender": with statistics on, it posts one signed fixture report (a golden
// of the statistics schema, report.json) to EVER_STATS_API_URL, signed with a statistics key it
// generates at start. The positive_stats mode must pass it with the mock platform, and fail it
// without one.
import { serve } from '../lib/fixture.mjs';
import { sendGoldenReport } from '../lib/stats.mjs';

serve();
await sendGoldenReport(new URL('./report.json', import.meta.url));
