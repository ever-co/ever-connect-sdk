// Fixture product "ui-link" for the browser leg: the toy web app with ./index.html as its page.
import { serveWeb } from '../lib/web.mjs';

serveWeb(new URL('./index.html', import.meta.url));
