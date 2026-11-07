# App Launcher data

The SDK helps a product show the App Launcher (`<ever-app-launcher>`) in its header: the Ever apps, and the apps of
the person's organization from Ever Platform. It only prepares the data; the product renders the element and makes
the organization calls with its own token.

## What it calls

| Call | When | Credentials | Off |
|---|---|---|---|
| `GET <Ever Works API>/api/app-launcher/platforms` | `loadLauncherCatalog()`, when the product asks | none (`credentials: "omit"`), 2 s timeout | the product does not call it |

Nothing else. When the catalog cannot be read (unreachable, slow, not the catalog's shape), `loadLauncherCatalog()`
returns the bundled snapshot instead (`launcherSnapshot()`), so the Ever apps always render. A product without an
address yet is listed as "not live" and never linked.

The organization's apps come from two Ever Platform reads **the product** makes, with the signed-in person's token
exchanged for the `apps:read` scope (RFC 8693 at Ever ID): `GET /v1/orgs/{org}/installs` (what the organization
installed from apps.ever.co) and `GET /v1/orgs/{org}/apps` (its apps). Ever Platform answers them only for an
organization the person belongs to, and the token reaches nothing else.

## Using it

```ts
import { loadLauncherCatalog, mapApps, mapInstalls, mergeLauncherResponse } from '@ever-co/connect-sdk';

const catalog = await loadLauncherCatalog('https://api.ever.works', { environment: 'production' });
const data = mergeLauncherResponse({
  catalog,
  installs: mapInstalls(installPage.items),
  apps: mapApps(appPage.items),
  current: 'platform:ever-gauzy',
  scopeKey: `org:${orgId}`,
});
launcherElement.data = data;
```

- `mapInstalls(installs, addressOf?)`: installs that are `installed` or `delivered` and have an `https` address
  (`next_action_url` unless the product resolves the listing's address itself) become tiles under "Your apps".
- `mapApps(apps)`: live apps with an `https` deployment address (production first); a deployment still going out
  shows "deploying", a failed one "last deploy failed".
- `mergeLauncherResponse()`: the Ever apps first, then the installs and the apps, one tile per key; `current` marks
  the product's own tile.

The launcher opens addresses only: an install or an app without an `https` address is left out.
