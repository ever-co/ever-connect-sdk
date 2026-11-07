import { describe, expect, it } from 'vitest';
import {
  type AppLauncherPlatformsResponse,
  isLauncherItem,
  LAUNCHER_SNAPSHOT_VERSION,
  launcherSnapshot,
  loadLauncherCatalog,
  mapApps,
  mapInstalls,
  mergeLauncherResponse,
} from '../src/index';

const CATALOG: AppLauncherPlatformsResponse = {
  catalogVersion: '2026-11-01',
  environment: 'production',
  platforms: [
    {
      key: 'platform:ever-gauzy',
      kind: 'platform',
      section: 'platforms',
      name: 'Ever Gauzy',
      url: 'https://app.gauzy.co/',
      host: 'app.gauzy.co',
      visible: true,
      pinned: false,
      pinOrder: null,
      order: 0,
      manageState: 'listed',
    },
  ],
};

describe('the catalog', () => {
  it('reads Ever Works without credentials and keeps only items it may show', async () => {
    const seen: { url: string; init?: RequestInit }[] = [];
    const catalog = await loadLauncherCatalog('https://api.ever.works/', {
      fetch: async (url, init) => {
        seen.push({ url, init });
        const unsafe = { ...CATALOG.platforms[0], key: 'platform:x', url: 'http://plain.example' };
        return new Response(JSON.stringify({ ...CATALOG, platforms: [...CATALOG.platforms, unsafe] }));
      },
    });
    expect(seen[0].url).toBe('https://api.ever.works/api/app-launcher/platforms');
    expect(seen[0].init?.credentials).toBe('omit');
    expect(catalog.catalogVersion).toBe('2026-11-01');
    expect(catalog.platforms.map((p) => p.key)).toEqual(['platform:ever-gauzy']);
  });

  it('falls back to the bundled snapshot when Ever Works cannot be read', async () => {
    for (const fetch of [
      async () => new Response('nope', { status: 503 }),
      async () => new Response('not json'),
      async () => {
        throw new TypeError('fetch failed');
      },
    ]) {
      const catalog = await loadLauncherCatalog('https://api.ever.works', { fetch, environment: 'stage' });
      expect(catalog.catalogVersion).toBe(LAUNCHER_SNAPSHOT_VERSION);
      expect(catalog.environment).toBe('stage');
      expect(catalog.platforms.length).toBeGreaterThan(0);
    }
  });

  it('gives up after the timeout', async () => {
    const catalog = await loadLauncherCatalog('https://api.ever.works', {
      timeoutMs: 20,
      fetch: (_url, init) =>
        new Promise((_resolve, reject) => {
          init?.signal?.addEventListener('abort', () => reject(new Error('aborted')));
        }),
    });
    expect(catalog.catalogVersion).toBe(LAUNCHER_SNAPSHOT_VERSION);
  });

  it('the snapshot never links a product without an address', () => {
    for (const item of launcherSnapshot('production').platforms) {
      expect(isLauncherItem(item), item.key).toBe(true);
      if (item.url === null) expect(item.manageState).toBe('notLive');
    }
  });
});

describe('the organization feeds', () => {
  it('maps installed or delivered installs that have an address', () => {
    const items = mapInstalls([
      {
        id: 'i1',
        listing_slug: 'cal',
        listing_title: 'Cal',
        listing_type: 'app',
        state: 'installed',
        next_action_url: 'https://cal.example/',
      },
      { id: 'i2', listing_slug: 'x', listing_title: 'X', listing_type: 'app', state: 'requested', next_action_url: 'https://x.example/' },
      { id: 'i3', listing_slug: 'y', listing_title: 'Y', listing_type: 'app', state: 'delivered', next_action_url: null },
      { id: 'i4', listing_slug: 'z', listing_title: 'Z', listing_type: 'app', state: 'installed', next_action_url: 'http://z.example/' },
    ]);
    expect(items.map((i) => [i.key, i.name, i.url])).toEqual([['install:i1', 'Cal', 'https://cal.example/']]);
    expect(items[0]).toMatchObject({ kind: 'work', section: 'works', manageState: 'listed' });
  });

  it('maps live apps by their production deployment, with a chip while it is not plain', () => {
    const items = mapApps([
      {
        id: 'a1',
        name: 'Bookings',
        status: 'live',
        work_kind: 'directory',
        deployments: [
          { environment: 'preview', status: 'ready', url: 'https://preview.bookings.example' },
          { environment: 'production', status: 'pending', url: 'https://bookings.example' },
        ],
      },
      { id: 'a2', name: 'Draft', status: 'draft', deployments: [{ environment: 'production', status: 'ready', url: 'https://d.example' }] },
      { id: 'a3', name: 'No address', status: 'live', deployments: [{ environment: 'production', status: 'ready', url: null }] },
      {
        id: 'a5',
        name: 'Retired',
        status: 'live',
        deployments: [{ environment: 'production', status: 'retired', url: 'https://old.example' }],
      },
      {
        id: 'a4',
        name: 'Failed',
        status: 'live',
        deployments: [{ environment: 'production', status: 'timeout', url: 'https://f.example' }],
      },
    ]);
    expect(items.map((i) => [i.key, i.url, i.chip ?? null])).toEqual([
      ['app:a1', 'https://bookings.example/', 'deploying'],
      ['app:a4', 'https://f.example/', 'lastDeployFailed'],
    ]);
    expect(items[0].workKind).toBe('directory');
  });

  it('merges the Ever apps first, one tile per key, and marks the product itself', () => {
    const installs = mapInstalls([
      {
        id: 'i1',
        listing_slug: 'cal',
        listing_title: 'Cal',
        listing_type: 'app',
        state: 'installed',
        next_action_url: 'https://cal.example/',
      },
    ]);
    const merged = mergeLauncherResponse({
      catalog: CATALOG,
      installs: [...installs, ...installs],
      apps: [],
      current: 'platform:ever-gauzy',
      scopeKey: 'org:acme',
    });
    expect(merged.items.map((i) => i.key)).toEqual(['platform:ever-gauzy', 'install:i1']);
    expect(merged.items[0].current).toBe(true);
    expect(merged.meta).toMatchObject({ worksTotal: 1, total: 2, pinLimit: 6, scopeKey: 'org:acme', catalogVersion: '2026-11-01' });
  });
});
