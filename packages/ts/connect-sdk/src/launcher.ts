/**
 * The App Launcher's data for a product's header: the Ever apps (Ever Works' public catalog, or a
 * bundled snapshot when it cannot be read) and the organization's own apps from Ever Platform
 * (what it installed from apps.ever.co, and its apps with a live deployment), in the shape the
 * `<ever-app-launcher>` element takes (`AppLauncherListResponse`).
 *
 * The product reads the two feeds itself (`GET /v1/orgs/{org}/installs` and
 * `GET /v1/orgs/{org}/apps`) with the person's token exchanged for the `apps:read` scope, then
 * hands the pages to {@link mapInstalls} and {@link mapApps}. This module makes one call of its
 * own: {@link loadLauncherCatalog}, without credentials.
 *
 * The launcher opens addresses only: an install or an app without an `https` address is left
 * out.
 */

export type AppLauncherEnvironment = 'production' | 'stage' | 'develop';
export type AppLauncherItemKind = 'platform' | 'work';
export type AppLauncherSection = 'pinned' | 'platforms' | 'works';
export type AppLauncherWorkChip = 'deploying' | 'lastDeployFailed';
export type AppLauncherManageState = 'listed' | 'notLive' | 'exposureOff';
export type AppLauncherPlatformStatus = 'available' | 'beta' | 'soon';

/** One launcher tile (`url` is `https`, or `null` exactly when `manageState` is not `listed`). */
export interface AppLauncherItem {
  key: string;
  kind: AppLauncherItemKind;
  section: AppLauncherSection;
  name: string;
  description?: string;
  iconDataUri?: string;
  url: string | null;
  host: string | null;
  current?: boolean;
  status?: AppLauncherPlatformStatus;
  workKind?: string;
  chip?: AppLauncherWorkChip;
  visible: boolean;
  pinned: boolean;
  pinOrder: number | null;
  order: number;
  manageState: AppLauncherManageState;
}

/** What the element is given. */
export interface AppLauncherListResponse {
  items: AppLauncherItem[];
  meta: {
    environment: AppLauncherEnvironment;
    catalogVersion: string | null;
    catalogAvailable: boolean;
    scopeKey: string;
    worksTotal: number;
    total: number;
    truncated: boolean;
    pinLimit: 6;
    appWorksAvailable: boolean;
  };
}

/** Ever Works' public catalog (`GET /api/app-launcher/platforms`). */
export interface AppLauncherPlatformsResponse {
  catalogVersion: string | null;
  environment: AppLauncherEnvironment;
  platforms: AppLauncherItem[];
}

/** An install as `GET /v1/orgs/{org}/installs` lists it (the fields the launcher reads). */
export interface LauncherInstall {
  id: string;
  listing_slug: string;
  listing_title: string;
  listing_type: string;
  state: string;
  next_action_url?: string | null;
}

/** A deployment of an app as `GET /v1/orgs/{org}/apps` lists it (the fields the launcher reads). */
export interface LauncherAppDeployment {
  environment: string;
  status: string;
  url?: string | null;
}

/** An app as `GET /v1/orgs/{org}/apps` lists it (the fields the launcher reads). */
export interface LauncherApp {
  id: string;
  name: string;
  status: string;
  work_kind?: string | null;
  deployments: LauncherAppDeployment[];
}

export type LauncherFetch = (input: string, init?: RequestInit) => Promise<Response>;

/** The snapshot's version, reported as the catalog version when it stands in. */
export const LAUNCHER_SNAPSHOT_VERSION = 'sdk-snapshot-2026-11-07';

const SNAPSHOT: readonly { id: string; name: string; description: string; url: string | null }[] = [
  { id: 'app-ever-co', name: 'Ever Platform', description: 'Your Ever ID, organizations and plan', url: 'https://app.ever.co' },
  { id: 'ever-gauzy', name: 'Ever Gauzy', description: 'Business management', url: 'https://app.gauzy.co' },
  { id: 'ever-teams', name: 'Ever Teams', description: 'Work and time tracking', url: 'https://app.ever.team' },
  { id: 'ever-works', name: 'Ever Works', description: 'Build and run your apps', url: 'https://app.ever.works' },
  { id: 'ever-rec', name: 'Ever Rec', description: 'Screen recording', url: null },
  { id: 'ever-traduora', name: 'Ever Traduora', description: 'Translations', url: null },
];

function httpsUrl(raw: string | null | undefined): string | null {
  if (!raw) return null;
  try {
    const url = new URL(raw);
    return url.protocol === 'https:' && url.username === '' && url.password === '' ? url.toString() : null;
  } catch {
    return null;
  }
}

function hostOf(url: string | null): string | null {
  return url ? new URL(url).host : null;
}

/** The bundled Ever apps, in the shape of Ever Works' public catalog. */
export function launcherSnapshot(environment: AppLauncherEnvironment): AppLauncherPlatformsResponse {
  return {
    catalogVersion: LAUNCHER_SNAPSHOT_VERSION,
    environment,
    platforms: SNAPSHOT.map((entry, order) => ({
      key: `platform:${entry.id}`,
      kind: 'platform',
      section: 'platforms',
      name: entry.name,
      description: entry.description,
      url: entry.url,
      host: hostOf(entry.url),
      status: 'available',
      visible: entry.url !== null,
      pinned: false,
      pinOrder: null,
      order,
      manageState: entry.url ? 'listed' : 'notLive',
    })),
  };
}

/** Whether `value` is a launcher item the element may show (an `https` address, or none while not listed). */
export function isLauncherItem(value: unknown): value is AppLauncherItem {
  if (typeof value !== 'object' || value === null) return false;
  const item = value as Record<string, unknown>;
  if (typeof item.key !== 'string' || typeof item.name !== 'string') return false;
  if (item.kind !== 'platform' && item.kind !== 'work') return false;
  if (item.url === null) return item.manageState !== 'listed';
  return typeof item.url === 'string' && httpsUrl(item.url) !== null;
}

/**
 * Ever Works' public catalog of Ever apps (no credentials, `timeoutMs` 2 s by default), or the
 * bundled snapshot when it cannot be read (unreachable, slow, not the catalog's shape).
 */
export async function loadLauncherCatalog(
  worksApiUrl: string,
  options: { environment?: AppLauncherEnvironment; timeoutMs?: number; fetch?: LauncherFetch } = {},
): Promise<AppLauncherPlatformsResponse> {
  const environment = options.environment ?? 'production';
  const fetcher = options.fetch ?? ((input: string, init?: RequestInit) => globalThis.fetch(input, init));
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), options.timeoutMs ?? 2000);
  try {
    const base = worksApiUrl.replace(/\/+$/, '');
    const answer = await fetcher(`${base}/api/app-launcher/platforms`, {
      credentials: 'omit',
      headers: { accept: 'application/json' },
      signal: controller.signal,
    });
    if (!answer.ok) return launcherSnapshot(environment);
    const body = (await answer.json()) as Partial<AppLauncherPlatformsResponse>;
    if (!Array.isArray(body.platforms)) return launcherSnapshot(environment);
    return {
      catalogVersion: typeof body.catalogVersion === 'string' ? body.catalogVersion : null,
      environment,
      platforms: body.platforms.filter(isLauncherItem),
    };
  } catch {
    return launcherSnapshot(environment);
  } finally {
    clearTimeout(timer);
  }
}

/**
 * The organization's installs as launcher tiles: those `installed` or `delivered` with an address
 * (`addressOf`, which a product resolves from the listing; `next_action_url` by default).
 */
export function mapInstalls(
  installs: readonly LauncherInstall[],
  addressOf: (install: LauncherInstall) => string | null | undefined = (install) => install.next_action_url,
): AppLauncherItem[] {
  const items: AppLauncherItem[] = [];
  for (const install of installs) {
    if (install.state !== 'installed' && install.state !== 'delivered') continue;
    const url = httpsUrl(addressOf(install));
    if (!url) continue;
    items.push({
      key: `install:${install.id}`,
      kind: 'work',
      section: 'works',
      name: install.listing_title,
      url,
      host: hostOf(url),
      visible: true,
      pinned: false,
      pinOrder: null,
      order: items.length,
      manageState: 'listed',
    });
  }
  return items;
}

/** Deployment states that no longer serve the app (Ever Platform's vocabulary). */
const ENDED = new Set(['canceled', 'retired']);

/**
 * The deployment an app's tile opens: production first, then any other with an address; a
 * canceled or retired deployment never.
 */
function deploymentOf(app: LauncherApp): LauncherAppDeployment | null {
  const withUrl = app.deployments.filter((d) => !ENDED.has(d.status) && httpsUrl(d.url) !== null);
  return withUrl.find((d) => d.environment === 'production') ?? withUrl[0] ?? null;
}

/**
 * The organization's apps as launcher tiles: live apps with a deployment address; a deployment
 * still going out (`pending`) shows `deploying`, one that failed (`error`, `timeout`)
 * `lastDeployFailed`.
 */
export function mapApps(apps: readonly LauncherApp[]): AppLauncherItem[] {
  const items: AppLauncherItem[] = [];
  for (const app of apps) {
    if (app.status !== 'live') continue;
    const deployment = deploymentOf(app);
    const url = httpsUrl(deployment?.url);
    if (!deployment || !url) continue;
    const chip: AppLauncherWorkChip | undefined =
      deployment.status === 'pending'
        ? 'deploying'
        : deployment.status === 'error' || deployment.status === 'timeout'
          ? 'lastDeployFailed'
          : undefined;
    items.push({
      key: `app:${app.id}`,
      kind: 'work',
      section: 'works',
      name: app.name,
      url,
      host: hostOf(url),
      ...(app.work_kind ? { workKind: app.work_kind } : {}),
      ...(chip ? { chip } : {}),
      visible: true,
      pinned: false,
      pinOrder: null,
      order: items.length,
      manageState: 'listed',
    });
  }
  return items;
}

/**
 * What the element is given: the Ever apps, then the organization's own (installs first, then
 * apps), one tile per key; `current` marks the product's own catalog entry (`platform:<id>`).
 */
export function mergeLauncherResponse(input: {
  catalog: AppLauncherPlatformsResponse;
  installs?: readonly AppLauncherItem[];
  apps?: readonly AppLauncherItem[];
  current?: string;
  scopeKey?: string;
}): AppLauncherListResponse {
  const seen = new Set<string>();
  const items: AppLauncherItem[] = [];
  const works = [...(input.installs ?? []), ...(input.apps ?? [])];
  for (const item of [...input.catalog.platforms, ...works]) {
    if (seen.has(item.key)) continue;
    seen.add(item.key);
    items.push(item.key === input.current ? { ...item, current: true } : item);
  }
  const worksTotal = items.filter((item) => item.section === 'works').length;
  return {
    items,
    meta: {
      environment: input.catalog.environment,
      catalogVersion: input.catalog.catalogVersion,
      catalogAvailable: true,
      scopeKey: input.scopeKey ?? 'global',
      worksTotal,
      total: items.length,
      truncated: false,
      pinLimit: 6,
      appWorksAvailable: false,
    },
  };
}
