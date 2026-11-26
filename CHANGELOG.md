# Changelog

Notable changes of the Ever Connect SDK (`@ever-co/connect-sdk`, `@ever-co/connect-contracts`,
`@ever-co/connect-tools`, the `ever-connect-sdk` and `ever-connect-contracts` crates, and the mock
platform). Versions are released together.

## Unreleased

### Added

- A tenant link's members (`GET /v1/instances/me/tenant-links/{link}/memberships`, operation
  `instanceListLinkMemberships`, outbound-call row 38): the re-read a product makes after the event
  feed answered `410 resync_required`. TypeScript: `client.instances.tenantLinks.memberships(linkId,
  { cursor, limit })` for one page and `allMemberships(linkId, { maxPages })` for every page. Rust:
  `EverPlatformClient::link_memberships` and `all_link_memberships`. A deployment that sends no
  membership events answers `404 module_disabled`.
- Bounded cursor-paged reads: `readPages` and `readAllPages` (TypeScript) and `Pager` (Rust) read
  every page and stop with `PagingError` / `Error::Paging` (`cursor_repeated`, `too_many_pages`,
  `malformed_page`) rather than answer part of a list.
- Mock platform: the member list of a tenant link (`POST /__mock/memberships` seeds an
  organization's members) and the fault `memberships_module_disabled`.
- `LinkMembership` and `LinkMembershipPage` types in `@ever-co/connect-contracts`.
- `Ever-Link-Id` on the apps mirror and the install status report, which the platform's contract does
  not declare yet. The mirror (`instanceMirrorApps`, `instanceListMirroredApps`) takes it optionally,
  as Ever Platform's `any_link` gate does. TypeScript: `mirrorApps.push(batch, linkId?)`, and
  `mirrorApps.list(cursor, limit, link)` sends `link` as the header too. The install status report
  requires it, as the per-link `marketplace_installs` gate does: TypeScript
  `instances.installs.reportStatus(installId, linkId, report)`, and in both languages a call without
  a link is refused before it is sent (`link_required`). Products no longer need to add the header
  in their own transport.

### Changed

- The contract follows Ever Platform's contract scope 1.8.0: the operation above, the
  `works_apps` integration (coming soon), Ever Rec among the products of `provisioning`, the
  fields an organization's own Apps carry, and two problem codes (`listing_changed`,
  `licence_check_required`).
- The mock platform gates the apps mirror as Ever Platform does: without `Ever-Link-Id` it answers
  while `app_sync` is enabled for any active link (it used to require the header).
- The mirror's vocabularies stay open, as in the platform's contract: an app or deployment status,
  an environment, an owner (`managed_by`) or a kind the SDK does not list is sent as it is, and an
  outcome or refusal code it does not list reaches the caller unchanged (tests in both languages).
- The contract sync reads a one-line design `description` or `summary` that starts with a backtick
  as the quoted string it was meant to be, with a warning, as it already did for one holding `: `.
- Consent scopes that changed since `1.0.0-rc.8` (`contracts/integrations/scope-versions.lock.json`
  pins each scope's SHA-256 with its version):
  - `app_sync` is at scope version 2. Ever Platform takes a consent at the current version only (an
    older one answers `422 scope_version_outdated`), and a link whose `app_sync` consent predates
    version 2 moves nothing until an owner or admin consents again. A product that shows the
    `app_sync` consent screen, sends its `scope_version` or pins its scope hash takes all three from
    this release.
  - `provider_access` is at scope version 2: it declares what moves.
  - New: `provisioning` (scope version 2) and `works_apps` (scope version 1, coming soon).

The operation id is the one products used while they registered the route themselves, so a
product's "add it when the SDK lacks it" guard keeps the SDK's entry.

### Fixed

- `STEP_UP_EXCLUDED_KEYS` and `stepUpAllowed` / `step_up_allowed` list `works_apps` with
  `instance_url` and `counterparty_discoverable`: Ever Platform consents it in app.ever.co only and
  answers a product's own consent write for it `403 session_required`.

### Upgrading from 1.0.0-rc.8

- Re-vendor the integration definitions, so the `app_sync` consent screen, `scope_version` and scope
  hash are version 2.
- Pass the tenant link to the SDK: `mirrorApps.push(batch, linkId)` and `mirrorApps.list(cursor,
  limit, link)` for the apps mirror, `instances.installs.reportStatus(installId, linkId, report)`
  (or `linkId` / `link_id` in `CallInput`) for the install status report. A transport that added
  `Ever-Link-Id` itself is no longer needed.
- Send the product's own app and deployment statuses, environments and owners as they are: the
  mirror's request body no longer limits them to a closed list.
