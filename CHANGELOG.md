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

The operation id is the one products used while they registered the route themselves, so a
product's "add it when the SDK lacks it" guard keeps the SDK's entry.
