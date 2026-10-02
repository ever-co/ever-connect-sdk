# Ever Platform modules: what this installation sends, and when

**Audience:** operators of a self-hosted Ever Gauzy, Ever Teams, Ever Works, Ever Rec or Ever Traduora installation; security reviewers; anyone auditing outbound traffic.
**Applies to:** the two optional modules every product ships — **Anonymous usage statistics** (`ever-stats`) and **Ever Platform connection** (`ever-connect`). Ever Demand does not ship these modules yet ("Soon").
**Prerequisites:** none to read. To verify yourself: Docker Compose and `tcpdump` (see *How to verify yourself* below).

This page is generated from the same table the modules are built from. If a request is not listed here, the modules do not make it.

This page describes installations you run yourself. On Ever Cloud, Ever operates the installation; the product analytics Ever keeps there as the operator are described in the Ever Cloud privacy policy, and none of them is shipped to, or switched on in, a self-hosted installation.

---

## 1. When nothing is sent

| Setting | Effect |
|---|---|
| `EVER_CONNECT_ENABLED` unset or not `true` **and** `EVER_STATS_ENABLED=false` | Neither module is loaded: no routes (their URLs answer 404), no timers, no HTTP client objects, **no request to any `*.ever.co` host**. The product is complete and every feature works. |
| `EVER_STATS_ENABLED` unset (default) | Only the statistics module is loaded: one signed, anonymous report per day (row 17). Nothing else. |
| `EVER_CONNECT_ENABLED=true` but not connected | The connection module is loaded but idle. It makes **no** request until an operator submits a connect code (or `EVER_CONNECT_CODE` is set at first boot). |

Every product repository runs a continuous-integration job (`egress-audit`) that boots the product in a sealed Docker environment with no route out, a logging DNS sink and a packet capture, exercises the product, and fails the build if any name outside the Compose services is resolved or any connection attempt leaves the subnet. Links to the job live in each product's `docs/ever-platform/outbound-calls.md`.

Some products contact **non-Ever** hosts by design, independently of these modules; they are listed so the audit can allow them and you can see them:

| Product | Host(s) contacted regardless of Ever Platform modules | Why |
|---|---|---|
| Ever Works | `api.github.com`, `raw.githubusercontent.com` | plugin / template catalog fetches |
| Ever Rec | the Firebase hosts of your configured project | Rec's storage and database backend |
| Ever Gauzy, Teams, Traduora | none | — |

Error reporting and product analytics integrations that a product supports (for example an error tracker or a product-analytics client) send data only to a service whose address and key **you** configure. No self-hosted installation ships with an Ever-owned key for any of them.

### Older features that can contact Ever hosts (off by default)

Some products had features before these modules existed that can reach an Ever-operated host, such as an update check, a news feed, or an analytics key in a sample configuration. On a self-hosted installation every such call is **off by default**: it is switched off through the default configuration, the code stays in the product, and you can turn it back on with the setting below. The egress audit above is what finds them; this table is generated from its results, and a product the audit found nothing for says "none".

| Product | Feature | Setting that turns it on | Ever host it calls once on |
|---|---|---|---|
| Ever Gauzy | none | — | — |
| Ever Teams | none | — | — |
| Ever Works | none | — | — |
| Ever Rec | none | — | — |
| Ever Traduora | none | — | — |

---

## 2. Common properties of every request

- Base URL: `EVER_PLATFORM_API_URL` (default `https://api.ever.co`); statistics use `EVER_STATS_API_URL` (defaults to the same value). Plain `http://` is accepted only for `localhost` and private (RFC 1918) addresses, e.g. a CI mock.
- TLS; `User-Agent: ever-connect-sdk/<sdk version> (<product>/<product version>)`; `Content-Type: application/json`; timeout 10 s for writes, 6 s for reads; no redirects followed; no cookies; `Idempotency-Key` on writes.
- No request is made on user sign-in, page view, record create/update/delete, or any timer other than the ones listed.
- No request carries a person's name, e-mail address, or an identifier of a record from your tenants' data. Where an identifier is needed for a lookup, it is a salted one-way hash computed on your server (row 12–13).

---

## 3. The table

<!-- generated:outbound-intro -->
Rows 1–16, 18–34 belong to the connection module and row 17 to the statistics module. Each row runs only on the trigger it names: the connect calls (rows 2, 3, 29) when an operator starts a connection, every other connection-module row only while connected. Rows 11–15, 18–19, 21–23, 25, 27–28, 30, 32, 34 also need an active consent for the named integration, recorded by Ever Platform. The table holds 34 rows; a row marked *pending upstream* is answered by the mock platform and documented here before the Ever Platform API publishes it.
<!-- /generated:outbound-intro -->

<!-- generated:outbound-calls -->
| # | Endpoint | Trigger | Payload | Cadence | How to disable | Products |
|---|---|---|---|---|---|---|
| 1 | `GET /.well-known/ever-keys.json` | first signature verification; every 24 h; an unknown key id. | none (read) | at most every 24 h; at most once per 10 min on an unknown key id | disconnect, or leave EVER_CONNECT_ENABLED unset | all |
| 2 | `GET /v1/connect/legal` | connect or link. | none (read: links to the terms, the data-processing agreement and the sub-processor list) | once per connect or link | do not connect | all |
| 3 | `POST /v1/connect/redeem` | the operator submits a connect code; EVER_CONNECT_CODE at first boot. | code, product, version, install_source, kind (self_hosted; cloud on deployments Ever operates), serves_products[], public_jwk (the connect key), tenant {product_tenant_id, product_org_id?, display_name}? (absent values are omitted, never sent as null); never the installation's address | once | do not connect | all |
| 4 | `POST /v1/instances/token` | while connected: before the token expires, and after a 401. | grant_type, client_assertion_type, client_assertion (issuer and subject are the Ever Platform instance id returned at connect, never the statistics instance id) | every 50 min while connected; on a 401 | disconnect | all |
| 5 | `POST /v1/instances/me/tenant-links`<br>`DELETE /v1/instances/me/tenant-links/{link}`<br>`PATCH /v1/instances/me/tenant-links/{link}` | an organization admin submits a link code, removes a link, or a single-organization product moves its link to a new organization id. | link_code, product, product_tenant_id, product_org_id? | on action | do not link | all |
| 6 | `POST /v1/instances/me/heartbeat`<br>`GET /v1/instances/me` | while connected; the status read also while an approval is pending and when an admin opens the connection page. | version, module_version?, serves_products[]? (heartbeat); none (status read) | within 5 min of boot, then every 24 h | disconnect | all |
| 7 | `GET /v1/instances/me/events`<br>`POST /v1/instances/me/events/ack` | while connected. | cursor only | continuous long-poll (wait=25), or one read every 15 min with EVER_CONNECT_FEED_MODE=interval | disconnect | all |
| 8 | `GET /v1/instances/me/entitlement`<br>`GET /v1/instances/me/tenant-links/{link}/entitlement` | while connected: every 6 h, at boot, on an entitlement notice, on demand. | none (read; If-None-Match with the cached sequence number) | every 6 h; on boot; on a change notice; on demand | disconnect | all |
| 9 | `GET /v1/instances/me/integrations`<br>`GET /v1/instances/me/consent-url` | after a consent notice; on return from app.ever.co; when an admin opens the integrations tab. | integration, link, return (query) | on action or notice | disconnect | all |
| 10 | `PUT /v1/instances/me/integrations/{key}` | an admin disables an integration locally; an operator policy denies it. | enabled: false, reason (instance or policy), tenant_link_id? | on action | none needed: this call only ever disables | all |
| 11 | `POST /v1/instances/me/stats-link` | integration stats_link enabled (self-hosted installations only). Integration `stats_link`. | stats_instance_id, stats_public_jwk, statement_sig: a statement signed with the separate statistics key, sent under the connect-key token, so app.ever.co can show the installation's last report | once; again after Reset instance identity | disable stats_link | all |
| 12 | `PUT /v1/instances/me/tenant-links/{link}/identifiers`<br>`DELETE /v1/instances/me/tenant-links/{link}/identifiers` | the organization opted in to being discoverable in app.ever.co; its identifiers change; it opts out. Integration `counterparty_discoverable`. | hashes[{kind, salt_version, hash}] of the organization's own tax id, registration number and billing e-mail | on opt-in, on change, on opt-out | disable counterparty_discoverable | Gauzy, Works, Rec, Traduora |
| 13 | `GET /v1/lookup/salt`<br>`GET /v1/lookup/test-vectors`<br>`POST /v1/lookup` | daily salt refresh; a user clicks Check on Ever Platform on a contact. Integration `counterparty_lookup`. | salt_version, hashes[at most 100] of a contact's tax id, registration number or e-mail | on click, and one salt read a day | disable counterparty_lookup | Gauzy, Works |
| 14 | `POST /v1/instances/me/oidc-client`<br>`GET /v1/instances/me/oidc-client` | integration ever_id_login enabled; then a status read until the client is ready. Integration `ever_id_login`. | redirect_uri, logout_uri (the sign-in callback and back-channel logout addresses); the answer carries the client id and, once, the client secret | once per installation (one client serves every linked organization), then a read every few seconds until ready | disable ever_id_login (the client is removed on the Ever Platform side) | Gauzy, Works, Rec, Traduora |
| 15 | `POST /v1/instances/me/mirror/apps`<br>`GET /v1/instances/me/mirror/apps` | integration app_sync enabled and an app or deployment changes; nightly reconciliation. Integration `app_sync`. | app and deployment identifiers, kind, status, deployment {target, provider, shape, managed_by, url}, organization id; member joined or left (ids only) | every 30 s when there is something to send; nightly | disable app_sync | Works |
| 16 | `POST /v1/instances/me/disconnect`<br>`POST /v1/instances/me/keys` | the operator disconnects; the connect key is rotated. | none (disconnect); public_jwk of the new connect key (rotation; the statistics key is never rotated by this call) | on action | none needed: operator action only | all |
| 17 | `POST /v1/stats/reports` | statistics module loaded and enabled. | the ever.stats.v1 document: statistics instance id, product, version, channel, install source, coarse country, month, allow-listed counts, feature flags and integer aggregates | once a day at a jittered time; at boot when the last send is older than 24 h; a final re-send of the previous month on days 1-3 | EVER_STATS_ENABLED=false, or the settings toggle | all |
| 18 | `PUT /v1/instances/me/public-url` (pending upstream)<br>`DELETE /v1/instances/me/public-url` (pending upstream) | integration instance_url enabled in app.ever.co by the organization that owns the connection and accepted by the operator; revoked. Integration `instance_url`. | base_url (the installation's public address) | once; again when the address changes | disable instance_url (the address is removed from Ever Platform) | all |
| 19 | `POST /v1/instances/me/person-links`<br>`DELETE /v1/instances/me/person-links/{ref}` | a user of the installation links or unlinks Ever ID; a one-time sync of links that existed before the installation connected. Integration `ever_id_login`. | product_user_ref (the product's user id), identity_issuer, identity_subject, link_method, product_tenant_id?, product_org_id?, tenant_link_id?, display_name? of the tenant; never an e-mail or a person's name | on action | disable ever_id_login | Gauzy, Works, Rec, Traduora |
| 20 | `POST /v1/instances/me/ack` | a deletion or export request for a person arrived on the event feed and was handled. | job_id, result (deleted, anonymised, retained_legal, no_account, forwarded_to_controller, exported or failed), optional non-identifying detail | once per request | disconnect | all |
| 21 | `POST /v1/instances/me/org-profile` | an admin clicks Import into public profile. Integration `profile_import`. | the declared public-profile fields only (name, website, short description, logo address, country) | on click | disable profile_import | Gauzy, Works |
| 22 | `POST /v1/identity/resolve` | a backend that holds only an Ever ID token needs the Ever Platform context of that sign-in. Integration `ever_id_login`. | issuer, subject, id_token? | only on such a sign-in | disable ever_id_login | Gauzy, Works, Rec, Traduora |
| 23 | `GET /v1/me/context`<br>`GET /v1/me/memberships` | an Ever ID sign-in whose token lacks the Ever Platform claims. Integration `ever_id_login`. | none (read) | only on such a sign-in | disable ever_id_login | Gauzy, Works, Rec, Traduora |
| 24 | `GET /v1/sso/discover` | a user picks Sign in with your company. | email_domain (a domain, never an address) | on click | disconnect | Gauzy, Works, Rec, Traduora |
| 25 | `POST /v1/instances/me/billing-links` | integration billing_link enabled (installations Ever operates only). Integration `billing_link`. | product_tenant_id, the payment customer reference of the linked tenant | once per link | disable billing_link | Gauzy |
| 26 | `POST /v1/provision-intents/{jti}/complete` | a provisioning hand-off the person confirmed on a product screen. | instance_id, product_tenant_id, product_org_id?, product_user_ref?, urls?, result, refusal_reason? | once per hand-off | leave EVER_CONNECT_PROVISION_ENABLED unset | Gauzy, Works, Rec, Traduora |
| 27 | `POST /v1/instances/me/usage`<br>`POST /v1/instances/me/usage-readings` | integration usage_reporting enabled (on under the cloud terms on Ever Cloud; off on self-hosted installations unless an admin consents). Integration `usage_reporting`. | the consented meters only (counts, never names or ids of people) | daily | disable usage_reporting | Gauzy, Works |
| 28 | `POST /v1/installs/{install}/status` | an install request picked from apps.ever.co was handled by the installation's plugin installer. Integration `marketplace_installs`. | state, detail? (a fixed token), external_ref? | once per install step | disable marketplace_installs | Gauzy, Works |
| 29 | `POST /v1/connect/device`<br>`POST /v1/connect/token` | the operator chooses Show a code instead. | product, version, install_source, kind, serves_products[], public_jwk (start); device_code, client_assertion (poll) | once, then a poll at the interval the platform answers until approved or expired | do not connect | all |
| 30 | `POST /v1/instances/me/webhooks`<br>`PATCH /v1/webhooks/{webhook}`<br>`DELETE /v1/webhooks/{webhook}`<br>`POST /v1/webhooks/{webhook}/rotate-secret`<br>`POST /v1/webhooks/{webhook}/test`<br>`GET /v1/webhooks/{webhook}/deliveries`<br>`POST /v1/deliveries/{delivery}/redeliver` | integration webhooks enabled on an installation that can receive requests; the operator manages its endpoint. Integration `webhooks`. | url (the installation's own callback address), event_filter[] | on action | disable webhooks (the endpoint is deleted) | Gauzy, Works |
| 31 | `POST /v1/instances/me/integrations/{key}/accept` (pending upstream) | the operator accepts or declines an installation-wide integration that waits for the local accept. | consent_id, accepted | on action | none needed: operator action only | all |
| 32 | `GET /v1/instances/me/provider-grants/{grant}` (pending upstream)<br>`POST /v1/instances/me/provider-grants/{grant}/status` (pending upstream) | a provider access notice arrived on the event feed and was handled. Integration `provider_access`. | none (read of the grant); grant_id, status, product_user_ref (status report) | once per grant change | disable provider_access | Gauzy, Works |
| 33 | `PUT /v1/orgs/{org}/instances/{instance}/integrations/{key}` | an organization owner or admin confirms the in-product consent dialog after a fresh Ever ID sign-in. | enabled, tenant_link_id?, consent {scope_version, dpa_version, accepted, screen_version?, ui_locale?} | on action | never offered for instance_url and counterparty_discoverable; without an Ever ID client the product links to app.ever.co instead | all |
| 34 | `POST /v1/instances/me/managed-operations/{operation}/result` | the product's executor finished an operation an owner or admin requested, with the managed_operations integration consented and the operator's local opt-in. Integration `managed_operations`. | status, version?, artefact_ref?, size_bytes? (status and size only; never backup content, file names or customer data) | once per operation status | disable managed_operations, or leave the local opt-in off | Gauzy, Works, Rec, Traduora |
<!-- /generated:outbound-calls -->

**Nothing else.** A row that names an integration runs only while that integration has an active consent recorded by Ever Platform, given on app.ever.co or in the product after a fresh Ever ID sign-in; the integrations that act for the whole installation also need the operator to accept them on the installation. Apart from the connect calls themselves, every connection-module row runs only while connected; row 17 runs only while statistics are enabled. This table is generated from the SDK's operation table in continuous integration, so a request the SDK can make and this page does not list fails the build.

---

## 4. Rows grouped by what they are for

<!-- generated:outbound-groups -->
| Group | Rows | Disable by |
|---|---|---|
| Keys, tokens, heartbeat, entitlements and notices | 1, 2, 4, 6, 7, 8 | *Disconnect* (or leave `EVER_CONNECT_ENABLED` unset) |
| Connect, link and disconnect | 3, 5, 16, 26, 29 | not connecting; *Disconnect* |
| Integrations, each with its own consent and scope | 9, 10, 11 `stats_link`, 12 `counterparty_discoverable`, 13 `counterparty_lookup`, 14 `ever_id_login`, 15 `app_sync`, 18 `instance_url`, 19 `ever_id_login`, 21 `profile_import`, 22 `ever_id_login`, 23 `ever_id_login`, 25 `billing_link`, 27 `usage_reporting`, 28 `marketplace_installs`, 30 `webhooks`, 31, 32 `provider_access`, 33, 34 `managed_operations` | per integration in the product or in app.ever.co; for the whole installation with `EVER_CONNECT_INTEGRATIONS_DENY` |
| Receipts for a person's deletion or export request | 20 | *Disconnect* |
| Company sign-in discovery | 24 | *Disconnect* |
| Anonymous usage statistics | 17 | `EVER_STATS_ENABLED=false` or the settings toggle |
<!-- /generated:outbound-groups -->

Scope tables for each integration: *Integrations and data scopes*.

---

## 5. Environment variables

Read once at boot; compared strictly to `true` / `false`; a malformed value falls back to the default and is logged once.

| Variable | Default | Values / notes | Module |
|---|---|---|---|
| `EVER_INSTALL_SOURCE` | `self-hosted` | `cloud`, `self-hosted`, `partner:<slug>`, `ever.sh`, `works_app`, `desktop`; never inferred | both |
| `EVER_PLATFORM_API_URL` | `https://api.ever.co` | `http://` only for localhost / RFC 1918 | both |
| `EVER_CONNECT_ENABLED` | unset = off | `true` loads the connection module | connect |
| `EVER_CONNECT_CODE` | unset | a connect code consumed once at first boot; never retried after a 4xx | connect |
| `EVER_CONNECT_INTEGRATIONS_DENY` | unset | comma-separated integration keys denied instance-wide; env beats UI | connect |
| `EVER_CONNECT_FEED_MODE` | `longpoll` | `longpoll` or `interval` (one poll / 15 min; use behind restrictive proxies) | connect |
| `EVER_CONNECT_PROVISION_ENABLED` | `false` | `true` lets people who start a company on app.ever.co create it on this installation (they always sign in with Ever ID and confirm on a page of this installation) | connect |
| `EVER_CONNECT_PROVISION_MODE` | `handoff` | `handoff` only in this version | connect |
| `EVER_STATS_ENABLED` | unset = **on** | `false` unloads the statistics module | stats |
| `EVER_STATS_API_URL` | = `EVER_PLATFORM_API_URL` | | stats |
| `EVER_STATS_COUNTRY` | unset = `ZZ` | ISO 3166-1 alpha-2, declared by you; never derived from tenant data | stats |
| `EVER_STATS_SERVES` | the product | Gauzy only: `gauzy`, `teams`, `gauzy,teams` when one API serves both | stats |
| `EVER_STATS_SEND_INTERVAL_S` | `86400` | test override; the platform floor is 3600 | stats |
| `EVER_INSTANCE_ID` | unset | fixed UUID for stateless frontends (Teams) or fixtures; ignored when a persisted identity exists | both |
| `EVER_STATS_PRIVATE_KEY` | unset | stateless frontends only: the statistics signing key (base64url PKCS#8) that goes with a fixed `EVER_INSTANCE_ID`; with `EVER_INSTANCE_ID` set and no key, statistics stay off | stats |
| `EVER_PLATFORM_ROOT_KEYS_FILE` | unset | CI only: alternative trust roots; honoured only when the API URL is local | connect |

Per-product prefixes and extras:

| Product | Prefix | Extra |
|---|---|---|
| Ever Gauzy | `EVER_*` | desktop / Electron builds expose the same keys in the settings form |
| Ever Teams (web) | `NEXT_PUBLIC_EVER_CONNECT_ENABLED` shows the section (only when the Gauzy API it points at answers `GET /api/ever-connect/health`); server-side `EVER_STATS_ENABLED`, `EVER_INSTALL_SOURCE`, `EVER_INSTANCE_ID`, `EVER_STATS_API_URL` | `NEXT_PUBLIC_DEMO=true` hides the section |
| Ever Works | `EVER_*` | `EVER_WORKS_PLATFORM_CONNECTOR=ever-connect`, `EVER_WORKS_STATS_SINK=ever-stats-sink` select the transport plugins; the plugin allow-list is a second switch |
| Ever Rec | `EVER_*` | `NEXT_PUBLIC_EVER_CONNECT_ENABLED` for the portal page |
| Ever Traduora | `TR_EVER_*` (e.g. `TR_EVER_CONNECT_ENABLED`) | `TR_EVER_ADMIN_EMAILS` (defaults to `TR_ADMIN_EMAIL`) names who may operate the connection |

---

## 6. Errors you may see in logs

The platform answers with RFC 9457 `application/problem+json`; the `code` is stable. The codes the modules can receive on the calls above:
<!-- generated:outbound-problems -->
`already_connected`, `already_exists`, `already_linked`, `authorization_pending`, `code_invalid`, `credential_revoked`, `entitlement_required`, `expired_token`, `forbidden_role`, `gone`, `hashes_invalid`, `identifier_claimed`, `illegal_transition`, `instance_disconnected`, `instance_pending_approval`, `integration_disabled`, `integration_revoked`, `invalid_client`, `key_mismatch`, `keys_unavailable`, `limit_exceeded`, `module_disabled`, `not_connection_owner`, `not_found`, `payload_too_large`, `product_mismatch`, `product_not_supported`, `public_jwk_invalid`, `rate_limited`, `resync_required`, `salt_version_retired`, `salt_version_unknown`, `schema_violation`, `scope_version_outdated`, `session_required`, `signature_invalid`, `slow_down`, `step_up_required`, `unauthorized`, `validation_failed`
<!-- /generated:outbound-problems -->

The modules log the code and the request id, never the body of a request that carries a code, an assertion or a client secret.

---

## 7. How to verify yourself

1. Start the product with `EVER_STATS_ENABLED=false` and `EVER_CONNECT_ENABLED` unset.
2. Seal it off from the outside: `docker network create --internal ever-audit` and attach every service to it (add a CoreDNS container as the only resolver with `log` enabled if you want the DNS view).
3. Capture connection attempts from the API container's namespace: `docker run --rm --net=container:<api container> nicolaka/netshoot tcpdump -i any -w /tmp/api.pcap 'tcp[tcpflags] & tcp-syn != 0 and tcp[tcpflags] & tcp-ack == 0'`.
4. Use the product for a few minutes (sign in, create records, open the settings pages, call `/api/ever-stats/status` and `/api/ever-connect/status` and expect 404).
5. Inspect: the pcap should hold no SYN to an address outside the Compose subnet; the DNS log should hold no name outside your Compose services and the non-Ever hosts listed under *When nothing is sent*; the module URLs answered 404.

The same recipe with `EVER_STATS_ENABLED=true` shows exactly one request per day to `EVER_STATS_API_URL` (row 17). Turn on the connection module and connect, and you will see rows 1, 3, 4, 6, 7, 8 and 9: the key manifest, the redeem, the token, then the heartbeat, the event feed, the entitlement and the integration states. `ever-egress-audit` in this repository automates the recipe (see `tools/egress-audit/README.md`).
