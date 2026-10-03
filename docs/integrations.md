# Integrations and data scopes

**Audience:** organization admins deciding what to enable; operators setting an instance-wide policy; privacy officers and counsel reviewing what data leaves an installation.
**Prerequisites:** the installation is connected to Ever Platform and your organization is linked (*Connecting a self-hosted installation*). To enable anything you need the **owner** or **admin** role in the linked organization on app.ever.co.

---

## 1. What a scope is

An **integration** is a named data flow between your installation and Ever Platform. Every integration ships with a **definition** — the same file in the product, in the SDK and on app.ever.co — that declares:

| Field | Meaning |
|---|---|
| `key` | stable machine name (`counterparty_lookup`) |
| `scope_version` | increases whenever the list of fields changes; a new version requires a new consent |
| `direction` | `outbound` (data leaves the installation), `inbound` (the platform sends something to it), or `both` |
| `scope` | the exact fields that may move, each with its **form** (`clear`, `hashed`, `identifier`) and **when** it moves |
| `platform_retention` | what Ever Platform keeps, and for how long |
| `frequency` | on user action, once, on change, daily, or event-driven |
| `defaults` | `enabled` or `available` on Ever-operated cloud; `available` or `disabled` on self-hosted |
| `requires_feature` | the entitlement feature that must be granted |
| `products` | where the integration exists |

The consent screen is generated from this definition, so what you read before enabling is exactly what the code is allowed to send. A field not in the scope cannot be sent: the request bodies are validated against the published schemas on both ends.

---

## 2. Consent

- On a self-hosted installation every integration starts as **available** (off). Nothing turns on by itself.
- On Ever-operated cloud, the integrations marked *enabled* by default are materialised as real, auditable consent records (`consent_source: cloud_terms`) when the organization is linked; any cloud organization can disable any of them.
- Consent is granted on app.ever.co, or inside Ever Gauzy, Ever Teams or Ever Works after you confirm with a fresh Ever ID sign-in, by an owner or admin of the linked organization; both record the same consent. Discoverability and the instance URL are enabled on app.ever.co only. The screen is the same in both places and shows: purpose; *What leaves this installation* (field, form, when); *What Ever Platform keeps*; *How often*; where to change it; the terms, the data-processing agreement and the sub-processor list; the confirmation *I am authorised to enable this for <organization>*.
- Integrations that act for the whole installation (`instance_url`, `stats_link`, `ever_id_login`, `webhooks`, `managed_operations`) can be enabled only by the organization that owns the installation's connection, and they start only after the installation's operator also accepts them on the installation.
- Consent is recorded on both sides with: `integration, scope_version, granted_at, granted_by (the Ever ID person id and a display label), consent_source, terms_version, dpa_version, ui_locale, instance_id, link_id`. Both audit logs receive an entry.
- A `scope_version` bump (the definition changed) invalidates the old consent for new transfers; the row shows *re-consent required*.

## 3. Revoke

| From | How | Effect |
|---|---|---|
| app.ever.co | *Integrations & data → Revoke* | the platform refuses further calls at once; the installation is notified within seconds and marks the row *revoked in app.ever.co*; the per-integration cleanup runs (see "Revoke effect" below) |
| the product | *Integrations & data → Disable* | the installation tells the platform first, then disables locally; if the platform is unreachable it disables locally anyway and retries the notification |
| the operator | `EVER_CONNECT_INTEGRATIONS_DENY` or the policy tab | the integration becomes *denied by policy* for every tenant; existing consents under this installation are revoked with reason `policy` |

Revocation stops data movement immediately, including offline. The consent record itself is kept (with `revoked_at`, `revoke_source`) for audit.

---

## 4. Catalog (v1)

<!-- generated:integrations-catalog -->
| Key | What it does | Direction | Ever Cloud / self-hosted | Products | Status |
|---|---|---|---|---|---|
| `instance_url` | Installation address: Shows the public address of this installation to its own organization in app.ever.co, and on the public profile if the owner turns that section on. | outbound | enabled / available | gauzy, teams, works, rec, traduora | active |
| `stats_link` | Link usage statistics to this organization: Connects the anonymous statistics identity of this self-hosted installation to your organization, so you can see your installation's latest statistics report in app.ever.co. Without this link, statistics stay anonymous. It is never offered on Ever Cloud, where one installation serves many organizations. | outbound | not_applicable / available | gauzy, teams, works, rec, traduora | active |
| `ever_id_login` | Sign in with Ever ID: Adds Ever ID as an extra sign-in option in this installation. Existing sign-in methods keep working unchanged. | both | enabled / available | gauzy, works, rec, traduora | coming soon |
| `counterparty_lookup` | Check contacts on Ever Platform: When you click 'Check on Ever Platform' on a contact, the installation sends salted hashes of that contact's VAT number, registration number or e-mail and gets back the handle of any organization that chose to be discoverable. The values themselves never leave the installation. | outbound | enabled / available | gauzy, works | coming soon |
| `counterparty_discoverable` | Let your partners find you: Publishes salted hashes of your own organization's tax ID, registration number and billing e-mail, so other organizations that already know these values can find your Ever Platform handle. Nothing is findable by browsing or searching. It is off everywhere, Ever Cloud included, until an owner of your organization turns it on in app.ever.co. | outbound | available / available | gauzy, works, rec, traduora | coming soon |
| `profile_import` | Import into public profile: Copies your organization's name, website, description, logo and country into your ever.co profile draft, and only when you click 'Import into public profile'. You review the draft before anything is published. | outbound | enabled / available | gauzy, works | coming soon |
| `usage_reporting` | Usage reporting: Sends daily counts of a plan's metered quantities (for example active employees or seats) for plans that are priced by usage. On Ever Cloud it will start on under the Ever Cloud terms once cloud plans are billed on these counts (for example per employee for Ever Gauzy and Ever Teams, on the latest successful count); until then it stays off. A self-hosted installation sends nothing unless an administrator turns it on. | outbound | enabled / disabled | gauzy, works | active |
| `app_sync` | Apps and deployments: Lists the apps you build and deploy in Ever Works on your organization's account pages, and on your public profile if you choose. Only identifiers and status move. App content, repositories, budgets, agents and memory never leave Ever Works. | outbound | enabled / available | works | active |
| `billing_link` | Link cloud billing: Links your existing Ever Gauzy Cloud billing account to your Ever Platform organization, so all your plans show in one place. Prices, limits and existing offers do not change. | outbound | enabled / not_applicable | gauzy | active |
| `webhooks` | Event delivery: Lets Ever Platform send signed notifications (for example 'your plan changed') to installations that can receive them. Installations that only make outbound connections use polling instead. | inbound | enabled / available | gauzy, works | active |
| `managed_operations` | Maintenance operations: Lets an owner or admin ask this self-hosted installation, from app.ever.co, to run a maintenance operation: an update, a backup, a restore check or a health report. Requests reach the installation through its own outbound connection; the operator also turns the feature on locally and sets when and what may run. Backups stay in your own storage, and Ever Platform sees only each operation's status and size. Ever never connects in. | both | not_applicable / available | gauzy, works, rec, traduora | coming soon |
| `provider_access` | Grant a provider access: Lets a service provider you choose on apps.ever.co (for example an accountant or payroll provider) work in your installation with a role and scope you pick. The grant shows in Integrations & data and you can revoke it at any time. | both | enabled / available | gauzy, works | coming soon |
| `marketplace_installs` | Install apps from apps.ever.co: Lets you install an app you picked on apps.ever.co into this installation. The installation picks up the request and runs its normal plugin installer, then reports whether the install worked. | both | enabled / available | gauzy, works | coming soon |
<!-- /generated:integrations-catalog -->

Content, documents, task or project data, repositories, budgets, agents and memory never appear in any scope.

### 4.1 Hashing used by the lookup integrations

Identifiers are normalised on your server (VAT: uppercase, no spaces or punctuation, country prefix kept; registration: `<ISO country>:<number>`; e-mail: trimmed, lower-cased, domain in IDNA form) and hashed as `sha256(salt : kind : normalized)` in hexadecimal, with a published, versioned salt fetched from `GET /v1/lookup/salt`. The platform stores only hashes of organizations that opted in through `counterparty_discoverable`, answers a lookup only with opted-in handles, and does not store or log query hashes. Published test vectors let anyone reproduce the hashes.

The optional *check automatically when opening a contact* switch is **off** by default and is part of the consented scope text.

---

## 5. Data-processing agreement

One data-processing agreement covers every integration, and one public list names every sub-processor; both are linked from each consent screen and their versions are recorded in the consent (`terms_version`, `dpa_version`). The URLs and versions come from `GET /v1/connect/legal`. The agreement's annex lists every integration's scope; it is generated from the same definitions as the consent screen, so the legal text and the code describe the same data.

Reviewers of the DPA can use the scope table: it mirrors the definition fields one-to-one.

---

## 6. Reference: where to look

| Question | Where |
|---|---|
| The exact scope of an integration in my installation | product → *Integrations & data* → the row → **Show scope** (read-only table from the local definition) |
| Which integrations are enabled, since when, by whom | app.ever.co → *Integrations & data* (per instance and link); product → *Audit* tab |
| Every outbound request these integrations make | *What this installation sends, and when* (every row that names an integration) |
| The machine-readable definitions | `contracts/integrations/<key>.json` in the SDK; `GET https://api.ever.co/v1/integrations` |
| Operator deny list | `EVER_CONNECT_INTEGRATIONS_DENY` (comma-separated keys) or the *Connection → Policy* tab |
