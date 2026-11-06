# Connecting an App to Ever Platform

**Audience:** developers and operators of an App your organization owns on Ever Platform, for example a site built
with Ever Works, that is not one of the Ever products (Ever Gauzy, Ever Teams, Ever Works, Ever Rec, Ever Traduora).
**Prerequisites:**
- An Ever ID and an organization on app.ever.co where you are **owner** or **admin**.
- The App registered to that organization on Ever Platform (it appears among the organization's Apps).
- The Ever Connect SDK (`ever-connect-sdk`, Rust or TypeScript) in the App's server, and outbound HTTPS to
  `api.ever.co`. Nothing inbound is required.

Connecting is optional. An App connects the same way a self-hosted installation does (see *Connecting a self-hosted
installation*); this page lists only what differs.

---

## 1. What a connected App is

A connected App is an **installation** whose product is the App itself: `app:<app id>`, where `<app id>` is the App's
id on Ever Platform. It holds one connection and one or more **tenant links**, each to one organization. It serves no
Ever product, so its entitlement documents name no product and carry the free profile until a plan names App
features.

## 2. Mint a connect code (organization owner or admin)

An owner or admin of the organization that owns the App mints its code through the API (the app.ever.co page comes
later):

```http
POST /v1/orgs/{org}/connect-codes
{"product": "app:<app id>"}
```

The answer carries the code (`EVC-XXXX-XXXX-XXXX`) and its expiry. An App that does not exist, belongs to another
organization or is archived gets the same answer: `422 validation_failed` with the field code `app_not_found`.

## 3. Redeem it (the App's server)

The App redeems the code once, with its own connection key, exactly like an installation:

```http
POST /v1/connect/redeem
{
  "code": "EVC-…",
  "kind": "app",
  "product": "app:<app id>",
  "version": "<your App's version>",
  "install_source": "self-hosted",
  "public_jwk": { … },
  "tenant": {"product_tenant_id": "<your App's own tenant id>", "display_name": "<a name people recognise>"}
}
```

- `kind` must be `app` and `product` must name the App the code was minted for; anything else is refused.
- The App sends no address: Ever Platform never calls the App.
- The answer carries the instance token and the first tenant link, as for any installation.

## 4. Tokens and entitlements

The instance token works as it does for an installation: entitlement documents (fetch and verify offline with the
SDK), heartbeats, the event feed, consents. The App's documents name no product (`products: []`); the link document
names the App as its tenant's product (`app:<app id>`).

## 5. Signing people in with Ever ID

With **Ever ID sign-in** (`ever_id_login`) enabled for the App by an organization owner, the App asks for its own
client (`POST /v1/instances/me/oidc-client`, as an installation does) and gets one client for this App instance.
A person who signs in through it is known to the App with the organizations **linked to this App instance only**:
the token's claims, `GET /v1/me/context` and `POST /v1/identity/resolve` leave out every other organization the
person belongs to.

What the App's sign-in tokens can do on `api.ever.co`: two reads, `GET /v1/me/context` and `GET /v1/me/memberships`,
both reduced to the linked organizations. Every other operation, and every write, answers `403 session_required`.

## 6. Integrations an App can be offered

| Integration | Offered to Apps |
|---|---|
| Ever ID sign-in (`ever_id_login`) | yes, once it is generally available |
| The installation's address (`instance_url`) | yes |
| Anonymous usage statistics (`stats_link`) | no: an App sends no usage statistics |

Each is off until an organization owner enables it through its consent screen.

## 7. People's data: deletion and export

A person linked to the App through Ever ID can ask Ever Platform to delete or export their data. The request reaches
the App over its event feed like any installation's; the App answers with a receipt:

- `deleted` or `exported` when the App handled the account itself;
- `forwarded_to_controller` when the account belongs to someone else's controller (for example your customer's
  workspace), with the request passed on to them.

## 8. Disconnect

Disconnecting works as for any installation: the App's tokens stop working, its Ever ID client is turned off, and
its people's links end. The App keeps its own data.

## 9. Check what your App sends

Run the SDK's egress harness against your App to list every outbound call it makes; each call matches a row of
*What an installation sends, and when*.
