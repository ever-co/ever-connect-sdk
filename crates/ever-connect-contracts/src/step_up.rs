//! Types for the in-product consent dialog: the fresh Ever ID sign-in (step-up) a product asks for
//! through its own client, and the consent write it then sends with that token. Types and pure
//! checks only; this crate makes no request.

use serde::{Deserialize, Serialize};

use crate::openapi::components::IntegrationPut;

/// How old a step-up sign-in may be when the consent write arrives, in seconds.
pub const STEP_UP_MAX_AGE_S: i64 = 300;

/// How far in the future an `auth_time` may be (clock skew), in seconds.
pub const STEP_UP_MAX_FUTURE_SKEW_S: i64 = 60;

/// Integration keys that never take an in-product consent: they are enabled in app.ever.co only.
pub const STEP_UP_EXCLUDED_KEYS: [&str; 2] = ["counterparty_discoverable", "instance_url"];

/// The OpenID Connect authorization request of a step-up sign-in: a fresh sign-in
/// (`prompt=login`, `max_age=300`) with PKCE through the installation's own client, asking for the
/// Ever Platform API audience.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StepUpAuthorizationRequest {
    /// Always `code`.
    pub response_type: String,
    /// The installation's own client.
    pub client_id: String,
    /// The product's callback.
    pub redirect_uri: String,
    /// The scopes asked for.
    pub scope: String,
    /// Always `login`: a fresh sign-in.
    pub prompt: String,
    /// Always [`STEP_UP_MAX_AGE_S`].
    pub max_age: i64,
    /// The PKCE challenge.
    pub code_challenge: String,
    /// Always `S256`.
    pub code_challenge_method: String,
    /// The anti-forgery state.
    pub state: String,
    /// The replay nonce.
    pub nonce: String,
    /// The Ever Platform API audience the token must carry.
    pub audience: String,
}

impl StepUpAuthorizationRequest {
    /// A request with the fixed step-up parameters (`code`, `login`, `max_age=300`, `S256`).
    pub fn new(
        client_id: impl Into<String>,
        redirect_uri: impl Into<String>,
        scope: impl Into<String>,
        code_challenge: impl Into<String>,
        state: impl Into<String>,
        nonce: impl Into<String>,
        audience: impl Into<String>,
    ) -> Self {
        Self {
            response_type: "code".into(),
            client_id: client_id.into(),
            redirect_uri: redirect_uri.into(),
            scope: scope.into(),
            prompt: "login".into(),
            max_age: STEP_UP_MAX_AGE_S,
            code_challenge: code_challenge.into(),
            code_challenge_method: "S256".into(),
            state: state.into(),
            nonce: nonce.into(),
            audience: audience.into(),
        }
    }
}

/// The audience of a token: one value or several.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Audience {
    /// A single audience.
    One(String),
    /// Several audiences.
    Many(Vec<String>),
}

/// The claims of a step-up token a product checks before it sends the consent write.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StepUpTokenClaims {
    /// The Ever ID issuer.
    pub iss: String,
    /// The person.
    pub sub: String,
    /// The Ever Platform API audience (among others).
    pub aud: Audience,
    /// The client that asked for the token: the installation's own client.
    pub azp: String,
    /// When the person signed in (seconds); at most [`STEP_UP_MAX_AGE_S`] old.
    pub auth_time: i64,
    /// Issued at (seconds).
    pub iat: i64,
    /// Expires at (seconds).
    pub exp: i64,
}

/// The body of the in-product consent write
/// (`PUT /v1/orgs/{org}/instances/{instance}/integrations/{key}`):
/// `{enabled, tenant_link_id?, consent: {scope_version, dpa_version, accepted, screen_version?, ui_locale?}}`.
pub type StepUpGrantBody = IntegrationPut;

/// Whether an integration may be consented in the product's own dialog.
pub fn step_up_allowed(key: &str) -> bool {
    !STEP_UP_EXCLUDED_KEYS.contains(&key)
}

/// Whether a step-up sign-in is fresh enough at `now_s` (seconds): at most `max_age_s` old and not
/// more than [`STEP_UP_MAX_FUTURE_SKEW_S`] in the future.
pub fn is_step_up_fresh(auth_time: i64, now_s: i64, max_age_s: i64) -> bool {
    now_s - auth_time <= max_age_s && auth_time <= now_s + STEP_UP_MAX_FUTURE_SKEW_S
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    #[test]
    fn freshness_window() {
        let now = 1_793_613_600;
        assert!(is_step_up_fresh(now - 300, now, STEP_UP_MAX_AGE_S));
        assert!(!is_step_up_fresh(now - 301, now, STEP_UP_MAX_AGE_S));
        assert!(is_step_up_fresh(now + 60, now, STEP_UP_MAX_AGE_S));
        assert!(!is_step_up_fresh(now + 61, now, STEP_UP_MAX_AGE_S));
    }

    #[test]
    fn excluded_keys_are_app_ever_co_only() {
        assert!(!step_up_allowed("instance_url"));
        assert!(!step_up_allowed("counterparty_discoverable"));
        assert!(step_up_allowed("counterparty_lookup"));
        for key in STEP_UP_EXCLUDED_KEYS {
            assert!(
                crate::INTEGRATION_KEYS.contains(&key),
                "{key} is an integration key"
            );
        }
    }

    #[test]
    fn request_defaults_and_claims_shape() {
        let r = StepUpAuthorizationRequest::new("c", "https://p/cb", "openid", "x", "s", "n", "a");
        assert_eq!(
            (
                r.prompt.as_str(),
                r.max_age,
                r.code_challenge_method.as_str()
            ),
            ("login", 300, "S256")
        );
        let claims: StepUpTokenClaims = serde_json::from_value(serde_json::json!({
            "iss": "https://auth.ever.co", "sub": "1", "aud": ["a", "b"], "azp": "c",
            "auth_time": 1, "iat": 1, "exp": 2
        }))
        .unwrap();
        assert_eq!(claims.aud, Audience::Many(vec!["a".into(), "b".into()]));
    }

    #[test]
    fn grant_body_is_the_contract_type() {
        let body: StepUpGrantBody = serde_json::from_value(serde_json::json!({
            "enabled": true,
            "consent": { "scope_version": 1, "dpa_version": "2026-10", "accepted": true }
        }))
        .unwrap();
        assert!(body.enabled);
    }
}
