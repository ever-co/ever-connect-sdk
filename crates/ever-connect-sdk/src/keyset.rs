//! The key set: the keys of the last verified manifest, for one issuer, held in memory. Storage
//! stays in the product (persist [`KeySet::stored`] and rebuild with [`KeySet::restore`], which
//! verifies again for the issuer it is given).
//!
//! * A key set exists only over a manifest [`verify_key_manifest`] answered.
//! * [`KeySet::issuer`] is the issuer the manifest was verified for: the entitlement verifier
//!   refuses a document expected from any other issuer.
//! * [`KeySet::find`] answers only an `active` or `previous` key of the purpose asked for, inside
//!   its validity window, so an assertion or intent key never verifies an entitlement document.
//! * [`KeySet::needs_refresh`] is true 24 h after the fetch, and once the manifest has expired.
//! * [`KeySet::unknown_kid_refresh_allowed`] answers true at most once per 10 minutes.
//! * A manifest that fails verification, is for another issuer, or is older than the current one
//!   never replaces it.
//!
//! ```compile_fail
//! # fn f(m: ever_connect_sdk::manifest::VerifiedKeyManifest) {
//! // Only this crate builds a key set over a verified manifest.
//! let set = ever_connect_sdk::keyset::KeySet::from_manifest(m, 0);
//! # }
//! ```

use std::sync::atomic::{AtomicI64, Ordering};

use serde_json::{Value, json};

use crate::manifest::{
    CLOCK_SKEW_S, KeyManifestError, ManifestKey, VerifiedKeyManifest, VerifyKeyManifestOptions,
    now_s, origin_of, verify_key_manifest,
};

/// Seconds after which the manifest is fetched again.
pub const REFRESH_S: i64 = 86_400;
/// The shortest time between two refreshes caused by an unknown key id.
pub const UNKNOWN_KID_REFRESH_MIN_S: i64 = 600;

/// The keys of a verified manifest, for one issuer.
#[derive(Debug)]
pub struct KeySet {
    manifest: VerifiedKeyManifest,
    fetched_at: i64,
    last_unknown_kid_refresh: AtomicI64,
}

/// The outcome of [`KeySet::update`].
#[derive(Debug)]
pub enum KeySetUpdate {
    /// The new manifest verified and replaces the set.
    Replaced(KeySet),
    /// The new manifest is older than the current one: the current set stays.
    Kept,
    /// The new manifest was refused (or is for another issuer): the current set stays.
    Refused(KeyManifestError),
}

impl KeySet {
    /// A key set over a manifest that [`verify_key_manifest`] answered.
    pub(crate) const fn from_manifest(manifest: VerifiedKeyManifest, fetched_at: i64) -> Self {
        Self {
            manifest,
            fetched_at,
            last_unknown_kid_refresh: AtomicI64::new(i64::MIN),
        }
    }

    /// Verifies a served body for one issuer and builds a key set.
    ///
    /// # Errors
    /// [`KeyManifestError`].
    pub fn verify(
        body: &Value,
        options: &VerifyKeyManifestOptions<'_>,
    ) -> Result<Self, KeyManifestError> {
        let now = options.now.unwrap_or_else(now_s);
        let options = VerifyKeyManifestOptions {
            now: Some(now),
            ..options.clone()
        };
        Ok(Self::from_manifest(
            verify_key_manifest(body, &options)?,
            now,
        ))
    }

    /// Rebuilds a stored key set (`{document, fetchedAt}`) for one issuer, verifying the manifest
    /// again (offline: only the pinned root of that issuer is needed). A stored fetch time in the
    /// future counts as now.
    ///
    /// # Errors
    /// [`KeyManifestError`]; `SchemaViolation` when the stored value has no document.
    pub fn restore(
        stored: &Value,
        options: &VerifyKeyManifestOptions<'_>,
    ) -> Result<Self, KeyManifestError> {
        let now = options.now.unwrap_or_else(now_s);
        let options = VerifyKeyManifestOptions {
            now: Some(now),
            ..options.clone()
        };
        let document = stored
            .get("document")
            .ok_or(KeyManifestError::SchemaViolation)?;
        let fetched_at = stored.get("fetchedAt").and_then(Value::as_i64).unwrap_or(0);
        Ok(Self::from_manifest(
            verify_key_manifest(document, &options)?,
            fetched_at.clamp(0, now.max(0)),
        ))
    }

    /// The verified manifest.
    #[must_use]
    pub const fn manifest(&self) -> &VerifiedKeyManifest {
        &self.manifest
    }

    /// The issuer origin the manifest was verified for.
    #[must_use]
    pub fn issuer(&self) -> &str {
        self.manifest.issuer()
    }

    /// Unix seconds of the fetch.
    #[must_use]
    pub const fn fetched_at(&self) -> i64 {
        self.fetched_at
    }

    /// The key `kid` for `purpose` at `now`, or `None`: unknown, another purpose, retired or
    /// outside its window (300 s of skew).
    #[must_use]
    pub fn find(&self, kid: &str, purpose: &str, now: i64) -> Option<&ManifestKey> {
        let key = self.manifest.keys().iter().find(|k| k.kid() == kid)?;
        if key.purpose() != purpose || (key.state() != "active" && key.state() != "previous") {
            return None;
        }
        if now.saturating_add(CLOCK_SKEW_S) < key.not_before() {
            return None;
        }
        if key
            .not_after()
            .is_some_and(|na| now > na.saturating_add(CLOCK_SKEW_S))
        {
            return None;
        }
        Some(key)
    }

    /// Whether the manifest lists `kid` at all (an unknown `kid` suggests one refresh).
    #[must_use]
    pub fn has(&self, kid: &str) -> bool {
        self.manifest.keys().iter().any(|k| k.kid() == kid)
    }

    /// True 24 h after the fetch, and once the manifest has expired.
    #[must_use]
    pub const fn needs_refresh(&self, now: i64) -> bool {
        now.saturating_sub(self.fetched_at) >= REFRESH_S || now >= self.manifest.expires_at()
    }

    /// Whether an unknown `kid` may trigger a refresh now (at most once per 10 minutes; a fetch
    /// counts as one); answering true records the refresh. Safe across threads: of two callers at
    /// the same time, one gets `true`.
    pub fn unknown_kid_refresh_allowed(&self, now: i64) -> bool {
        let mut last = self.last_unknown_kid_refresh.load(Ordering::Acquire);
        loop {
            if now.saturating_sub(self.fetched_at.max(last)) < UNKNOWN_KID_REFRESH_MIN_S {
                return false;
            }
            match self.last_unknown_kid_refresh.compare_exchange(
                last,
                now,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return true,
                Err(current) => last = current,
            }
        }
    }

    /// Verifies a newly fetched manifest body for this set's issuer; it replaces this set only
    /// when it verifies and is not older than the current manifest.
    #[must_use]
    pub fn update(&self, body: &Value, options: &VerifyKeyManifestOptions<'_>) -> KeySetUpdate {
        if origin_of(options.issuer).as_deref() != Some(self.issuer()) {
            return KeySetUpdate::Refused(KeyManifestError::IssuerMismatch);
        }
        let now = options.now.unwrap_or_else(now_s);
        let options = VerifyKeyManifestOptions {
            now: Some(now),
            ..options.clone()
        };
        match verify_key_manifest(body, &options) {
            Err(error) => KeySetUpdate::Refused(error),
            Ok(next) if next.issued_at() < self.manifest.issued_at() => KeySetUpdate::Kept,
            Ok(next) => {
                let set = Self::from_manifest(next, now);
                set.last_unknown_kid_refresh.store(
                    self.last_unknown_kid_refresh.load(Ordering::Acquire),
                    Ordering::Release,
                );
                KeySetUpdate::Replaced(set)
            }
        }
    }

    /// What to persist: the served body and the fetch time (no secret is in it).
    #[must_use]
    pub fn stored(&self) -> Value {
        json!({"document": self.manifest.document(), "fetchedAt": self.fetched_at})
    }
}
