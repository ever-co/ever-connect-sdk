//! The instance token: acquired lazily with a client assertion, kept in memory only behind a
//! mutex, refreshed after `token_refresh_after_s` (or earlier when the platform gives a shorter
//! life) and after a 401. `Debug` shows whether a token is held, never the token.

use std::fmt;

use tokio::sync::Mutex;

/// Seconds after which a token is refreshed (`token_refresh_after_s`).
pub const TOKEN_REFRESH_AFTER_S: i64 = 3000;

#[derive(Default)]
struct Held {
    token: Option<String>,
    refresh_at: i64,
}

/// The in-memory instance token.
#[derive(Default)]
pub(crate) struct InstanceTokens {
    held: Mutex<Held>,
    /// Serialises acquisitions (one token request at a time).
    pub(crate) acquiring: Mutex<()>,
}

impl InstanceTokens {
    /// The current token when it is not due for refresh.
    pub(crate) async fn current(&self, now: i64) -> Option<String> {
        let held = self.held.lock().await;
        held.token.clone().filter(|_| now < held.refresh_at)
    }

    /// Stores a new token.
    pub(crate) async fn store(&self, token: String, expires_in: i64, now: i64) {
        let mut held = self.held.lock().await;
        let life = if expires_in > 0 { expires_in } else { 3600 };
        held.refresh_at = now + TOKEN_REFRESH_AFTER_S.min((life - 60).max(0));
        held.token = Some(token);
    }

    /// Drops the token (after a 401, a revocation or a disconnect).
    pub(crate) async fn invalidate(&self) {
        let mut held = self.held.lock().await;
        held.token = None;
        held.refresh_at = 0;
    }

    /// Whether a token is held.
    pub(crate) async fn is_held(&self) -> bool {
        self.held.lock().await.token.is_some()
    }
}

impl fmt::Debug for InstanceTokens {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let held = self.held.try_lock().map(|h| h.token.is_some());
        match held {
            Ok(held) => write!(f, "InstanceTokens {{ held: {held} }}"),
            Err(_) => f.write_str("InstanceTokens { busy }"),
        }
    }
}
