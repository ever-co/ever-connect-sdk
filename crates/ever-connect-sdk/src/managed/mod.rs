//! Managed operations: what a product implements to run an operation an owner or admin requested
//! from app.ever.co (an update, a backup, a restore check, a health report) on the installation's
//! own hardware, and the runner that decides whether an operation runs at all.
//!
//! Rules of [`ManagedOperationRunner::handle`], in order:
//!
//! 1. only `ever.registry.managed_operation.requested` events are handled; every other type is
//!    ignored;
//! 2. the event data is validated against the vendored event schema (closed per-kind params); an
//!    invalid operation, or a kind the executor does not run, gets one `failed` result and nothing
//!    runs;
//! 3. an operation past its `expires_at` never runs; one before its `not_before` is deferred;
//! 4. the dry run always runs first; a failed dry run is a `failed` result;
//! 5. every `update` takes [`ManagedOperationExecutor::backup_before_update`] before it executes;
//!    a failed backup is a `failed` result and the update never executes; `dry_run_only` updates
//!    stop after the dry run;
//! 6. exactly one result is posted per operation (a repeated delivery is ignored), carrying status,
//!    version and sizes only.
//!
//! The runner opens no listener and makes no request: the [`ResultSink`] the product passes in is
//! the only way out.

use std::collections::HashSet;

use jsonschema::{Draft, Registry, Validator};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// The event type the runner handles.
pub const MANAGED_REQUESTED: &str = "ever.registry.managed_operation.requested";

/// A managed operation kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ManagedOperationKind {
    /// Update the product.
    Update,
    /// Take a backup into the customer's own storage.
    Backup,
    /// Check that a backup restores.
    RestoreCheck,
    /// Report the installation's health.
    HealthReport,
}

/// The data of an `ever.registry.managed_operation.requested` event.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ManagedOperation {
    /// The operation (ULID).
    pub operation_id: String,
    /// The organization that asked for it.
    pub org_id: String,
    /// This installation.
    pub instance_id: String,
    /// What to do.
    pub kind: ManagedOperationKind,
    /// The closed per-kind parameters.
    pub params: Value,
    /// Not before (RFC 3339 UTC).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not_before: Option<String>,
    /// Expires at (RFC 3339 UTC).
    pub expires_at: String,
}

/// The status a result reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResultStatus {
    /// The operation succeeded.
    Succeeded,
    /// The operation failed or was refused.
    Failed,
}

/// The body of the result call: status, version and sizes only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManagedOperationResult {
    /// Succeeded or failed.
    pub status: ResultStatus,
    /// The product version after an update.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// An opaque reference of a backup in the customer's own storage.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artefact_ref: Option<String>,
    /// A size in bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size_bytes: Option<u64>,
}

impl ManagedOperationResult {
    /// A `failed` result with nothing else.
    #[must_use]
    pub fn failed() -> Self {
        Self {
            status: ResultStatus::Failed,
            version: None,
            artefact_ref: None,
            size_bytes: None,
        }
    }

    /// Keeps only well-formed values (a version, an opaque reference, a size).
    #[must_use]
    pub fn sanitized(self) -> Self {
        let version = self.version.filter(|v| is_semver(v));
        let artefact_ref = self.artefact_ref.filter(|r| is_artefact_ref(r));
        Self {
            status: self.status,
            version,
            artefact_ref,
            size_bytes: self.size_bytes,
        }
    }
}

/// The answer of a backup taken before an update.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct BackupResult {
    /// An opaque reference of the backup.
    pub artefact_ref: Option<String>,
    /// Its size in bytes.
    pub size_bytes: Option<u64>,
}

/// Implemented by a product. An `Err` from any hook becomes a `failed` result.
pub trait ManagedOperationExecutor {
    /// The kinds this installation can run.
    fn kinds(&self) -> Vec<ManagedOperationKind>;
    /// Checks that the operation can run now; always called first.
    ///
    /// # Errors
    /// A short, non-identifying reason when it cannot run.
    fn dry_run(&mut self, op: &ManagedOperation) -> Result<(), String>;
    /// Takes a backup; called before every update, after a successful dry run.
    ///
    /// # Errors
    /// A short reason when the backup failed (the update then never runs).
    fn backup_before_update(&mut self, op: &ManagedOperation) -> Result<BackupResult, String>;
    /// Runs the operation.
    ///
    /// # Errors
    /// A short reason when the operation failed.
    fn execute(&mut self, op: &ManagedOperation) -> Result<ManagedOperationResult, String>;
}

/// Sends the result call; the product wires it to its Ever Platform client.
pub trait ResultSink {
    /// Posts one result.
    ///
    /// # Errors
    /// When the call could not be made (the product's scheduler retries).
    fn post(&mut self, operation_id: &str, result: &ManagedOperationResult) -> Result<(), String>;
}

/// What happened to one event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunOutcome {
    /// Not a managed-operation request.
    Ignored,
    /// The operation was handled before.
    Duplicate,
    /// The data does not match the event schema.
    RefusedInvalid,
    /// The executor does not run this kind.
    RefusedKind,
    /// Past `expires_at`.
    Expired,
    /// Before `not_before`.
    Deferred,
    /// The dry run said no.
    DryRunFailed,
    /// A `dry_run_only` update.
    DryRunOnly,
    /// The backup before an update failed.
    BackupFailed,
    /// Executed; the result says how it went.
    Executed,
    /// The executor failed.
    ExecuteFailed,
}

/// The report of one handled event.
#[derive(Debug, Clone, PartialEq)]
pub struct RunReport {
    /// What happened.
    pub outcome: RunOutcome,
    /// The operation, when the event named a valid one.
    pub operation_id: Option<String>,
    /// The result posted, when one was.
    pub result: Option<ManagedOperationResult>,
    /// The executor hooks called, in order.
    pub calls: Vec<&'static str>,
}

/// Runs managed operations through a product's executor, one result per operation.
pub struct ManagedOperationRunner {
    validator: Validator,
    handled: HashSet<String>,
}

impl std::fmt::Debug for ManagedOperationRunner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ManagedOperationRunner")
            .field("handled", &self.handled.len())
            .finish()
    }
}

fn schema_text(file: &str) -> Option<&'static str> {
    ever_connect_contracts::event_schemas()
        .iter()
        .find(|(name, _)| *name == file)
        .map(|(_, text)| *text)
}

impl ManagedOperationRunner {
    /// A runner validating against the vendored event schema.
    ///
    /// # Errors
    /// When the embedded schemas do not compile (a build defect).
    pub fn new() -> Result<Self, String> {
        let common: Value = serde_json::from_str(
            schema_text("common.schema.json").ok_or("the common event schema is missing")?,
        )
        .map_err(|e| e.to_string())?;
        let data: Value = serde_json::from_str(
            schema_text("ever.registry.managed_operation.requested.v1.schema.json")
                .ok_or("the managed-operation schema is missing")?,
        )
        .map_err(|e| e.to_string())?;
        let common_id = common["$id"]
            .as_str()
            .ok_or("the common schema has no $id")?
            .to_owned();
        let registry = Registry::new()
            .add(common_id, Draft::Draft202012.create_resource(common))
            .map_err(|e| e.to_string())?
            .prepare()
            .map_err(|e| e.to_string())?;
        let validator = jsonschema::options()
            .with_draft(Draft::Draft202012)
            .with_registry(&registry)
            .build(&data)
            .map_err(|e| e.to_string())?;
        Ok(Self {
            validator,
            handled: HashSet::new(),
        })
    }

    /// Handles one feed event (`{type, data}`) at `now` (Unix seconds).
    pub fn handle(
        &mut self,
        event: &Value,
        now: i64,
        executor: &mut dyn ManagedOperationExecutor,
        sink: &mut dyn ResultSink,
    ) -> RunReport {
        let mut calls = Vec::new();
        if event["type"].as_str() != Some(MANAGED_REQUESTED) {
            return report(RunOutcome::Ignored, None, None, calls);
        }
        let data = &event["data"];
        let operation_id = data["operation_id"]
            .as_str()
            .filter(|s| is_ulid(s))
            .map(str::to_owned);
        if let Some(id) = &operation_id
            && self.handled.contains(id)
        {
            return report(RunOutcome::Duplicate, operation_id, None, calls);
        }
        let op: Option<ManagedOperation> = if self.validator.is_valid(data) {
            serde_json::from_value(data.clone()).ok()
        } else {
            None
        };
        let Some(op) = op else {
            return match operation_id {
                Some(id) => {
                    let posted = self.post(sink, &id, ManagedOperationResult::failed());
                    report(RunOutcome::RefusedInvalid, Some(id), posted, calls)
                }
                None => report(RunOutcome::RefusedInvalid, None, None, calls),
            };
        };
        let id = op.operation_id.clone();
        if !executor.kinds().contains(&op.kind) {
            let posted = self.post(sink, &id, ManagedOperationResult::failed());
            return report(RunOutcome::RefusedKind, Some(id), posted, calls);
        }
        if parse_rfc3339(&op.expires_at).is_none_or(|t| now >= t) {
            return report(RunOutcome::Expired, Some(id), None, calls);
        }
        if op
            .not_before
            .as_deref()
            .and_then(parse_rfc3339)
            .is_some_and(|t| now < t)
        {
            return report(RunOutcome::Deferred, Some(id), None, calls);
        }
        calls.push("dry_run");
        if executor.dry_run(&op).is_err() {
            let posted = self.post(sink, &id, ManagedOperationResult::failed());
            return report(RunOutcome::DryRunFailed, Some(id), posted, calls);
        }
        if op.kind == ManagedOperationKind::Update {
            if op.params["dry_run_only"].as_bool() == Some(true) {
                let ok = ManagedOperationResult {
                    status: ResultStatus::Succeeded,
                    version: None,
                    artefact_ref: None,
                    size_bytes: None,
                };
                let posted = self.post(sink, &id, ok);
                return report(RunOutcome::DryRunOnly, Some(id), posted, calls);
            }
            calls.push("backup_before_update");
            if executor.backup_before_update(&op).is_err() {
                let posted = self.post(sink, &id, ManagedOperationResult::failed());
                return report(RunOutcome::BackupFailed, Some(id), posted, calls);
            }
        }
        calls.push("execute");
        let (outcome, result) = match executor.execute(&op) {
            Ok(r) if r.status == ResultStatus::Succeeded => (RunOutcome::Executed, r),
            Ok(r) => (RunOutcome::ExecuteFailed, r),
            Err(_) => (RunOutcome::ExecuteFailed, ManagedOperationResult::failed()),
        };
        let posted = self.post(sink, &id, result);
        report(outcome, Some(id), posted, calls)
    }

    fn post(
        &mut self,
        sink: &mut dyn ResultSink,
        id: &str,
        result: ManagedOperationResult,
    ) -> Option<ManagedOperationResult> {
        let result = result.sanitized();
        self.handled.insert(id.to_owned());
        // A failed post is the product scheduler's to retry; the operation still counts as handled.
        let _ = sink.post(id, &result);
        Some(result)
    }
}

fn report(
    outcome: RunOutcome,
    operation_id: Option<String>,
    result: Option<ManagedOperationResult>,
    calls: Vec<&'static str>,
) -> RunReport {
    RunReport {
        outcome,
        operation_id,
        result,
        calls,
    }
}

fn is_ulid(s: &str) -> bool {
    s.len() == 26
        && s.bytes().all(|b| {
            b.is_ascii_digit()
                || (b.is_ascii_uppercase() && !matches!(b, b'I' | b'L' | b'O' | b'U'))
        })
}

fn is_artefact_ref(s: &str) -> bool {
    (1..=64).contains(&s.len())
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b':' | b'-'))
}

fn is_semver(s: &str) -> bool {
    let (core, suffix) = s.split_once('-').map_or((s, None), |(c, x)| (c, Some(x)));
    let parts: Vec<&str> = core.split('.').collect();
    parts.len() == 3
        && parts
            .iter()
            .all(|p| (1..=4).contains(&p.len()) && p.bytes().all(|b| b.is_ascii_digit()))
        && suffix.is_none_or(|x| {
            (1..=16).contains(&x.len()) && x.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'.')
        })
}

/// Unix seconds of an RFC 3339 UTC timestamp (`YYYY-MM-DDTHH:MM:SS[.fff]Z`).
#[must_use]
pub fn parse_rfc3339(s: &str) -> Option<i64> {
    let b = s.as_bytes();
    if b.len() < 20
        || b[4] != b'-'
        || b[7] != b'-'
        || b[10] != b'T'
        || b[13] != b':'
        || b[16] != b':'
        || !s.ends_with('Z')
    {
        return None;
    }
    let num = |from: usize, to: usize| s.get(from..to)?.parse::<i64>().ok();
    let (y, m, d) = (num(0, 4)?, num(5, 7)?, num(8, 10)?);
    let (hh, mm, ss) = (num(11, 13)?, num(14, 16)?, num(17, 19)?);
    if !(1..=12).contains(&m) || !(1..=31).contains(&d) || hh > 23 || mm > 59 || ss > 60 {
        return None;
    }
    // Days from the civil date (proleptic Gregorian), then seconds.
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    Some(days * 86_400 + hh * 3_600 + mm * 60 + ss)
}
