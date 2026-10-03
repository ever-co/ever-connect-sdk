//! The managed-operation runner against the feed fixtures.
#![cfg(feature = "managed")]
#![allow(clippy::unwrap_used, clippy::expect_used, missing_docs)]

use std::path::Path;

use ever_connect_sdk::managed::{
    BackupResult, ManagedOperation, ManagedOperationExecutor, ManagedOperationKind,
    ManagedOperationResult, ManagedOperationRunner, ResultSink, ResultStatus, RunOutcome,
    parse_rfc3339,
};
use serde_json::Value;

const NOW: i64 = 1_793_620_800; // 2026-11-02T12:00:00Z

fn event(name: &str) -> Value {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../contracts/fixtures/feed")
        .join(format!("{name}.json"));
    let page: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    page["events"][0].clone()
}

#[derive(Default)]
struct Recorder {
    kinds: Vec<ManagedOperationKind>,
    calls: Vec<String>,
    fail_backup: bool,
    fail_dry_run: bool,
}

impl ManagedOperationExecutor for Recorder {
    fn kinds(&self) -> Vec<ManagedOperationKind> {
        self.kinds.clone()
    }
    fn dry_run(&mut self, op: &ManagedOperation) -> Result<(), String> {
        self.calls.push(format!("dry_run:{:?}", op.kind));
        if self.fail_dry_run {
            Err("window closed".into())
        } else {
            Ok(())
        }
    }
    fn backup_before_update(&mut self, _op: &ManagedOperation) -> Result<BackupResult, String> {
        self.calls.push("backup_before_update".into());
        if self.fail_backup {
            Err("no space".into())
        } else {
            Ok(BackupResult {
                artefact_ref: Some("bk-1".into()),
                size_bytes: Some(1024),
            })
        }
    }
    fn execute(&mut self, op: &ManagedOperation) -> Result<ManagedOperationResult, String> {
        self.calls.push(format!("execute:{:?}", op.kind));
        Ok(ManagedOperationResult {
            status: ResultStatus::Succeeded,
            version: Some("1.5.0".into()),
            artefact_ref: None,
            size_bytes: Some(2048),
        })
    }
}

#[derive(Default)]
struct Sink(Vec<(String, ManagedOperationResult)>);

impl ResultSink for Sink {
    fn post(&mut self, id: &str, result: &ManagedOperationResult) -> Result<(), String> {
        self.0.push((id.to_owned(), result.clone()));
        Ok(())
    }
}

fn all_kinds() -> Vec<ManagedOperationKind> {
    vec![
        ManagedOperationKind::Update,
        ManagedOperationKind::Backup,
        ManagedOperationKind::RestoreCheck,
        ManagedOperationKind::HealthReport,
    ]
}

#[test]
fn managed_update_always_backs_up_first_and_posts_one_result() {
    let mut runner = ManagedOperationRunner::new().unwrap();
    let mut exec = Recorder {
        kinds: all_kinds(),
        ..Recorder::default()
    };
    let mut sink = Sink::default();
    let report = runner.handle(
        &event("managed-operation-requested.update"),
        NOW,
        &mut exec,
        &mut sink,
    );
    assert_eq!(report.outcome, RunOutcome::Executed);
    assert_eq!(
        exec.calls,
        ["dry_run:Update", "backup_before_update", "execute:Update"]
    );
    assert_eq!(sink.0.len(), 1);
    assert_eq!(sink.0[0].1.version.as_deref(), Some("1.5.0"));
}

#[test]
fn managed_unknown_kind_gives_one_failed_result_and_no_execute() {
    let mut runner = ManagedOperationRunner::new().unwrap();
    let mut exec = Recorder {
        kinds: vec![ManagedOperationKind::Backup],
        ..Recorder::default()
    };
    let mut sink = Sink::default();
    let report = runner.handle(
        &event("managed-operation-requested.health-report"),
        NOW,
        &mut exec,
        &mut sink,
    );
    assert_eq!(report.outcome, RunOutcome::RefusedKind);
    assert!(exec.calls.is_empty());
    assert_eq!(sink.0.len(), 1);
    assert_eq!(sink.0[0].1, ManagedOperationResult::failed());
}

#[test]
fn managed_out_of_schema_params_give_one_failed_result_and_nothing_runs() {
    for name in [
        "managed-operation-requested.update.invalid-unknown-param",
        "managed-operation-requested.restore-check.invalid-unknown-param",
        "managed-operation-requested.backup.invalid-missing-params",
    ] {
        let mut runner = ManagedOperationRunner::new().unwrap();
        let mut exec = Recorder {
            kinds: all_kinds(),
            ..Recorder::default()
        };
        let mut sink = Sink::default();
        let report = runner.handle(&event(name), NOW, &mut exec, &mut sink);
        assert_eq!(report.outcome, RunOutcome::RefusedInvalid, "{name}");
        assert!(exec.calls.is_empty(), "{name}");
        assert_eq!(sink.0.len(), 1, "{name}");
        assert_eq!(sink.0[0].1.status, ResultStatus::Failed, "{name}");
    }
}

#[test]
fn managed_one_result_per_operation() {
    let mut runner = ManagedOperationRunner::new().unwrap();
    let mut exec = Recorder {
        kinds: all_kinds(),
        ..Recorder::default()
    };
    let mut sink = Sink::default();
    let e = event("managed-operation-requested.backup");
    assert_eq!(
        runner.handle(&e, NOW, &mut exec, &mut sink).outcome,
        RunOutcome::Executed
    );
    assert_eq!(
        runner.handle(&e, NOW, &mut exec, &mut sink).outcome,
        RunOutcome::Duplicate
    );
    assert_eq!(sink.0.len(), 1);
}

#[test]
fn managed_failed_backup_or_dry_run_never_executes() {
    let mut runner = ManagedOperationRunner::new().unwrap();
    let mut exec = Recorder {
        kinds: all_kinds(),
        fail_backup: true,
        ..Recorder::default()
    };
    let mut sink = Sink::default();
    let report = runner.handle(
        &event("managed-operation-requested.update"),
        NOW,
        &mut exec,
        &mut sink,
    );
    assert_eq!(report.outcome, RunOutcome::BackupFailed);
    assert!(!exec.calls.iter().any(|c| c.starts_with("execute")));
    let mut runner = ManagedOperationRunner::new().unwrap();
    let mut exec = Recorder {
        kinds: all_kinds(),
        fail_dry_run: true,
        ..Recorder::default()
    };
    let mut sink = Sink::default();
    let report = runner.handle(
        &event("managed-operation-requested.backup"),
        NOW,
        &mut exec,
        &mut sink,
    );
    assert_eq!(report.outcome, RunOutcome::DryRunFailed);
    assert_eq!(exec.calls, ["dry_run:Backup"]);
}

#[test]
fn managed_expired_operations_never_run_and_other_events_are_ignored() {
    let mut runner = ManagedOperationRunner::new().unwrap();
    let mut exec = Recorder {
        kinds: all_kinds(),
        ..Recorder::default()
    };
    let mut sink = Sink::default();
    let late = parse_rfc3339("2026-11-04T00:00:00Z").unwrap();
    let report = runner.handle(
        &event("managed-operation-requested.backup"),
        late,
        &mut exec,
        &mut sink,
    );
    assert_eq!(report.outcome, RunOutcome::Expired);
    let other: Value = serde_json::json!({"type": "ever.registry.instance.seen", "data": {}});
    assert_eq!(
        runner.handle(&other, NOW, &mut exec, &mut sink).outcome,
        RunOutcome::Ignored
    );
    assert!(sink.0.is_empty() && exec.calls.is_empty());
}

#[test]
fn managed_results_keep_status_and_sizes_only() {
    let r = ManagedOperationResult {
        status: ResultStatus::Succeeded,
        version: Some("not a version".into()),
        artefact_ref: Some("../etc/passwd".into()),
        size_bytes: Some(1),
    }
    .sanitized();
    assert_eq!(
        r,
        ManagedOperationResult {
            status: ResultStatus::Succeeded,
            version: None,
            artefact_ref: None,
            size_bytes: Some(1)
        }
    );
    assert_eq!(parse_rfc3339("2026-11-02T12:00:00Z"), Some(NOW));
    assert_eq!(parse_rfc3339("2026-11-02 12:00"), None);
}
