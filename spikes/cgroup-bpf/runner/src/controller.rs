// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

use std::fs;
use std::io::Write;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

use serde::Serialize;

use crate::cli::RunOptions;
use crate::command::CommandExecutor;
use crate::context::TestContext;
use crate::environment;
use crate::evidence::{EvidenceRecorder, new_run_id, unix_ms};
use crate::final_audit;
use crate::journal::RunJournal;
use crate::model::{RunSummary, TestId, TestResult, Verdict};
use crate::resources::ResourceRegistry;
use crate::source;
use crate::tests::s0::S0;
use crate::tests::s1::S1;
use crate::tests::s1b::S1b;
use crate::tests::s2::S2;
use crate::tests::s3::S3;
use crate::tests::s4::S4;
use crate::tests::s5::S5;
use crate::tests::s6::S6;
use crate::tests::s7::S7;
use crate::tests::s8::S8;
use crate::tests::s10::S10;
use crate::tests::s11::S11;
use crate::tests::s12::S12;
use crate::tests::s13::S13;
use crate::tests::s14::S14;
use crate::tests::{SpikeTest, TestError};

#[derive(Serialize)]
struct RunRecord<'a> {
    run_id: &'a str,
    authoritative: bool,
    requested_only: Option<TestId>,
    requested_from: Option<TestId>,
    started_unix_ms: u128,
    runner_pid: u32,
}

pub fn doctor(options: RunOptions) -> Result<i32, String> {
    let (context, mut summary) = create_context(options)?;
    checkpoint(&context, "PREFLIGHT", None)?;
    let observation = environment::probe(
        &context.commands.with_scope("preflight"),
        &context.options.artifacts,
    )?;
    context
        .evidence
        .write_json("environment.json", &observation)
        .map_err(|error| format!("write environment evidence: {error}"))?;
    summary.verdict = observation.verdict;
    mark_remaining_not_executed(&mut summary);
    persist_summary(&context, &summary)?;
    context
        .journal
        .finish(observation.verdict, observation.detail.clone());
    context.journal.persist()?;
    println!("Preflight ........................ {}", observation.verdict);
    println!("Evidence: {}", context.evidence.root().display());
    Ok(observation.verdict.exit_code())
}

pub fn run(options: RunOptions) -> Result<i32, String> {
    let (mut context, mut summary) = create_context(options)?;
    let outcome = catch_unwind(AssertUnwindSafe(|| {
        persist_summary(&context, &summary)?;
        run_inner(&mut context, &mut summary)
    }));
    match outcome {
        Ok(Ok(code)) => Ok(code),
        Ok(Err(error)) => finalize_infrastructure_failure(
            &mut context,
            &mut summary,
            format!("infrastructure failure: {error}"),
            Verdict::InfraError.exit_code(),
        ),
        Err(_) => finalize_infrastructure_failure(
            &mut context,
            &mut summary,
            "internal runner panic outside the per-test boundary".to_owned(),
            Verdict::NotExecuted.exit_code(),
        ),
    }
}

fn run_inner(context: &mut TestContext, summary: &mut RunSummary) -> Result<i32, String> {
    let authoritative = context.authoritative;
    if authoritative && implemented_tests() != TestId::ALL.as_slice() {
        return Err("authoritative run refused: S0-S14 are not all implemented".to_owned());
    }
    checkpoint(context, "PREFLIGHT", None)?;
    let environment = environment::probe(
        &context.commands.with_scope("preflight"),
        &context.options.artifacts,
    )?;
    context
        .evidence
        .write_json("environment.json", &environment)
        .map_err(|error| format!("write environment evidence: {error}"))?;
    if !environment.verdict.is_pass() {
        summary.verdict = environment.verdict;
        mark_remaining_not_executed(summary);
        persist_summary(&context, &summary)?;
        context
            .journal
            .finish(environment.verdict, environment.detail.clone());
        context.journal.persist()?;
        println!("Preflight ........................ {}", environment.verdict);
        println!("Evidence: {}", context.evidence.root().display());
        return Ok(environment.verdict.exit_code());
    }
    if context.cancelled.load(Ordering::Relaxed) {
        return Err("run interrupted after preflight".to_owned());
    }
    checkpoint(context, "SOURCE_COLLECTION", None)?;
    let source = source::collect(
        &context.commands.with_scope("source"),
        &context.options.repository,
        &context.options.artifacts,
        &context.executable,
    )?;
    context
        .evidence
        .write_json("source.json", &source)
        .map_err(|error| format!("write source evidence: {error}"))?;
    if context.cancelled.load(Ordering::Relaxed) {
        return Err("run interrupted after source collection".to_owned());
    }
    if authoritative {
        checkpoint(context, "PRISTINE_VM_CLAIM", None)?;
        claim_pristine_vm(&context)?;
    }
    let selected = selected_tests(&context.options);
    for id in TestId::ALL {
        if !selected.contains(&id) {
            summary.results.push(not_executed(id, authoritative));
            continue;
        }
        if context.cancelled.load(Ordering::Relaxed) {
            let result = stopped_result(id, authoritative, Verdict::InfraError, "run cancelled");
            summary.stopped_at = Some(id);
            summary.verdict = result.verdict;
            summary.results.push(result);
            break;
        }
        checkpoint(context, format!("{}.STARTING", id.as_str()), Some(id))?;
        let result = match id {
            TestId::S0 => execute_test(&mut S0::new(&context), &mut *context),
            TestId::S1 => execute_test(&mut S1::new(&context), &mut *context),
            TestId::S1b => execute_test(&mut S1b::new(&context), &mut *context),
            TestId::S2 => execute_test(&mut S2::new(&context), &mut *context),
            TestId::S3 => execute_test(&mut S3::new(&context), &mut *context),
            TestId::S4 => execute_test(&mut S4::new(&context), &mut *context),
            TestId::S5 => execute_test(&mut S5::new(&context), &mut *context),
            TestId::S6 => execute_test(&mut S6::new(&context), &mut *context),
            TestId::S7 => execute_test(&mut S7::new(&context), &mut *context),
            TestId::S8 => execute_test(&mut S8::new(&context), &mut *context),
            TestId::S9 => execute_test(&mut S4::new_s9(&context), &mut *context),
            TestId::S10 => execute_test(&mut S10::new(&context), &mut *context),
            TestId::S11 => execute_test(&mut S11::new(&context), &mut *context),
            TestId::S12 => execute_test(&mut S12::new(&context), &mut *context),
            TestId::S13 => execute_test(&mut S13::new(&context), &mut *context),
            TestId::S14 => execute_test(&mut S14::new(&context), &mut *context),
        };
        println!("{:<4} ............................. {}", id, result.verdict);
        let passed = result.verdict.is_pass();
        if !passed {
            summary.stopped_at = Some(id);
            summary.verdict = result.verdict;
        }
        summary.results.push(result);
        persist_summary(&context, &summary)?;
        if !passed {
            break;
        }
    }
    mark_remaining_not_executed(summary);
    if summary
        .results
        .iter()
        .filter(|result| selected.contains(&result.test))
        .all(|result| result.verdict.is_pass())
    {
        summary.verdict = Verdict::Pass;
    }
    checkpoint(context, "FINAL_RESOURCE_SNAPSHOT", None)?;
    context
        .evidence
        .write_json("final/resources.json", context.resources.entries())
        .map_err(|error| format!("write final resource registry: {error}"))?;
    checkpoint(context, "FINAL_ENVIRONMENT", None)?;
    let environment_after = environment::probe(
        &context.commands.with_scope("final/environment"),
        &context.options.artifacts,
    )?;
    context
        .evidence
        .write_json("final/environment-after.json", &environment_after)
        .map_err(|error| format!("write final environment: {error}"))?;
    checkpoint(context, "FINAL_CLEANUP_AUDIT", None)?;
    let cleanup = final_audit::audit(
        &context.commands.with_scope("final/cleanup"),
        &context.resources,
        &context.run_id,
    );
    context
        .evidence
        .write_json("final/cleanup.json", &cleanup)
        .map_err(|error| format!("write final cleanup audit: {error}"))?;
    if !cleanup.pass {
        summary.verdict = Verdict::CleanupFail;
        if summary.stopped_at.is_none() {
            summary.stopped_at = selected.last().copied();
        }
    }
    persist_summary(&context, &summary)?;
    context
        .journal
        .finish(summary.verdict, format!("authoritative={authoritative}"));
    context.journal.persist()?;
    println!("RESULT: {}", summary.verdict);
    println!("Evidence: {}", context.evidence.root().display());
    Ok(summary.verdict.exit_code())
}

fn checkpoint(
    context: &TestContext,
    phase: impl Into<String>,
    current_test: Option<TestId>,
) -> Result<(), String> {
    context.journal.set_phase(phase, current_test);
    context.journal.persist()
}

fn finalize_infrastructure_failure(
    context: &mut TestContext,
    summary: &mut RunSummary,
    detail: String,
    exit_code: i32,
) -> Result<i32, String> {
    summary.verdict = Verdict::InfraError;
    mark_remaining_not_executed(summary);
    let _ = context
        .evidence
        .write_json("final/resources.json", context.resources.entries());
    context.journal.resources(context.resources.entries());
    context.journal.infrastructure_failure(detail.clone());
    context.journal.persist()?;
    persist_summary(context, summary)?;
    eprintln!("soglia-spike-runner: {detail}");
    eprintln!("Evidence: {}", context.evidence.root().display());
    Ok(exit_code)
}

fn create_context(options: RunOptions) -> Result<(TestContext, RunSummary), String> {
    let run_id = new_run_id();
    let authoritative = options.authoritative();
    let evidence = EvidenceRecorder::create(&options.evidence_base, &run_id)
        .map_err(|error| format!("create evidence root: {error}"))?;
    let journal = RunJournal::create(evidence.clone(), &run_id, authoritative)?;
    let commands =
        CommandExecutor::new(evidence.clone(), "preflight").with_journal(journal.clone());
    let cancelled = Arc::new(AtomicBool::new(false));
    for (signal, name) in [
        (signal_hook::consts::SIGINT, "SIGINT"),
        (signal_hook::consts::SIGTERM, "SIGTERM"),
        (signal_hook::consts::SIGHUP, "SIGHUP"),
    ] {
        if let Err(error) = signal_hook::flag::register(signal, Arc::clone(&cancelled)) {
            let detail = format!("register {name} handler: {error}");
            journal.infrastructure_failure(detail.clone());
            return Err(detail);
        }
    }
    let executable = match std::env::current_exe() {
        Ok(executable) => executable,
        Err(error) => {
            let detail = format!("resolve runner path: {error}");
            journal.infrastructure_failure(detail.clone());
            return Err(detail);
        }
    };
    let record = RunRecord {
        run_id: &run_id,
        authoritative,
        requested_only: options.only,
        requested_from: options.from,
        started_unix_ms: unix_ms(),
        runner_pid: std::process::id(),
    };
    if let Err(error) = evidence.write_json("run.json", &record) {
        let detail = format!("write run evidence: {error}");
        journal.infrastructure_failure(detail.clone());
        return Err(detail);
    }
    let summary = RunSummary {
        run_id: run_id.clone(),
        authoritative,
        verdict: Verdict::NotExecuted,
        results: Vec::new(),
        stopped_at: None,
        evidence_root: evidence.root().to_string_lossy().into_owned(),
    };
    Ok((
        TestContext {
            options,
            run_id,
            authoritative,
            evidence,
            journal: journal.clone(),
            commands,
            resources: ResourceRegistry::with_journal(journal),
            cancelled,
            executable,
            result_notes: Vec::new(),
        },
        summary,
    ))
}

fn implemented_tests() -> &'static [TestId] {
    &[
        TestId::S0,
        TestId::S1,
        TestId::S1b,
        TestId::S2,
        TestId::S3,
        TestId::S4,
        TestId::S5,
        TestId::S6,
        TestId::S7,
        TestId::S8,
        TestId::S9,
        TestId::S10,
        TestId::S11,
        TestId::S12,
        TestId::S13,
        TestId::S14,
    ]
}

fn selected_tests(options: &RunOptions) -> Vec<TestId> {
    if let Some(only) = options.only {
        return vec![only];
    }
    if let Some(from) = options.from {
        return TestId::ALL
            .into_iter()
            .skip_while(|id| *id != from)
            .filter(|id| implemented_tests().contains(id))
            .collect();
    }
    TestId::ALL.to_vec()
}

fn claim_pristine_vm(context: &TestContext) -> Result<(), String> {
    let directory = std::path::Path::new("/var/lib/soglia-spike-runner");
    let marker = directory.join("authoritative-run.json");
    if marker.exists() {
        return Err(format!(
            "authoritative run refused: pristine marker already exists at {}",
            marker.display()
        ));
    }
    fs::create_dir_all(directory)
        .map_err(|error| format!("create pristine marker directory: {error}"))?;
    fs::set_permissions(directory, fs::Permissions::from_mode(0o700))
        .map_err(|error| format!("secure pristine marker directory: {error}"))?;
    let metadata = fs::metadata(directory)
        .map_err(|error| format!("stat pristine marker directory: {error}"))?;
    if metadata.uid() != 0 || metadata.mode() & 0o777 != 0o700 {
        return Err(format!(
            "authoritative run refused: insecure pristine marker directory owner={} mode={:o}",
            metadata.uid(),
            metadata.mode() & 0o777
        ));
    }
    let value = serde_json::json!({"run_id": context.run_id, "claimed_unix_ms": unix_ms()});
    let bytes = serde_json::to_vec_pretty(&value).map_err(|error| error.to_string())?;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&marker)
        .map_err(|error| format!("atomically claim pristine VM: {error}"))?;
    file.write_all(&bytes)
        .and_then(|()| file.sync_all())
        .map_err(|error| format!("publish pristine marker: {error}"))
}

fn execute_test<T: SpikeTest>(test: &mut T, context: &mut TestContext) -> TestResult {
    let started_unix_ms = unix_ms();
    let started = Instant::now();
    let id = test.id();
    let _ = context.evidence.test_root(id.as_str());
    let _ = context.take_result_notes();
    let execution = catch_unwind(AssertUnwindSafe(|| -> Result<T::Observation, TestError> {
        context
            .journal
            .set_phase(format!("{}.PREPARE", id.as_str()), Some(id));
        test.prepare(context)?;
        context
            .journal
            .set_phase(format!("{}.EXECUTE", id.as_str()), Some(id));
        let observation = test.execute(context)?;
        context
            .evidence
            .write_json(format!("{id}/observations.json"), &observation)
            .map_err(|error| TestError::infra(format!("write observations: {error}")))?;
        context
            .journal
            .set_phase(format!("{}.VERIFY", id.as_str()), Some(id));
        test.verify(context, &observation)?;
        Ok(observation)
    }));
    let primary = match execution {
        Ok(Ok(_)) => Ok(()),
        Ok(Err(error)) => Err(error),
        Err(_) => Err(TestError::infra("internal runner panic during test")),
    };
    context
        .journal
        .set_phase(format!("{}.CLEANUP", id.as_str()), Some(id));
    let cleanup = test.cleanup(context).and_then(|()| {
        context
            .journal
            .set_phase(format!("{}.VERIFY_CLEANUP", id.as_str()), Some(id));
        test.verify_cleanup(context)
    });
    let (verdict, mut detail, cleanup_verdict) = match (primary, cleanup) {
        (Ok(()), Ok(())) => (
            Verdict::Pass,
            "invariant and cleanup proven".to_owned(),
            Verdict::Pass,
        ),
        (Ok(()), Err(error)) => (Verdict::CleanupFail, error.detail, Verdict::CleanupFail),
        (Err(error), Ok(())) => (error.verdict, error.detail, Verdict::Pass),
        (Err(error), Err(cleanup_error)) => (
            Verdict::CleanupFail,
            format!(
                "primary {}: {}; cleanup: {}",
                error.verdict, error.detail, cleanup_error.detail
            ),
            Verdict::CleanupFail,
        ),
    };
    let notes = context.take_result_notes();
    if !notes.is_empty() {
        detail.push_str("; ");
        detail.push_str(&notes.join("; "));
    }
    let mut result = TestResult {
        test: id,
        authoritative: context.authoritative,
        verdict,
        invariant: test.invariant().to_owned(),
        detail,
        cleanup: cleanup_verdict,
        started_unix_ms,
        duration_ms: started.elapsed().as_millis(),
    };
    if let Err(error) = context
        .evidence
        .write_json(format!("{id}/result.json"), &result)
    {
        result.verdict = Verdict::InfraError;
        result.detail = format!("persist test result: {error}");
    }
    if let Err(error) = context
        .evidence
        .write_json(format!("{id}/resources.json"), context.resources.entries())
    {
        result.verdict = Verdict::InfraError;
        result.detail = format!("persist test resource registry: {error}");
    }
    let _ = context
        .evidence
        .write_json(format!("{id}/result.json"), &result);
    context
        .journal
        .set_phase(format!("{}.COMPLETE", id.as_str()), Some(id));
    result
}

fn persist_summary(context: &TestContext, summary: &RunSummary) -> Result<(), String> {
    context
        .evidence
        .write_json("summary.json", summary)
        .map_err(|error| format!("write summary: {error}"))?;
    let mut markdown = format!(
        "# Spike replay {}\n\nAuthoritative: `{}`\n\n",
        summary.run_id, summary.authoritative
    );
    for result in &summary.results {
        markdown.push_str(&format!(
            "- {}: {} — {}\n",
            result.test, result.verdict, result.detail
        ));
    }
    markdown.push_str(&format!("\nResult: **{}**\n", summary.verdict));
    context
        .evidence
        .write_text("summary.md", &markdown)
        .map_err(|error| format!("write Markdown summary: {error}"))
}

fn not_executed(test: TestId, authoritative: bool) -> TestResult {
    stopped_result(test, authoritative, Verdict::NotExecuted, "not selected")
}

fn stopped_result(test: TestId, authoritative: bool, verdict: Verdict, detail: &str) -> TestResult {
    TestResult {
        test,
        authoritative,
        verdict,
        invariant: String::new(),
        detail: detail.to_owned(),
        cleanup: Verdict::NotExecuted,
        started_unix_ms: unix_ms(),
        duration_ms: 0,
    }
}

fn mark_remaining_not_executed(summary: &mut RunSummary) {
    let present = summary
        .results
        .iter()
        .map(|result| result.test)
        .collect::<Vec<_>>();
    for id in TestId::ALL {
        if !present.contains(&id) {
            summary
                .results
                .push(not_executed(id, summary.authoritative));
        }
    }
    summary.results.sort_by_key(|result| result.test);
}
