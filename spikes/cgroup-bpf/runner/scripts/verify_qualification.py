#!/usr/bin/env python3
# Copyright (c) 2022 Nitro Agility S.r.l.
# SPDX-License-Identifier: Apache-2.0

"""Verify a complete B1-B8 plus uninstall authoritative qualification set."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any


EMPTY_DIFF_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
EXPECTED_GATES = (*tuple(f"B{number}" for number in range(1, 9)), "UNINSTALL")
NEGATIVE_RESOLVE_OUTCOMES = (
    "identity_mismatch",
    "integrity_failure",
    "not_found",
    "queue_refusal",
    "revoked",
    "stale_generation",
    "timeout",
    "unavailable",
)


class VerificationError(Exception):
    """A qualification invariant was not proved."""


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise VerificationError(f"{path}: cannot read JSON: {error}") from error
    if not isinstance(value, dict):
        raise VerificationError(f"{path}: expected a JSON object")
    return value


def require(condition: bool, message: str) -> None:
    if not condition:
        raise VerificationError(message)


def checksum_count(run: Path) -> int:
    sums = run / "SHA256SUMS"
    try:
        lines = sums.read_text(encoding="utf-8").splitlines()
    except OSError as error:
        raise VerificationError(f"{sums}: cannot read: {error}") from error
    count = 0
    recorded: set[Path] = set()
    pattern = re.compile(r"^([0-9a-f]{64})  (?:\*)?(.*)$")
    root = run.resolve()
    for line_number, line in enumerate(lines, 1):
        match = pattern.fullmatch(line)
        require(match is not None, f"{sums}:{line_number}: malformed checksum line")
        expected, relative = match.groups()
        relative = relative.removeprefix("./")
        unresolved = run / relative
        candidate = unresolved.resolve()
        require(
            candidate != root and root in candidate.parents,
            f"{sums}:{line_number}: checksum path escapes run: {relative}",
        )
        require(unresolved.is_file(), f"{sums}:{line_number}: missing file: {relative}")
        require(not unresolved.is_symlink(), f"{sums}:{line_number}: symlink is not valid evidence: {relative}")
        require(candidate not in recorded, f"{sums}:{line_number}: duplicate checksum path: {relative}")
        actual = hashlib.sha256(candidate.read_bytes()).hexdigest()
        require(actual == expected, f"{run.name}: checksum mismatch: {relative}")
        recorded.add(candidate)
        count += 1
    require(count > 0, f"{sums}: empty checksum manifest")
    present = {
        path.resolve()
        for path in run.rglob("*")
        if path.is_file() and path != sums
    }
    missing = sorted(str(path.relative_to(root)) for path in present - recorded)
    require(not missing, f"{run.name}: files absent from SHA256SUMS: {', '.join(missing)}")
    return count


def source_fingerprint(run: Path) -> str:
    path = run / "source-fingerprint.txt"
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as error:
        raise VerificationError(f"{path}: cannot read: {error}") from error
    require(bool(lines), f"{path}: empty fingerprint")
    require(re.fullmatch(r"[0-9a-f]{40}", lines[0]) is not None, f"{path}: invalid commit")
    require(
        len(lines) > 1 and lines[1].split(maxsplit=1)[0] == EMPTY_DIFF_SHA256,
        f"{run.name}: source fingerprint records a non-empty working-tree diff",
    )
    return lines[0]


def verdict_files_pass(run: Path) -> None:
    verdicts = sorted(run.rglob("verdict.txt"))
    require(bool(verdicts), f"{run.name}: no case/group verdict files found")
    for path in verdicts:
        value = path.read_text(encoding="utf-8").strip()
        require(value == "PASS", f"{run.name}: {path.relative_to(run)} verdict is {value!r}")
    for name in ("result.json", "cleanup.json"):
        for path in sorted(run.rglob(name)):
            value = load_json(path)
            if "verdict" in value:
                require(
                    value["verdict"] == "PASS",
                    f"{run.name}: {path.relative_to(run)} verdict is {value['verdict']!r}",
                )


def verify_stop_classifications(run: Path) -> int:
    classifications = sorted(run.rglob("stop-classification.txt"))
    require(bool(classifications), f"{run.name}: stop-classification evidence is missing")
    prune_races = 0
    for path in classifications:
        value = path.read_text(encoding="utf-8").strip()
        require(
            value in {"NATIVE", "SYSTEMD_PRUNE_RACE"},
            f"{run.name}: {path.relative_to(run)} has invalid stop classification {value!r}",
        )
        prune_races += int(value == "SYSTEMD_PRUNE_RACE")
    return prune_races


def verify_b1(run: Path) -> None:
    summary = load_json(run / "summary.json")
    qualified = summary.get("qualified", {})
    require(
        qualified.get("unnamed_external_ancestor_preserved") is True,
        f"{run.name}: B1 does not qualify preservation of an unnamed external ancestor program",
    )
    require(
        qualified.get("unnamed_external_changed_tag_refused") is True,
        f"{run.name}: B1 does not qualify changed-tag refusal for an unnamed external program",
    )

    result = load_json(run / "cases/unnamed_external/result.json")
    require(result.get("verdict") == "PASS", f"{run.name}: B1 unnamed external case is not PASS")
    positive = result.get("positive", {})
    require(positive.get("startup_ready") is True, f"{run.name}: B1 unnamed external startup was not READY")
    require(
        positive.get("effective_on_execution_subtree") is True,
        f"{run.name}: B1 unnamed program was not effective on the Execution subtree",
    )
    require(
        positive.get("bpftool_name") == "ABSENT_OR_EMPTY",
        f"{run.name}: B1 did not prove that bpftool reports an absent or empty program name",
    )
    require(
        positive.get("program_preserved_by_uninstall") is True
        and positive.get("link_preserved_by_uninstall") is True,
        f"{run.name}: B1 uninstall did not preserve the unnamed external object",
    )

    negative = result.get("negative", {})
    original_id = positive.get("program_id")
    replacement_id = negative.get("program_id")
    original_tag = positive.get("tag")
    replacement_tag = negative.get("tag")
    require(
        isinstance(original_id, int)
        and isinstance(replacement_id, int)
        and original_id != replacement_id,
        f"{run.name}: B1 unnamed replacement program IDs are invalid or equal",
    )
    require(
        isinstance(original_tag, str)
        and bool(original_tag)
        and isinstance(replacement_tag, str)
        and bool(replacement_tag)
        and replacement_tag != original_tag
        and negative.get("tag_differs_from_original") is True,
        f"{run.name}: B1 unnamed replacement tag did not change",
    )
    require(
        negative.get("replacement_name") == "ABSENT_OR_EMPTY"
        and negative.get("refusal_class") == "UNKNOWN"
        and negative.get("exit_code") == 21,
        f"{run.name}: B1 unnamed changed-tag replacement was not refused as Unknown",
    )
    require(
        negative.get("replacement_preserved_during_refusal") is True,
        f"{run.name}: B1 changed-tag refusal modified the external replacement",
    )
    control = result.get("control", {})
    require(
        control.get("original_identity_restored") is True
        and control.get("startup_ready") is True
        and control.get("uninstall_preserved_external_program") is True,
        f"{run.name}: B1 unnamed external recovery control is incomplete",
    )
    require(
        result.get("cleanup", {}).get("soglia_owned_resources_absent") is True,
        f"{run.name}: B1 unnamed external case left Soglia-owned resources",
    )
    contract = load_json(run / "cases/resolver_contract/result.json")
    require(contract.get("verdict") == "PASS", f"{run.name}: B1 Resolve contract case is not PASS")
    require(contract.get("typed_exit_code") == 20, f"{run.name}: B1 Resolve refusal is not exit class 20")
    require(contract.get("ready_emitted") is False, f"{run.name}: B1 emitted READY after refusal")
    require(contract.get("backend_start_called") is False, f"{run.name}: B1 started the backend before refusal")
    expected = {"wrong_version", "wrong_max_pending", "wrong_workers", "malformed", "absent"}
    require(set(contract.get("cases", {})) == expected, f"{run.name}: B1 Resolve contract cases are incomplete")
    for name, case in contract["cases"].items():
        require(
            case.get("verdict") == "PASS"
            and case.get("refusal_class") == "INCOMPATIBLE"
            and case.get("stable_exit_code") == 20
            and case.get("durable_inventory_byte_identical") is True,
            f"{run.name}: B1 Resolve contract case {name} is incomplete",
        )


def verify_phase2_contract(run: Path, expected: set[str]) -> dict[str, Any]:
    contract = load_json(run / "phase2-contract/result.json")
    require(contract.get("verdict") == "PASS", f"{run.name}: Phase-2 contract is not PASS")
    cases = contract.get("cases", {})
    require(set(cases) == expected, f"{run.name}: Phase-2 contract cases are incomplete")
    require(
        all(case.get("verdict") == "PASS" for case in cases.values()),
        f"{run.name}: a Phase-2 contract case is not PASS",
    )
    return contract


def verify_b2(run: Path) -> None:
    verify_phase2_contract(
        run,
        {
            "out_of_order_replies_are_correlated_to_their_request_ids",
            "cancellation_before_write_removes_the_request_without_a_frame",
            "a_cancelled_caller_cannot_desynchronize_the_next_exchange",
            "pending_after_the_publication_deadline_times_out_without_poisoning",
            "complete_after_the_publication_deadline_is_still_consumed",
        },
    )


def verify_b3(run: Path) -> None:
    verify_phase2_contract(
        run,
        {
            "lifecycle_writer_has_priority_over_new_resolve_readers",
            "out_of_order_replies_are_correlated_to_their_request_ids",
        },
    )


def verify_b5(run: Path) -> None:
    steering = load_json(run / "driver/proxy-steering-boundary.json")
    require(steering.get("verdict") == "PASS", f"{run.name}: B5 steering verdict is not PASS")
    require(
        steering.get("proxy_steering_layer") == "outside BPF",
        f"{run.name}: B5 does not prove that proxy steering is outside BPF",
    )
    require(steering.get("no_writes_to_destination_fields") is True, f"{run.name}: B5 destination fields may be written")
    require(steering.get("bpf_bind_absent") is True, f"{run.name}: B5 found bpf_bind")
    require(steering.get("runtime", {}).get("destinations_match") is True, f"{run.name}: B5 runtime destinations differ")
    contract = load_json(run / "phase2-contract/result.json")
    direct = contract.get("direct_ipv4", {})
    require(
        contract.get("verdict") == "PASS"
        and direct.get("resolve_required_before_effect") is True
        and direct.get("veth_syn_packets") == 0
        and direct.get("execution_nft_drop_path_packets") == 0,
        f"{run.name}: B5 does not prove zero effect before a successful Resolve",
    )


def verify_b6(run: Path) -> None:
    case = run / "cases/sandbox_sigkill"
    offline = load_json(case / "target-offline-contract.json")
    require(offline.get("verdict") == "PASS", f"{run.name}: B6 offline contract is not PASS")
    require(offline.get("open_after_removal", {}).get("errno") == 116, f"{run.name}: B6 exact handle did not return ESTALE")
    for key in ("retained_cgroup_procs_write", "retained_clone_into_cgroup"):
        operation = offline.get(key, {})
        require(
            operation.get("result") == -1 and isinstance(operation.get("errno"), int) and operation["errno"] > 0,
            f"{run.name}: B6 offline process-admission operation {key} was not refused",
        )
    result = load_json(case / "result.json")
    released = result.get("target_released", {})
    require(released.get("exact_link_detaches_verified") == 6, f"{run.name}: B6 did not verify six exact link detaches")
    require(released.get("new_authorization_maps_empty") is True, f"{run.name}: B6 recovered maps are not empty")
    state = load_json(case / "state-after-restart.json")
    require(
        state.get("phase") == "READY" and state.get("generation") == released.get("new_generation"),
        f"{run.name}: B6 recovered generation is not READY",
    )
    startup = re.findall(
        r"event\.name=cgroup_bpf\.startup result=PASS generation=(\d+).* readiness=READY",
        (case / "journal.txt").read_text(encoding="utf-8"),
    )
    require(
        bool(startup) and int(startup[-1]) == released.get("new_generation"),
        f"{run.name}: B6 does not record READY-last startup for the recovered generation",
    )


def verify_b7(run: Path) -> None:
    summary = load_json(run / "summary.json")
    require(
        summary.get("qualified", {}).get("within_envelope_resolve_outcomes_clean") is True,
        f"{run.name}: B7 summary does not prove clean within-envelope Resolve outcomes",
    )
    resolve_files = sorted(run.glob("profiles/M*/resolve-health/*.json"))
    require(bool(resolve_files), f"{run.name}: B7 Resolve-health evidence is missing")
    for path in resolve_files:
        if path.name == "burst.json":
            continue
        totals = load_json(path).get("workload_totals", {})
        for outcome in NEGATIVE_RESOLVE_OUTCOMES:
            require(totals.get(outcome) == 0, f"{run.name}: {path.relative_to(run)} has {outcome}={totals.get(outcome)!r}")
    burst = load_json(run / "profiles/M3/burst-characterization.json")
    require(burst.get("verdict") == "PASS", f"{run.name}: B7 burst verdict is not PASS")
    requested = burst.get("requested")
    succeeded = burst.get("succeeded")
    refused = burst.get("refused")
    require(
        isinstance(requested, int)
        and isinstance(succeeded, int)
        and isinstance(refused, int)
        and requested == succeeded + refused,
        f"{run.name}: B7 burst requested count differs from succeeded plus refused",
    )
    attempts = burst.get("effects", {}).get("outbound_connection_attempts", {})
    require(
        attempts.get("distinct_connection_attempts") == succeeded,
        f"{run.name}: B7 burst outbound attempts differ from successful connections",
    )
    require(
        attempts.get("raw_syn_packets")
        == attempts.get("distinct_connection_attempts", 0)
        + attempts.get("duplicate_or_retransmitted_syn_packets", 0),
        f"{run.name}: B7 raw SYN accounting is inconsistent",
    )
    effects = burst.get("effects", {})
    require(
        effects.get("rejected_connection_outbound_attempts") == 0,
        f"{run.name}: B7 refused connections produced outbound attempts",
    )
    require(
        effects.get("rejected_connection_outbound_accepts") == 0,
        f"{run.name}: B7 refused connections produced outbound accepts",
    )
    require(
        burst.get("resolve_health", {}).get("workload_totals", {}).get("queue_refusal") == refused,
        f"{run.name}: B7 burst refusal count is inconsistent",
    )
    control = burst.get("immediate_control", {}).get("body", {})
    require(control.get("succeeded") == 1, f"{run.name}: B7 post-burst control connection did not succeed")
    dns = effects.get("dns_packet_delta", {})
    require(dns.get("tcp") == 0 and dns.get("udp") == 0, f"{run.name}: B7 refused burst produced DNS traffic")


def verify_b8(run: Path) -> None:
    summary = load_json(run / "summary.json")
    profile = summary.get("profile", {})
    require(
        profile.get("max_pending_resolves") == 64
        and profile.get("resolve_workers") == 4
        and profile.get("target_rate_per_second") == 500
        and profile.get("duration_seconds") == 60,
        f"{run.name}: B8 supported profile differs from the approved contract",
    )
    require(profile.get("p99_us", 20_001) <= 20_000, f"{run.name}: B8 client p99 exceeds 20 ms")
    require(profile.get("achieved_rate_per_second", 0) >= 475, f"{run.name}: B8 achieved rate is below 95%")
    evidence = load_json(run / "profiles/B8/b8-characterization.json")
    supported = evidence.get("supported_profile", {})
    measurement = supported.get("measurement", {})
    require(
        measurement.get("requested") == 30_000
        and measurement.get("succeeded") == 30_000
        and measurement.get("failed") == 0
        and measurement.get("expected_status") == 403
        and supported.get("correct_correlations") is True
        and supported.get("negative_outcomes") == 0,
        f"{run.name}: B8 supported load has missing, negative or miscorrelated outcomes",
    )
    supported_effects = supported.get("effects", {})
    supported_dns = supported_effects.get("dns_packet_delta", {})
    supported_attempts = supported_effects.get("outbound_attempts", {})
    require(
        supported.get("post_resolve_decision") == "policy_denied"
        and supported_effects.get("outbound_accept_delta") == 0
        and supported_dns.get("tcp") == 0
        and supported_dns.get("udp") == 0
        and supported_attempts.get("distinct_connection_attempts") == 0,
        f"{run.name}: B8 Resolve-only supported load caused an external effect",
    )
    burst = evidence.get("burst", {})
    require(burst.get("verdict") == "PASS", f"{run.name}: B8 burst is not PASS")
    require(
        burst.get("requested") == burst.get("succeeded", 0) + burst.get("refused", 0),
        f"{run.name}: B8 burst accounting is not exact",
    )
    effects = burst.get("effects", {})
    dns = effects.get("dns_packet_delta", {})
    require(
        effects.get("rejected_connection_outbound_attempts") == 0
        and effects.get("rejected_connection_outbound_accepts") == 0
        and dns.get("tcp") == 0
        and dns.get("udp") == 0,
        f"{run.name}: B8 refused burst caused an external effect",
    )
    require(
        evidence.get("baseline_return", {}).get("verdict") == "PASS",
        f"{run.name}: B8 did not return to its resource baseline",
    )
    require(
        evidence.get("mixed", {}).get("limits_respected") is True,
        f"{run.name}: B8 mixed workload exceeded a configured limit",
    )
    ramp = evidence.get("ramp", {})
    require(ramp.get("pass_criterion") is False, f"{run.name}: B8 ramp became a PASS criterion")
    require(
        ramp.get("declared_rate_cap_per_second", 0) > 2_000,
        f"{run.name}: B8 ramp did not extend beyond 2,000 resolves/s",
    )
    breakpoint = ramp.get("breakpoint")
    if breakpoint is None:
        require(
            ramp.get("breakpoint_reached") is False
            and ramp.get("stop_reason") == "breakpoint_not_reached_within_declared_cap"
            and ramp.get("steps", [{}])[-1].get("requested_rate_per_second")
            == ramp.get("declared_rate_cap_per_second"),
            f"{run.name}: B8 ramp stopped without a breakpoint or a declared-cap explanation",
        )
    else:
        require(
            ramp.get("breakpoint_reached") is True
            and ramp.get("stop_reason") == "breakpoint_reached"
            and breakpoint.get("breakpoint") is True
            and bool(breakpoint.get("breakpoint_reasons")),
            f"{run.name}: B8 ramp breakpoint has no typed stopping reason",
        )
    faults = evidence.get("fault_injection", {})
    require(faults.get("verdict") == "PASS", f"{run.name}: B8 fault injection is not PASS")
    expected_faults = {
        "duplicate_id", "unknown_id", "out_of_order", "cancel_before_write",
        "cancel_after_write", "partial_frame", "wrong_version",
        "writer_or_exchange_watchdog", "worker_blocked", "worker_panic",
        "malformed_result", "lifecycle_write_contention", "helper_exit",
    }
    require(set(faults.get("cases", {})) == expected_faults, f"{run.name}: B8 fault cases are incomplete")
    require(
        all(case.get("verdict") == "PASS" for case in faults["cases"].values()),
        f"{run.name}: one or more B8 fault cases are not PASS",
    )


def verify_uninstall(run: Path) -> None:
    summary = load_json(run / "summary.json")
    cases = summary.get("cases", {})
    expected = {
        "fresh_host",
        "interrupted_startup_pin_root",
        "normal_service_stop",
        "known_compatible",
        "live_runtime_refusal",
        "incompatible_refusal",
        "unknown_refusal",
        "unsupported_refusal",
        "nonempty_refusal",
        "interrupted_resume",
        "target_released",
    }
    require(set(cases) == expected, f"{run.name}: uninstall case set is incomplete")
    for name in sorted(expected):
        require(cases.get(name) == "PASS", f"{run.name}: uninstall case {name} is not PASS")
    residues = sorted(run.glob("cases/*/residue-before-harness-teardown.json"))
    require(bool(residues), f"{run.name}: uninstall pre-teardown residue evidence is missing")
    for path in residues:
        value = load_json(path)
        require(
            value.get("measured_before_harness_teardown") is True
            and value.get("owned_residue") is False,
            f"{run.name}: {path.relative_to(run)} does not prove zero residue before harness teardown",
        )


def verify_run(run: Path) -> dict[str, Any]:
    require(run.is_dir(), f"run directory does not exist: {run}")
    summary = load_json(run / "summary.json")
    gate = summary.get("gate")
    require(gate in EXPECTED_GATES, f"{run.name}: invalid or missing gate {gate!r}")
    require(summary.get("run_id") == run.name, f"{run.name}: summary run_id does not match directory")
    require(summary.get("authoritative") is True, f"{run.name}: run is not authoritative")
    require(summary.get("verdict") == "PASS", f"{run.name}: summary verdict is not PASS")
    cleanup = summary.get("cleanup", {})
    require(isinstance(cleanup, dict) and cleanup.get("verdict") == "PASS", f"{run.name}: cleanup verdict is not PASS")
    baseline = summary.get("production_source_baseline", {})
    require(baseline.get("matches") is True, f"{run.name}: production baseline does not match")
    require(re.fullmatch(r"[0-9a-f]{40}", str(baseline.get("commit", ""))) is not None, f"{run.name}: invalid production baseline")
    checksums = checksum_count(run)
    commit = source_fingerprint(run)
    verdict_files_pass(run)
    systemd_prune_races = verify_stop_classifications(run)
    if gate == "B1":
        verify_b1(run)
    elif gate == "B2":
        verify_b2(run)
    elif gate == "B3":
        verify_b3(run)
    elif gate == "B5":
        verify_b5(run)
    elif gate == "B6":
        verify_b6(run)
    elif gate == "B7":
        verify_b7(run)
    elif gate == "B8":
        verify_b8(run)
    elif gate == "UNINSTALL":
        verify_uninstall(run)
    return {
        "gate": gate,
        "run_id": run.name,
        "checksums": checksums,
        "source_commit": commit,
        "production_baseline": baseline["commit"],
        "systemd_prune_races": systemd_prune_races,
        "verdict": "PASS",
    }


def verify_manifest(results: list[dict[str, Any]], path: Path | None) -> str:
    commits = {result["source_commit"] for result in results}
    if path is None:
        require(len(commits) == 1, "qualification runs have different harness commits")
        return "single_commit"
    manifest = load_json(path)
    require(manifest.get("schema") == 1, f"{path}: unsupported manifest schema")
    declared = manifest.get("runs")
    require(isinstance(declared, dict), f"{path}: runs must be an object")
    require(set(declared) == set(EXPECTED_GATES), f"{path}: manifest must declare exactly B1-B8 and UNINSTALL")
    require(manifest.get("production_baseline") == results[0]["production_baseline"], f"{path}: baseline mismatch")
    for result in results:
        expected = declared[result["gate"]]
        require(expected.get("run_id") == result["run_id"], f"{path}: unexpected run for {result['gate']}")
        require(expected.get("source_commit") == result["source_commit"], f"{path}: unexpected source commit for {result['gate']}")
    return "reviewed_manifest_exception" if len(commits) > 1 else "single_commit_manifest"


def verify(runs: list[Path], manifest: Path | None = None) -> dict[str, Any]:
    require(len(runs) == 9, "qualification requires exactly nine run directories")
    results = [verify_run(run) for run in runs]
    order = {gate: index for index, gate in enumerate(EXPECTED_GATES)}
    results.sort(key=lambda result: order[result["gate"]])
    require(
        tuple(result["gate"] for result in results) == EXPECTED_GATES,
        "qualification must contain exactly one run for each gate B1-B8 and UNINSTALL",
    )
    baselines = {result["production_baseline"] for result in results}
    require(len(baselines) == 1, "qualification runs have different production baselines")
    commit_policy = verify_manifest(results, manifest)
    return {
        "schema": 1,
        "verdict": "PASS",
        "production_baseline": results[0]["production_baseline"],
        "harness_commit_policy": commit_policy,
        "total_checksums": sum(result["checksums"] for result in results),
        "runs": results,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("runs", nargs="+", type=Path)
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--json-output", type=Path)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        result = verify(args.runs, args.manifest)
    except (VerificationError, OSError, json.JSONDecodeError) as error:
        result = {"schema": 1, "verdict": "FAIL", "reason": str(error)}
        exit_code = 1
    else:
        exit_code = 0
    encoded = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.json_output is not None:
        args.json_output.parent.mkdir(parents=True, exist_ok=True)
        args.json_output.write_text(encoded, encoding="utf-8")
    print(f"RESULT: {result['verdict']}")
    if result["verdict"] == "PASS":
        print(f"Production baseline: {result['production_baseline']}")
        print(f"Checksums verified: {result['total_checksums']}")
        for run in result["runs"]:
            print(
                f"{run['gate']}: {run['run_id']} ({run['checksums']} checksums, "
                f"{run['systemd_prune_races']} SYSTEMD_PRUNE_RACE)"
            )
    else:
        print(f"Reason: {result['reason']}", file=sys.stderr)
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
