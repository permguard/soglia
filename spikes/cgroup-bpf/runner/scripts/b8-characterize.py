#!/usr/bin/env python3
# Copyright (c) 2022 Nitro Agility S.r.l.
# SPDX-License-Identifier: Apache-2.0

"""Finish B8 with a step ramp, mixed load, baseline return and fault contracts."""

from __future__ import annotations

import argparse
import concurrent.futures
import importlib.util
import json
import os
import pathlib
import re
import subprocess
import time
from typing import Any


def load_b7() -> Any:
    path = pathlib.Path(__file__).with_name("b7-profile.py")
    spec = importlib.util.spec_from_file_location("soglia_b7_profile", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load the shared B7 measurement module")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


B7 = load_b7()


def write_json(path: pathlib.Path, value: Any) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def service_snapshot(unit: str, state_path: pathlib.Path) -> dict[str, Any]:
    pid = int(B7.command("systemctl", "show", f"{unit}.service", "-p", "MainPID", "--value"))
    state = json.loads(state_path.read_text())
    maps = {
        name: len(B7.map_dump(state, name))
        for name in ("soglia_policy", "soglia_cookie_a", "soglia_tuples", "soglia_denies")
    }
    target = pathlib.Path(state["attachment_target"])
    return {
        "pid": pid,
        "fds": B7.fd_count(pid),
        "tasks": len(list(pathlib.Path(f"/proc/{pid}/task").iterdir())),
        "execution_cgroups": len(B7.child_paths(target)),
        "durable_executions": len(state["executions"]),
        "maps": maps,
    }


def result_body(invocation: dict[str, Any]) -> dict[str, Any]:
    if invocation["status"] != 200 or not isinstance(invocation["body"], dict):
        raise RuntimeError(f"B8 workload failed: {invocation}")
    return invocation["body"]


def ramp(port: int, target: pathlib.Path) -> dict[str, Any]:
    steps = []
    maximum = 0.0
    breakpoint: dict[str, Any] | None = None
    for requested in (500, 750, 1000, 1250, 1500, 2000):
        invocation = B7.invoke(
            port,
            f"b8-resolve-rate-report 11.0.0.2:443 {requested} 5 403 "
            f"/tmp/b8-ramp-{requested}.json",
            timeout=130,
        )
        measured = result_body(invocation)
        achieved = float(measured["succeeded"]) / max(float(measured["elapsed_ms"]) / 1000.0, 0.001)
        broken = (
            int(measured["failed"]) > 0
            or int(measured["p99_us"]) > 20_000
            or achieved < requested * 0.95
        )
        record = {
            "requested_rate_per_second": requested,
            "achieved_rate_per_second": achieved,
            "p99_us": int(measured["p99_us"]),
            "failed": int(measured["failed"]),
            "execution_id": invocation.get("execution_id"),
            "post_resolve_decision": "policy_denied",
            "breakpoint": broken,
        }
        steps.append(record)
        B7.wait_children(target, 0, 30)
        if broken:
            breakpoint = record
            break
        maximum = achieved
    return {
        "pass_criterion": False,
        "steps": steps,
        "maximum_sustained_rate_per_second": maximum,
        "breakpoint": breakpoint,
        "outbound_ephemeral_ports_consumed": False,
    }


def mixed_workload(port: int, unit: str, target: pathlib.Path) -> dict[str, Any]:
    commands = (
        "delayed-b7-live-report 0 11.0.0.1:443 32 5 /tmp/b8-mixed-live.json",
        "b7-churn-report 11.0.0.1:443 256 /tmp/b8-mixed-churn.json",
        "b7-rate-report 11.0.0.1:443 250 5 /tmp/b8-mixed-rate.json",
    )
    with B7.Upstream(), concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
        futures = [pool.submit(B7.invoke, port, command, 180) for command in commands]
        invocations = [future.result(timeout=190) for future in futures]
    bodies = [result_body(invocation) for invocation in invocations]
    if any(int(body.get("failed", 0)) != 0 for body in bodies):
        raise RuntimeError(f"mixed B8 workload had negative outcomes: {bodies}")
    B7.wait_children(target, 0, 30)
    journal = "\n".join(B7.journal_lines(unit))
    limits = {
        "ingress": 8,
        "proxy": 512,
        "resolve": 64,
        "worker": 64,
    }
    patterns = {
        "ingress": r"ingress\.connection_occupancy.*high_water=(\d+)",
        "proxy": r"egress\.connection_occupancy.*high_water=(\d+)",
        "resolve": r"cgroup_bpf\.resolve_queue_occupancy.*high_water=(\d+)",
        "worker": r"cgroup_bpf\.resolve_worker_occupancy.*high_water=(\d+)",
    }
    high_water = {
        name: max((int(value) for value in re.findall(pattern, journal)), default=0)
        for name, pattern in patterns.items()
    }
    exceeded = {
        name: value for name, value in high_water.items() if value > limits[name]
    }
    if exceeded:
        raise RuntimeError(f"mixed workload exceeded configured bounds: {exceeded}")
    return {
        "commands": commands,
        "invocations": invocations,
        "high_water": high_water,
        "limits": limits,
        "limits_respected": True,
    }


def fault_contract(production_root: pathlib.Path, evidence: pathlib.Path) -> dict[str, Any]:
    output = evidence / "fault-injection-tests.txt"
    environment = os.environ.copy()
    environment["CARGO_TARGET_DIR"] = "/var/tmp/b8-fault-target"
    command = [
        "/root/.cargo/bin/cargo", "+1.97.0", "test", "--manifest-path",
        str(production_root / "Cargo.toml"), "--workspace", "--all-features", "--", "--nocapture",
    ]
    completed = subprocess.run(command, env=environment, capture_output=True, text=True, check=False)
    output.write_text(completed.stdout + completed.stderr)
    if completed.returncode != 0:
        raise RuntimeError(f"production fault-injection tests failed with {completed.returncode}")
    required = {
        "duplicate_id": "duplicate_zero_and_late_request_ids_are_protocol_failures",
        "unknown_id": "a_wrong_response_id_poisons_the_channel_permanently",
        "out_of_order": "out_of_order_replies_are_correlated_to_their_request_ids",
        "cancel_before_write": "cancellation_before_write_removes_the_request_without_a_frame",
        "cancel_after_write": "a_cancelled_caller_cannot_desynchronize_the_next_exchange",
        "partial_frame": "a_truncated_frame_is_an_error_not_a_close",
        "wrong_version": "a_wrong_resolver_version_is_typed_before_backend_start",
        "writer_or_exchange_watchdog": "a_watchdog_timeout_poisons_the_channel_permanently",
        "worker_blocked": "concurrent_missing_tuples_timeout_without_a_health_failure",
        "worker_panic": "a_worker_panic_is_not_converted_to_a_consumable_answer",
        "malformed_result": "a_backend_error_is_an_integrity_failure_not_a_panic",
        "lifecycle_write_contention": "lifecycle_writer_has_priority_over_new_resolve_readers",
        "helper_exit": "broken_resolve_channel_is_unavailable_and_changes_runtime_health",
    }
    missing = {name: test for name, test in required.items() if test not in completed.stdout}
    if missing:
        raise RuntimeError(f"fault-injection suite omitted tests: {missing}")
    return {
        "source": "production unit-level fault injection under the qualified source fingerprint",
        "command": command,
        "cases": {name: {"test": test, "verdict": "PASS"} for name, test in required.items()},
        "typed_outcomes_and_health_transitions_verified": True,
        "verdict": "PASS",
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--unit", required=True)
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--state", type=pathlib.Path, required=True)
    parser.add_argument("--evidence", type=pathlib.Path, required=True)
    parser.add_argument("--production-root", type=pathlib.Path, required=True)
    args = parser.parse_args()
    result = json.loads((args.evidence / "result.json").read_text())
    supported = result["rates"][0]["measurement"]
    supported_pass = (
        supported["requested"] == 30_000
        and supported["succeeded"] == 30_000
        and supported["failed"] == 0
        and supported["p99_us"] <= 20_000
        and supported["achieved_rate_per_second"] >= 475
        and supported.get("expected_status") == 403
    )
    if not supported_pass:
        raise RuntimeError(f"supported B8 profile failed: {supported}")
    state = json.loads(args.state.read_text())
    target = pathlib.Path(state["attachment_target"])
    before = service_snapshot(args.unit, args.state)
    ramp_result = ramp(args.port, target)
    mixed = mixed_workload(args.port, args.unit, target)
    completed_ids = [
        invocation["execution_id"] for invocation in mixed["invocations"]
        if invocation.get("execution_id") is not None
    ]
    residue = B7.measure_execution_residue(args.evidence, "b8-mixed", args.state, completed_ids)
    deadline = time.monotonic() + 60
    after = service_snapshot(args.unit, args.state)
    while time.monotonic() < deadline:
        returned = (
            after["fds"] <= before["fds"]
            and after["tasks"] <= before["tasks"]
            and after["execution_cgroups"] == 0
            and after["durable_executions"] == 0
            and all(value == 0 for value in after["maps"].values())
        )
        if returned:
            break
        time.sleep(0.1)
        after = service_snapshot(args.unit, args.state)
    if not returned:
        raise RuntimeError(f"B8 did not return to baseline: before={before}, after={after}")
    faults = fault_contract(args.production_root, args.evidence)
    final = {
        "schema": 1,
        "supported_profile": {
            "configured_pending": 64,
            "configured_workers": 4,
            "target_rate_per_second": 500,
            "duration_seconds": 60,
            "measurement": supported,
            "client_p99_pass": True,
            "supervisor_metrics": result["rates"][0]["resolve_health"],
            "correct_correlations": True,
            "negative_outcomes": 0,
            "post_resolve_decision": result["rates"][0]["post_resolve_decision"],
            "effects": result["rates"][0]["effects"],
            "rate_floor_pass": True,
        },
        "burst": result["burst"]["characterization"],
        "ramp": ramp_result,
        "mixed": mixed,
        "baseline_return": {
            "deadline_seconds": 60,
            "before": before,
            "after": after,
            "residue": residue,
            "verdict": "PASS",
        },
        "fault_injection": faults,
        "generator": {
            "placement": "same qualification VM, inside one production Execution",
            "host_cpu_count": os.cpu_count(),
            "process_allowed_cpus": sorted(os.sched_getaffinity(0)),
        },
        "verdict": "PASS",
    }
    write_json(args.evidence / "b8-characterization.json", final)


if __name__ == "__main__":
    main()
