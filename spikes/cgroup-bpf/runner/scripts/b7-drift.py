#!/usr/bin/env python3
# Copyright (c) 2022 Nitro Agility S.r.l.
# SPDX-License-Identifier: Apache-2.0

"""Inject one B7 integrity drift and prove the production one-way transition."""

from __future__ import annotations

import argparse
import json
import pathlib
import socket
import subprocess
import threading
import time


def run(*args: str) -> bytes:
    return subprocess.check_output(args, stderr=subprocess.STDOUT)


def pinned_info(kind: str, path: pathlib.Path | str) -> dict[str, object]:
    completed = subprocess.run(
        ["bpftool", "-j", kind, "show", "pinned", str(path)],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    try:
        value = json.loads(completed.stdout)
    except json.JSONDecodeError as error:
        raise RuntimeError(
            f"bpftool could not describe pinned {kind} {path}: "
            f"exit={completed.returncode} output={completed.stdout!r}"
        ) from error
    if not isinstance(value, dict) or "id" not in value:
        raise RuntimeError(f"bpftool returned invalid pinned {kind} information: {value}")
    value["qualification_bpftool_exit_status"] = completed.returncode
    return value


def invoke(port: int, body: str, result: dict[str, object]) -> None:
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=5) as stream:
            stream.settimeout(40)
            request = (
                "POST /v1/execute/workload HTTP/1.1\r\nHost: soglia\r\n"
                "Content-Type: text/plain\r\n"
                f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n{body}"
            )
            stream.sendall(request.encode())
            response = bytearray()
            while chunk := stream.recv(65536):
                response.extend(chunk)
        result["response"] = response.decode(errors="replace")
    except Exception as error:  # the fail-closed transition is expected to break this request
        result["error"] = repr(error)


def wait_ready(port: int) -> None:
    started = time.monotonic()
    while time.monotonic() - started < 15:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                return
        except OSError:
            time.sleep(0.05)
    raise RuntimeError("production ingress did not become ready")


def wait_active_execution(
    state_path: pathlib.Path,
    target: pathlib.Path,
    request: dict[str, object],
) -> dict[str, object]:
    started = time.monotonic()
    last_state: dict[str, object] = {}
    while time.monotonic() - started < 10:
        if "response" in request or "error" in request:
            raise RuntimeError(
                f"drift control invocation finished before ACTIVE: {request}"
            )
        try:
            last_state = json.loads(state_path.read_text())
        except (FileNotFoundError, json.JSONDecodeError):
            time.sleep(0.02)
            continue
        executions = last_state.get("executions", {})
        active = [
            (tag, record)
            for tag, record in executions.items()
            if record.get("phase") == "ACTIVE"
        ]
        if len(active) == 1 and (target / active[0][0]).is_dir():
            return last_state
        time.sleep(0.02)
    raise RuntimeError(
        f"drift control invocation did not become ACTIVE: state={last_state} request={request}"
    )


def remove_injected_pins(pins: list[dict[str, object]]) -> dict[str, object]:
    removed: list[dict[str, object]] = []
    parents: set[pathlib.Path] = set()
    for item in pins:
        path = pathlib.Path(str(item["path"]))
        kind = str(item["kind"])
        info = pinned_info(kind, path)
        if int(info["id"]) != int(item["id"]):
            raise RuntimeError(f"refusing to remove changed qualification pin {path}")
        path.unlink()
        if path.exists():
            raise RuntimeError(f"qualification pin was not removed: {path}")
        removed.append({**item, "observed_before_removal": info})
        parents.add(path.parent)
    for parent in sorted(parents, key=lambda path: len(path.parts), reverse=True):
        parent.rmdir()
        if parent.exists():
            raise RuntimeError(f"qualification pin directory was not removed: {parent}")
    return {
        "wildcard_deletion": False,
        "removed_exact_pins": removed,
        "verdict": "PASS",
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=["foreign_link", "owned_link_detach"], required=True)
    parser.add_argument("--unit", required=True)
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--state", type=pathlib.Path, required=True)
    parser.add_argument("--evidence", type=pathlib.Path, required=True)
    parser.add_argument("--injector", required=True)
    parser.add_argument("--detacher", required=True)
    parser.add_argument("--foreign-object", required=True)
    args = parser.parse_args()
    args.evidence.mkdir(parents=True, exist_ok=True)
    wait_ready(args.port)
    state = json.loads(args.state.read_text())
    (args.evidence / "state-before.json").write_text(json.dumps(state, indent=2) + "\n")
    request: dict[str, object] = {}
    worker = threading.Thread(target=invoke, args=(args.port, "sleep 30000", request))
    worker.start()
    target = pathlib.Path(state["attachment_target"])
    active_state = wait_active_execution(args.state, target, request)
    mutation_started = time.monotonic()
    mutation: dict[str, object] = {
        "mode": args.mode,
        "started_monotonic": mutation_started,
        "active_state_before_mutation": active_state,
    }
    if args.mode == "foreign_link":
        root = pathlib.Path(state["pin_root"]).parent / "qualification-foreign"
        root.mkdir()
        run("bpftool", "prog", "loadall", args.foreign_object, str(root))
        program = pinned_info("prog", root / "foreign_allow")
        run(args.injector, str(program["id"]), "10", str(target), str(root / "foreign-link"))
        mutation["foreign_program"] = program
        mutation["foreign_link"] = pinned_info("link", root / "foreign-link")
        mutation["harness_injected_pins"] = []
        for path in sorted(root.iterdir()):
            kind = "link" if path.name == "foreign-link" else "prog"
            info = pinned_info(kind, path)
            mutation["harness_injected_pins"].append({
                "kind": kind,
                "path": str(path),
                "id": int(info["id"]),
                "observed": info,
            })
    else:
        link = next(item for item in state["links"] if item["name"] == "connect4")
        mutation["owned_link_before"] = pinned_info("link", link["pin"])
        run(args.detacher, link["pin"])
        mutation["owned_pin"] = link["pin"]
        mutation["harness_injected_pins"] = []
    main_pid = int(run("systemctl", "show", f"{args.unit}.service", "-p", "MainPID", "--value"))
    deadline = mutation_started + 3.0  # 1 s health interval plus deterministic 2 s tolerance.
    while time.monotonic() < deadline and pathlib.Path(f"/proc/{main_pid}").exists():
        time.sleep(0.02)
    transition_ms = int((time.monotonic() - mutation_started) * 1000)
    stopped = not pathlib.Path(f"/proc/{main_pid}").exists()
    worker.join(timeout=5)
    worker_finished = not worker.is_alive()
    cancelled_by_error = "error" in request
    cancelled_by_eof = request.get("response") == ""
    active_invocation_cancelled = worker_finished and (
        cancelled_by_error or cancelled_by_eof
    )
    admission_refused = False
    try:
        socket.create_connection(("127.0.0.1", args.port), timeout=0.2).close()
    except OSError:
        admission_refused = True
    journal = run("journalctl", "-u", f"{args.unit}.service", "-o", "cat", "--no-pager").decode()
    (args.evidence / "production-events.txt").write_text(journal)
    mutation.update({
        "health_interval_ms": 1000,
        "deterministic_tolerance_ms": 2000,
        "transition_ms": transition_ms,
        "process_stopped": stopped,
        "admission_refused": admission_refused,
        "request_worker_finished": worker_finished,
        "active_invocation_cancelled": active_invocation_cancelled,
        "active_invocation_cancel_reason": (
            "socket_error" if cancelled_by_error else
            "eof_without_response" if cancelled_by_eof else
            "not_cancelled"
        ),
        "request": request,
        "runtime_helper_lost_event": "runtime.helper_lost" in journal,
        "silent_in_process_repair": False,
    })
    if not all([
        stopped,
        admission_refused,
        active_invocation_cancelled,
        transition_ms <= 3000,
        "runtime.helper_lost" in journal,
    ]):
        mutation["verdict"] = "FAIL"
        (args.evidence / "result.json").write_text(json.dumps(mutation, indent=2) + "\n")
        raise RuntimeError(f"{args.mode} did not cause the required fail-closed transition")
    try:
        mutation["harness_injected_teardown"] = remove_injected_pins(
            mutation["harness_injected_pins"]
        )
    except Exception as error:
        mutation["harness_injected_teardown"] = {
            "wildcard_deletion": False,
            "verdict": "FAIL",
            "error": repr(error),
        }
        mutation["verdict"] = "FAIL"
        (args.evidence / "result.json").write_text(json.dumps(mutation, indent=2) + "\n")
        raise
    mutation["verdict"] = "PASS"
    (args.evidence / "result.json").write_text(json.dumps(mutation, indent=2) + "\n")
    (args.evidence / "verdict.txt").write_text("PASS\n")


if __name__ == "__main__":
    main()
