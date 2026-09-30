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
    started = time.monotonic()
    while time.monotonic() - started < 10 and not any(path.is_dir() for path in target.iterdir()):
        time.sleep(0.02)
    if not any(path.is_dir() for path in target.iterdir()):
        raise RuntimeError("drift control invocation never became live")
    mutation_started = time.monotonic()
    mutation: dict[str, object] = {"mode": args.mode, "started_monotonic": mutation_started}
    if args.mode == "foreign_link":
        root = pathlib.Path(state["pin_root"]).parent / "qualification-foreign"
        root.mkdir()
        run("bpftool", "prog", "loadall", args.foreign_object, str(root))
        program = json.loads(run("bpftool", "-j", "prog", "show", "pinned", str(root / "foreign_allow")))
        run(args.injector, str(program["id"]), "10", str(target), str(root / "foreign-link"))
        mutation["foreign_program"] = program
        mutation["foreign_link"] = json.loads(
            run("bpftool", "-j", "link", "show", "pinned", str(root / "foreign-link"))
        )
        mutation["harness_injected_pins"] = []
        for path in sorted(root.iterdir()):
            kind = "link" if path.name == "foreign-link" else "prog"
            info = json.loads(run("bpftool", "-j", kind, "show", "pinned", str(path)))
            mutation["harness_injected_pins"].append({
                "kind": kind,
                "path": str(path),
                "id": int(info["id"]),
                "observed": info,
            })
    else:
        link = next(item for item in state["links"] if item["name"] == "connect4")
        mutation["owned_link_before"] = json.loads(
            run("bpftool", "-j", "link", "show", "pinned", link["pin"])
        )
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
        "active_invocation_cancelled": "error" in request,
        "request": request,
        "runtime_helper_lost_event": "runtime.helper_lost" in journal,
        "silent_in_process_repair": False,
    })
    if not all([
        stopped,
        admission_refused,
        "error" in request,
        transition_ms <= 3000,
        "runtime.helper_lost" in journal,
    ]):
        mutation["verdict"] = "FAIL"
        (args.evidence / "result.json").write_text(json.dumps(mutation, indent=2) + "\n")
        raise RuntimeError(f"{args.mode} did not cause the required fail-closed transition")
    mutation["verdict"] = "PASS"
    (args.evidence / "result.json").write_text(json.dumps(mutation, indent=2) + "\n")
    (args.evidence / "verdict.txt").write_text("PASS\n")


if __name__ == "__main__":
    main()
