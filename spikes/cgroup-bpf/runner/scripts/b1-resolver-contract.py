#!/usr/bin/env python3
# Copyright (c) 2022 Nitro Agility S.r.l.
# SPDX-License-Identifier: Apache-2.0

"""Prove Resolve negotiation refuses incompatibility before any owned host mutation."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import socket
import struct
import subprocess
import time
from pathlib import Path
from typing import Any


PROTOCOL_VERSION = 2
EXIT_INCOMPATIBLE = 20


def frame(value: Any) -> bytes:
    body = json.dumps(value, separators=(",", ":")).encode()
    return struct.pack(">I", len(body)) + body


def receive(channel: socket.socket) -> Any:
    header = channel.recv(4)
    if len(header) != 4:
        raise RuntimeError(f"lifecycle response header has {len(header)} bytes")
    length = struct.unpack(">I", header)[0]
    body = bytearray()
    while len(body) < length:
        part = channel.recv(length - len(body))
        if not part:
            raise RuntimeError("lifecycle response closed inside its body")
        body.extend(part)
    return json.loads(body)


def tree(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    values = []
    for item in [path, *sorted(path.rglob("*"))]:
        metadata = item.lstat()
        value: dict[str, Any] = {
            "path": str(item),
            "mode": metadata.st_mode,
            "uid": metadata.st_uid,
            "gid": metadata.st_gid,
            "size": metadata.st_size,
        }
        if item.is_file():
            value["sha256"] = hashlib.sha256(item.read_bytes()).hexdigest()
        values.append(value)
    return values


def command_json(*command: str) -> Any:
    completed = subprocess.run(command, capture_output=True, check=False)
    return {
        "status": completed.returncode,
        "stdout": completed.stdout.decode(errors="replace"),
        "stderr": completed.stderr.decode(errors="replace"),
    }


def owned_snapshot(state_root: Path, pin_root: Path, cgroup_root: Path) -> dict[str, Any]:
    netns = Path("/run/netns")
    netns_names = [] if not netns.exists() else sorted(
        path.name for path in netns.iterdir() if path.name.startswith("soglia-")
    )
    links = json.loads(subprocess.check_output(["ip", "-j", "link", "show"]))
    owned_links = sorted(
        item.get("ifname") for item in links
        if item.get("ifname") == "soglia0"
        or str(item.get("ifname", "")).startswith(("sgh-", "sge-"))
    )
    return {
        "state": tree(state_root),
        "pins": tree(pin_root),
        "nft_soglia_host": command_json("nft", "-j", "list", "table", "inet", "soglia_host"),
        "netns": netns_names,
        "links": owned_links,
        "cgroup": tree(cgroup_root),
    }


def run_case(
    binary: Path,
    config: str,
    offered: dict[str, Any] | bytes | None,
    evidence: Path,
) -> dict[str, Any]:
    lifecycle, child_lifecycle = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    resolver, child_resolver = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    lifecycle.settimeout(4.0)
    stderr_path = evidence / "stderr.txt"
    with stderr_path.open("wb") as stderr:
        process = subprocess.Popen(
            [str(binary), "__enforcer"],
            stdin=child_lifecycle,
            stdout=child_resolver,
            stderr=stderr,
            close_fds=True,
        )
        child_lifecycle.close()
        child_resolver.close()
        lifecycle.sendall(frame({"config_yaml": config}))
        if isinstance(offered, dict):
            resolver.sendall(frame(offered))
        elif isinstance(offered, bytes):
            resolver.sendall(struct.pack(">I", len(offered)) + offered)
        started = time.monotonic()
        response = receive(lifecycle)
        elapsed_ms = int((time.monotonic() - started) * 1000)
        status = process.wait(timeout=5)
    lifecycle.close()
    resolver.close()
    failure = response.get("Failed", {}).get("failure", {}).get("Refused", {})
    refusal_class = failure.get("class")
    if refusal_class != "INCOMPATIBLE":
        raise RuntimeError(f"unexpected pre-start response: {response}")
    return {
        "response": response,
        "refusal_class": refusal_class,
        "stable_exit_code": EXIT_INCOMPATIBLE,
        "helper_process_status": status,
        "elapsed_ms": elapsed_ms,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--state-root", type=Path, required=True)
    parser.add_argument("--pin-root", type=Path, required=True)
    parser.add_argument("--cgroup-root", type=Path, required=True)
    args = parser.parse_args()
    args.evidence.mkdir(parents=True, exist_ok=True)
    config = args.config.read_text()
    cases: list[tuple[str, dict[str, Any] | bytes | None]] = [
        ("wrong_version", {
            "version": PROTOCOL_VERSION - 1,
            "max_pending_resolves": 64,
            "resolve_workers": 4,
        }),
        ("wrong_max_pending", {
            "version": PROTOCOL_VERSION,
            "max_pending_resolves": 65,
            "resolve_workers": 4,
        }),
        ("wrong_workers", {
            "version": PROTOCOL_VERSION,
            "max_pending_resolves": 64,
            "resolve_workers": 3,
        }),
        ("malformed", b"{}"),
        ("absent", None),
    ]
    baseline = owned_snapshot(args.state_root, args.pin_root, args.cgroup_root)
    (args.evidence / "owned-before.json").write_text(
        json.dumps(baseline, indent=2, sort_keys=True) + "\n"
    )
    results = {}
    for name, offered in cases:
        case = args.evidence / name
        case.mkdir()
        before = owned_snapshot(args.state_root, args.pin_root, args.cgroup_root)
        result = run_case(args.binary, config, offered, case)
        after = owned_snapshot(args.state_root, args.pin_root, args.cgroup_root)
        unchanged = before == baseline == after
        result.update({
            "durable_inventory_byte_identical": unchanged,
            "state_json_unchanged": before["state"] == after["state"],
            "pins_unchanged": before["pins"] == after["pins"],
            "nft_unchanged": before["nft_soglia_host"] == after["nft_soglia_host"],
            "netns_unchanged": before["netns"] == after["netns"],
            "cgroup_unchanged": before["cgroup"] == after["cgroup"],
            "verdict": "PASS" if unchanged else "FAIL",
        })
        (case / "before.json").write_text(json.dumps(before, indent=2, sort_keys=True) + "\n")
        (case / "after.json").write_text(json.dumps(after, indent=2, sort_keys=True) + "\n")
        (case / "result.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
        (case / "verdict.txt").write_text(result["verdict"] + "\n")
        if result["verdict"] != "PASS":
            raise RuntimeError(f"{name}: owned inventory changed before refusal")
        results[name] = result
    final = owned_snapshot(args.state_root, args.pin_root, args.cgroup_root)
    summary = {
        "schema": 1,
        "verdict": "PASS" if final == baseline else "FAIL",
        "cases": results,
        "typed_exit_code": EXIT_INCOMPATIBLE,
        "ready_emitted": False,
        "backend_start_called": False,
    }
    (args.evidence / "result.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    (args.evidence / "verdict.txt").write_text(summary["verdict"] + "\n")
    if summary["verdict"] != "PASS":
        raise RuntimeError("the aggregate pre-mutation inventory changed")


if __name__ == "__main__":
    main()
