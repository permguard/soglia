#!/usr/bin/env python3
# Copyright (c) 2022 Nitro Agility S.r.l.
# SPDX-License-Identifier: Apache-2.0

"""Measure a stopped B7 generation, then tear down only its recorded resources."""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import subprocess
from typing import Any


def run(*args: str) -> bytes:
    return subprocess.check_output(args, stderr=subprocess.STDOUT)


def json_run(*args: str) -> Any:
    return json.loads(run(*args))


def write_json(path: pathlib.Path, value: Any) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def tree(root: pathlib.Path) -> tuple[list[str], list[str]]:
    if not root.exists():
        return [], []
    files: list[str] = []
    directories = [str(root)]
    for current, names, filenames in os.walk(root):
        current_path = pathlib.Path(current)
        directories.extend(str(current_path / name) for name in names)
        files.extend(str(current_path / name) for name in filenames)
    return sorted(files), sorted(set(directories))


def pinned_info(kind: str, path: str) -> dict[str, Any]:
    completed = subprocess.run(
        ["bpftool", "-j", kind, "show", "pinned", path],
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


def injected_pins(path: pathlib.Path | None) -> list[dict[str, Any]]:
    if path is None:
        return []
    value = json.loads(path.read_text())
    pins = value.get("harness_injected_pins", [])
    if not isinstance(pins, list):
        raise RuntimeError("drift result has an invalid harness_injected_pins field")
    return pins


def verify(args: argparse.Namespace) -> None:
    state = json.loads(args.state.read_text())
    if state["executions"]:
        raise RuntimeError("persistent generation still contains per-Execution records")
    registered = [
        {"kind": "link", "path": item["pin"], "id": int(item["id"])}
        for item in state["links"]
    ] + [
        {"kind": "map", "path": item["pin"], "id": int(item["id"])}
        for item in state["maps"]
    ]
    deliberate = injected_pins(args.drift_result)
    expected_pins = registered + deliberate
    expected_paths = sorted(item["path"] for item in expected_pins)
    if len(state["programs"]) != 6 or len(state["links"]) != 6 \
            or len(state["maps"]) != 7 or len(registered) != 13:
        raise RuntimeError("recorded persistent generation is not exactly 6/6/7/13")

    actual_pin_files, actual_pin_directories = tree(args.pin_parent)
    expected_pin_directories = {
        str(args.pin_parent),
        str(args.configured_pin_root),
        state["pin_root"],
        str(pathlib.Path(state["pin_root"]) / "links"),
        str(pathlib.Path(state["pin_root"]) / "maps"),
    }
    for item in deliberate:
        expected_pin_directories.add(str(pathlib.Path(item["path"]).parent))
    unknown_pin_files = sorted(set(actual_pin_files) - set(expected_paths))
    unknown_pin_directories = sorted(set(actual_pin_directories) - expected_pin_directories)

    runtime_root = args.state.parent.parent
    expected_runtime_files = sorted([
        str(args.state),
        str(runtime_root / "lock"),
        str(runtime_root / "net" / "host.json"),
    ])
    expected_runtime_directories = {
        str(args.runtime_parent),
        str(runtime_root),
        str(runtime_root / "cgroup-bpf"),
        str(runtime_root / "net"),
        str(runtime_root / "sandbox"),
        str(runtime_root / "bundles"),
        str(runtime_root / "runc"),
    }
    actual_runtime_files, actual_runtime_directories = tree(args.runtime_parent)
    unknown_runtime_files = sorted(set(actual_runtime_files) - set(expected_runtime_files))
    missing_runtime_files = sorted(set(expected_runtime_files) - set(actual_runtime_files))
    unknown_runtime_directories = sorted(
        set(actual_runtime_directories) - expected_runtime_directories
    )

    pin_evidence = []
    for item in expected_pins:
        info = pinned_info(item["kind"], item["path"])
        pin_evidence.append({**item, "observed": info})
        if int(info["id"]) != int(item["id"]):
            raise RuntimeError(f"pinned {item['kind']} identity changed: {item}")
    programs = json_run("bpftool", "-j", "prog", "show")
    live_program_ids = {int(item["id"]) for item in programs}
    missing_programs = sorted(
        int(item["id"]) for item in state["programs"]
        if int(item["id"]) not in live_program_ids
    )

    host_record = json.loads((runtime_root / "net" / "host.json").read_text())
    clean = not any([
        unknown_pin_files,
        unknown_pin_directories,
        unknown_runtime_files,
        unknown_runtime_directories,
        missing_runtime_files,
        missing_programs,
        sorted(actual_pin_files) != expected_paths,
        host_record.get("dummy") != "soglia0",
    ])
    result = {
        "measurement": "persistent generation after production stop",
        "harness_deletion_before_measurement": False,
        "registered_inventory": {
            "programs": len(state["programs"]),
            "links": len(state["links"]),
            "maps": len(state["maps"]),
            "pins": len(registered),
            "state_json": str(args.state),
        },
        "deliberate_qualification_drift": deliberate,
        "expected_pin_paths": expected_paths,
        "actual_pin_paths": actual_pin_files,
        "pin_evidence": pin_evidence,
        "unknown_pin_files": unknown_pin_files,
        "unknown_pin_directories": unknown_pin_directories,
        "expected_runtime_files": expected_runtime_files,
        "actual_runtime_files": actual_runtime_files,
        "unknown_runtime_files": unknown_runtime_files,
        "missing_runtime_files": missing_runtime_files,
        "unknown_runtime_directories": unknown_runtime_directories,
        "missing_program_ids": missing_programs,
        "host_record": host_record,
        "teardown_permitted": clean,
        "verdict": "PASS" if clean else "CLEANUP_FAIL",
    }
    write_json(args.output, result)
    if not clean:
        raise RuntimeError("unknown or missing resource found before B7 harness teardown")


def remove_file(path: pathlib.Path, expected_id: int | None, kind: str | None) -> None:
    if not path.exists():
        raise RuntimeError(f"recorded teardown path vanished: {path}")
    if expected_id is not None and kind is not None:
        info = pinned_info(kind, str(path))
        if int(info["id"]) != expected_id:
            raise RuntimeError(f"refusing to remove changed {kind} pin {path}")
    path.unlink()
    if path.exists():
        raise RuntimeError(f"exact teardown did not remove {path}")


def remove_directory(path: pathlib.Path) -> None:
    path.rmdir()
    if path.exists():
        raise RuntimeError(f"exact teardown did not remove directory {path}")


def teardown(args: argparse.Namespace) -> None:
    measured = json.loads(args.measurement.read_text())
    if measured.get("verdict") != "PASS" or not measured.get("teardown_permitted"):
        raise RuntimeError("refusing teardown without a clean pre-teardown measurement")
    removed: list[str] = []
    for item in reversed(measured["pin_evidence"]):
        path = pathlib.Path(item["path"])
        remove_file(path, int(item["id"]), item["kind"])
        removed.append(str(path))
    pin_directories = sorted(
        {pathlib.Path(path).parent for path in measured["expected_pin_paths"]},
        key=lambda path: len(path.parts),
        reverse=True,
    )
    generation_root = pathlib.Path(measured["pin_evidence"][0]["path"]).parents[1]
    for path in pin_directories + [generation_root, args.configured_pin_root]:
        if path.exists():
            remove_directory(path)
            removed.append(str(path))

    run("nft", "delete", "table", "inet", "soglia_host")
    run("ip", "link", "delete", "soglia0")
    runtime_root = args.state.parent.parent
    for path in [runtime_root / "net" / "host.json", args.state, runtime_root / "lock"]:
        remove_file(path, None, None)
        removed.append(str(path))
    for path in [
        runtime_root / "cgroup-bpf",
        runtime_root / "net",
        runtime_root / "sandbox",
        runtime_root / "bundles",
        runtime_root / "runc",
        runtime_root,
    ]:
        remove_directory(path)
        removed.append(str(path))

    remaining_pin_files, remaining_pin_directories = tree(args.pin_parent)
    remaining_runtime_files, remaining_runtime_directories = tree(args.runtime_parent)
    result = {
        "measurement": "harness exact teardown after residue measurements",
        "source": str(args.measurement),
        "wildcard_deletion": False,
        "removed_exact_paths": removed,
        "remaining_pin_files": remaining_pin_files,
        "remaining_pin_directories": remaining_pin_directories,
        "remaining_runtime_files": remaining_runtime_files,
        "remaining_runtime_directories": remaining_runtime_directories,
        "verdict": "PASS" if not remaining_pin_files and not remaining_runtime_files else "FAIL",
    }
    write_json(args.output, result)
    if result["verdict"] != "PASS":
        raise RuntimeError("exact teardown left files behind")


def main() -> None:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="action", required=True)
    for action in ["verify", "teardown"]:
        sub = subparsers.add_parser(action)
        sub.add_argument("--state", type=pathlib.Path, required=True)
        sub.add_argument("--runtime-parent", type=pathlib.Path, required=True)
        sub.add_argument("--pin-parent", type=pathlib.Path, required=True)
        sub.add_argument("--configured-pin-root", type=pathlib.Path, required=True)
        sub.add_argument("--output", type=pathlib.Path, required=True)
        if action == "verify":
            sub.add_argument("--drift-result", type=pathlib.Path)
        else:
            sub.add_argument("--measurement", type=pathlib.Path, required=True)
    args = parser.parse_args()
    if args.action == "verify":
        verify(args)
    else:
        teardown(args)


if __name__ == "__main__":
    main()
