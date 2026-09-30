#!/usr/bin/env python3
# Copyright (c) 2022 Nitro Agility S.r.l.
# SPDX-License-Identifier: Apache-2.0

"""Drive one declared B7 production profile and preserve independent kernel evidence."""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import os
import pathlib
import socket
import subprocess
import threading
import time
from typing import Any


def command(*args: str) -> bytes:
    return subprocess.check_output(args, stderr=subprocess.STDOUT)


def json_command(*args: str) -> Any:
    return json.loads(command(*args))


def write_json(path: pathlib.Path, value: Any) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


class Upstream:
    def __init__(self) -> None:
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind(("11.0.0.1", 443))
        self.listener.listen(1024)
        self.listener.settimeout(0.01)
        self.sockets: list[socket.socket] = []
        self.stop = False
        self.thread = threading.Thread(target=self._accept, daemon=True)

    def _accept(self) -> None:
        while not self.stop:
            try:
                stream, _ = self.listener.accept()
                stream.setblocking(False)
                self.sockets.append(stream)
            except TimeoutError:
                pass
            except OSError:
                return
            alive = []
            for stream in self.sockets:
                try:
                    data = stream.recv(4096)
                    if data:
                        alive.append(stream)
                    else:
                        stream.close()
                except BlockingIOError:
                    alive.append(stream)
                except OSError:
                    stream.close()
            self.sockets = alive

    def __enter__(self) -> "Upstream":
        self.thread.start()
        return self

    def __exit__(self, *_: object) -> None:
        self.stop = True
        self.listener.close()
        for stream in self.sockets:
            stream.close()
        self.thread.join(timeout=2)


def invoke(port: int, body: str, timeout: float = 150.0) -> dict[str, Any]:
    started = time.monotonic()
    with socket.create_connection(("127.0.0.1", port), timeout=10) as stream:
        stream.settimeout(timeout)
        request = (
            "POST /v1/execute/workload HTTP/1.1\r\n"
            "Host: soglia\r\nContent-Type: text/plain\r\n"
            f"Content-Length: {len(body.encode())}\r\nConnection: close\r\n\r\n{body}"
        )
        stream.sendall(request.encode())
        chunks = []
        while True:
            part = stream.recv(65536)
            if not part:
                break
            chunks.append(part)
    response = b"".join(chunks).decode(errors="replace")
    head, separator, payload = response.partition("\r\n\r\n")
    if not separator:
        raise RuntimeError("invocation response omitted the header terminator")
    lines = head.splitlines()
    status = int(lines[0].split()[1])
    headers = {}
    for line in lines[1:]:
        if ":" in line:
            name, value = line.split(":", 1)
            headers[name.lower()] = value.strip()
    try:
        parsed = json.loads(payload)
    except json.JSONDecodeError:
        parsed = payload
    return {
        "command": body,
        "status": status,
        "execution_id": headers.get("soglia-execution-id"),
        "elapsed_ms": int((time.monotonic() - started) * 1000),
        "body": parsed,
    }


def child_paths(target: pathlib.Path) -> list[pathlib.Path]:
    return sorted(path for path in target.iterdir() if path.is_dir())


def wait_children(target: pathlib.Path, expected: int, timeout: float = 20.0) -> None:
    started = time.monotonic()
    while time.monotonic() - started < timeout:
        if len(child_paths(target)) == expected:
            return
        time.sleep(0.02)
    raise RuntimeError(f"expected {expected} Execution cgroups, saw {len(child_paths(target))}")


def fd_count(pid: int) -> int:
    try:
        return len(list(pathlib.Path(f"/proc/{pid}/fd").iterdir()))
    except FileNotFoundError:
        return 0


def snapshot(root: pathlib.Path, label: str, unit: str, expected: int,
             identity: dict[str, list[int]] | None,
             state_path: pathlib.Path) -> dict[str, list[int]]:
    directory = root / "checkpoints" / label
    directory.mkdir(parents=True)
    state = json.loads(state_path.read_text())
    target = pathlib.Path(state["attachment_target"])
    children = child_paths(target)
    if len(children) != expected:
        raise RuntimeError(f"{label}: target has {len(children)} children, expected {expected}")
    programs = [int(item["id"]) for item in state["programs"]]
    links = [int(item["id"]) for item in state["links"]]
    maps = [int(item["id"]) for item in state["maps"]]
    current = {"programs": programs, "links": links, "maps": maps}
    if len(programs) != 6 or len(links) != 6 or len(maps) != 7:
        raise RuntimeError(f"{label}: production topology is not 6/6/7")
    if identity is not None and current != identity:
        raise RuntimeError(f"{label}: shared kernel object IDs changed with Execution count")
    pins = sorted(str(path) for path in pathlib.Path(state["pin_root"]).rglob("*") if path.is_file())
    if len(pins) != 13:
        raise RuntimeError(f"{label}: found {len(pins)} pins, expected 13")
    direct = json_command("bpftool", "-j", "cgroup", "show", str(target))
    direct_ids = sorted(int(item["id"]) for item in direct)
    if direct_ids != sorted(programs):
        raise RuntimeError(f"{label}: direct target programs differ from durable inventory")
    representative = None
    effective = []
    if children:
        representative = str(children[-1])
        effective = json_command("bpftool", "-j", "cgroup", "show", representative, "effective")
        effective_ids = {int(item["id"]) for item in effective}
        if not set(programs).issubset(effective_ids):
            raise RuntimeError(f"{label}: representative child lacks inherited Soglia hooks")
    map_info = []
    for item in state["maps"]:
        info = json_command("bpftool", "-j", "map", "show", "pinned", item["pin"])
        map_info.append(info)
    main_pid = int(command("systemctl", "show", f"{unit}.service", "-p", "MainPID", "--value"))
    record = {
        "label": label,
        "execution_count": expected,
        "constant_shared_topology": True,
        "program_ids": programs,
        "link_ids": links,
        "map_ids": maps,
        "pin_count": len(pins),
        "pins": pins,
        "direct_target": direct,
        "representative_child": representative,
        "representative_effective": effective,
        "state": state,
        "map_info": map_info,
        "main_pid": main_pid,
        "main_pid_fds": fd_count(main_pid),
        "service_tasks": command("systemctl", "show", f"{unit}.service", "-p", "TasksCurrent", "--value").decode().strip(),
        "nofile": next(
            line for line in pathlib.Path(f"/proc/{main_pid}/limits").read_text().splitlines()
            if line.startswith("Max open files")
        ),
        "source": {"topology": "independent bpftool comparison", "state": "production durable manifest"},
    }
    write_json(directory / "snapshot.json", record)
    (directory / "programs.json").write_bytes(command("bpftool", "-j", "prog", "show"))
    (directory / "links.json").write_bytes(command("bpftool", "-j", "link", "show"))
    (directory / "maps.json").write_bytes(command("bpftool", "-j", "map", "show"))
    return current


def workload_value(result: dict[str, Any]) -> dict[str, Any]:
    if result["status"] != 200 or not isinstance(result["body"], dict):
        raise RuntimeError(f"workload failed: {result}")
    return result["body"]


def assert_measurement(value: dict[str, Any], requested_rate: int | None,
                       duration: int | None, deadline_ms: int) -> None:
    if value.get("failed") != 0 or value.get("succeeded") != value.get("requested"):
        raise RuntimeError(f"workload did not resolve every connection: {value}")
    if int(value.get("max_us", deadline_ms * 1000 + 1)) > deadline_ms * 1000:
        raise RuntimeError(f"successful Resolve exceeded the configured deadline: {value}")
    if requested_rate and duration:
        achieved = int(value["succeeded"]) / max(int(value["elapsed_ms"]) / 1000.0, 0.001)
        value["requested_rate_per_second"] = requested_rate
        value["achieved_rate_per_second"] = achieved
        value["minimum_rate_per_second"] = requested_rate * 0.95
        if achieved < requested_rate * 0.95:
            raise RuntimeError(f"achieved rate is below 95% of requested rate: {value}")


def directory_entries(path: pathlib.Path) -> list[str]:
    if not path.exists():
        return []
    return sorted(str(entry) for entry in path.iterdir())


def map_dump(state: dict[str, Any], name: str) -> list[dict[str, Any]]:
    manifest = next(item for item in state["maps"] if item["name"] == name)
    value = json_command("bpftool", "-j", "map", "dump", "pinned", manifest["pin"])
    if not isinstance(value, list):
        raise RuntimeError(f"{name}: bpftool returned a non-list map dump")
    return value


def measure_execution_residue(
    root: pathlib.Path,
    label: str,
    state_path: pathlib.Path,
    execution_ids: list[str],
) -> dict[str, Any]:
    """Prove completed Executions left no resource, before harness teardown."""
    directory = root / "active-residue"
    directory.mkdir(exist_ok=True)
    runtime_root = state_path.parent.parent
    tags = sorted({execution_id[:10] for execution_id in execution_ids})
    deadline = time.monotonic() + 15.0
    record: dict[str, Any] = {}
    while True:
        state = json.loads(state_path.read_text())
        target = pathlib.Path(state["attachment_target"])
        maps = {
            name: map_dump(state, name)
            for name in ["soglia_policy", "soglia_cookie_a", "soglia_tuples", "soglia_denies"]
        }
        resources = []
        for tag in tags:
            paths = {
                "cgroup": target / tag,
                "netns": pathlib.Path("/run/netns") / f"soglia-{tag}",
                "host_veth": pathlib.Path("/sys/class/net") / f"sgh-{tag}",
                "network_record": runtime_root / "net" / f"{tag}.json",
                "sandbox_record": runtime_root / "sandbox" / f"{tag}.json",
                "bundle": runtime_root / "bundles" / tag,
                "runc_state": runtime_root / "runc" / f"soglia-{tag}",
            }
            resources.extend(
                {"tag": tag, "kind": kind, "path": str(path), "present": path.exists()}
                for kind, path in paths.items()
            )
        directory_state = {
            "target_children": [str(path) for path in child_paths(target)],
            "network_execution_records": sorted(
                entry for entry in directory_entries(runtime_root / "net")
                if not entry.endswith("/host.json")
            ),
            "sandbox_records": directory_entries(runtime_root / "sandbox"),
            "bundles": directory_entries(runtime_root / "bundles"),
            "runc_states": directory_entries(runtime_root / "runc"),
        }
        live_registry_entries = [entry for entry in resources if entry["present"]]
        clean = (
            not state["executions"]
            and all(not entries for entries in maps.values())
            and all(not entries for entries in directory_state.values())
            and not live_registry_entries
        )
        record = {
            "label": label,
            "measured_while_runtime_active": True,
            "harness_deletion_before_measurement": False,
            "execution_ids": execution_ids,
            "tags": tags,
            "durable_execution_records": state["executions"],
            "map_entries": maps,
            "directory_state": directory_state,
            "resource_registry": {
                "entries": resources,
                "live_entries": len(live_registry_entries),
                "closed": not live_registry_entries,
            },
            "verdict": "PASS" if clean else "FAIL",
        }
        if clean or time.monotonic() >= deadline:
            break
        time.sleep(0.05)
    write_json(directory / f"{label}.json", record)
    if record["verdict"] != "PASS":
        raise RuntimeError(f"{label}: completed Execution residue remained: {record}")
    return record


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--profile", required=True)
    parser.add_argument("--unit", required=True)
    parser.add_argument("--state", type=pathlib.Path, required=True)
    parser.add_argument("--evidence", type=pathlib.Path, required=True)
    parser.add_argument("--ingress-port", type=int, required=True)
    parser.add_argument("--checkpoints", required=True)
    parser.add_argument("--live", type=int, required=True)
    parser.add_argument("--churn", type=int, required=True)
    parser.add_argument("--rates", default="")
    parser.add_argument("--burst", type=int, default=0)
    parser.add_argument("--deadline-ms", type=int, default=2000)
    args = parser.parse_args()
    args.evidence.mkdir(parents=True, exist_ok=True)
    checkpoints = [int(value) for value in args.checkpoints.split(",")]
    maximum = checkpoints[-1]
    target = pathlib.Path(f"/sys/fs/cgroup/system.slice/{args.unit}.service/executions")
    wait_children(target, 0)
    per_execution = args.live // maximum
    if per_execution * maximum != args.live:
        raise RuntimeError("live socket target must divide evenly across the maximum Execution count")
    results: dict[str, Any] = {"profile": args.profile, "matrix": vars(args).copy()}
    results["matrix"]["evidence"] = str(args.evidence)
    results["matrix"]["state"] = str(args.state)
    identity = snapshot(args.evidence, "executions-0", args.unit, 0, None, args.state)
    futures = []
    completed_execution_ids: list[str] = []
    residue_measurements: list[dict[str, Any]] = []
    with Upstream(), concurrent.futures.ThreadPoolExecutor(max_workers=max(maximum, 4)) as pool:
        previous = 0
        for checkpoint in checkpoints[1:]:
            for slot in range(previous, checkpoint):
                port = 40000 + (slot * max(per_execution, 1))
                command_body = (
                    f"delayed-b7-live-report 10000 11.0.0.1:443 {per_execution} 3 "
                    f"/tmp/b7-live-{slot}.json"
                )
                futures.append(pool.submit(invoke, args.ingress_port, command_body))
            wait_children(target, checkpoint)
            identity = snapshot(
                args.evidence, f"executions-{checkpoint}", args.unit, checkpoint, identity,
                args.state,
            )
            previous = checkpoint
        live_results = [future.result(timeout=90) for future in futures]
        if any(result["status"] != 200 for result in live_results):
            raise RuntimeError("one or more live-socket sampled children failed")
        live_values = [workload_value(result) for result in live_results]
        if sum(int(value["succeeded"]) for value in live_values) != args.live \
                or any(int(value["failed"]) != 0 for value in live_values):
            raise RuntimeError("the declared simultaneous live-socket count was not reached")
        execution_ids = [result["execution_id"] for result in live_results]
        if None in execution_ids or len(set(execution_ids)) != maximum:
            raise RuntimeError("sampled child attribution omitted or reused an ExecutionId")
        completed_execution_ids.extend(execution_ids)
        results["live"] = {
            "requested_sockets": args.live,
            "per_execution": per_execution,
            "sampled_children": live_results,
            "measurements": live_values,
            "correct_attribution": True,
        }
        wait_children(target, 0, 15)
        residue_measurements.append(measure_execution_residue(
            args.evidence, "live", args.state, completed_execution_ids
        ))

        churn_invocation = invoke(
            args.ingress_port,
            f"b7-churn-report 11.0.0.1:443 {args.churn} /tmp/b7-churn.json",
            timeout=max(180.0, args.churn / 20),
        )
        churn = workload_value(churn_invocation)
        assert_measurement(churn, None, None, args.deadline_ms)
        if churn_invocation["execution_id"] is None:
            raise RuntimeError("churn workload omitted its ExecutionId")
        completed_execution_ids.append(churn_invocation["execution_id"])
        results["churn"] = churn
        wait_children(target, 0, 15)
        residue_measurements.append(measure_execution_residue(
            args.evidence, "churn", args.state, completed_execution_ids
        ))

        rate_results = []
        for specification in filter(None, args.rates.split(",")):
            rate, duration = (int(value) for value in specification.split("x", 1))
            rate_invocation = invoke(
                args.ingress_port,
                f"b7-rate-report 11.0.0.1:443 {rate} {duration} /tmp/b7-rate.json",
                timeout=duration + 120,
            )
            measured = workload_value(rate_invocation)
            assert_measurement(measured, rate, duration, args.deadline_ms)
            if rate_invocation["execution_id"] is None:
                raise RuntimeError(f"rate {specification} omitted its ExecutionId")
            completed_execution_ids.append(rate_invocation["execution_id"])
            rate_results.append(measured)
            wait_children(target, 0, 15)
            residue_measurements.append(measure_execution_residue(
                args.evidence, f"rate-{rate}x{duration}", args.state,
                completed_execution_ids,
            ))
        results["rates"] = rate_results

        if args.burst:
            burst = invoke(
                args.ingress_port,
                f"b7-burst-report 11.0.0.1:443 {args.burst} /tmp/b7-burst.json",
                timeout=90,
            )
            if burst["status"] != 200 or not isinstance(burst["body"], dict):
                raise RuntimeError(f"simultaneous burst failed: {burst}")
            if int(burst["body"].get("max_us", args.deadline_ms * 1000 + 1)) \
                    > args.deadline_ms * 1000:
                raise RuntimeError(f"a successful burst Resolve exceeded its deadline: {burst}")
            if burst["execution_id"] is None:
                raise RuntimeError("burst workload omitted its ExecutionId")
            completed_execution_ids.append(burst["execution_id"])
            results["burst"] = burst
            wait_children(target, 0, 15)
            residue_measurements.append(measure_execution_residue(
                args.evidence, "burst", args.state, completed_execution_ids
            ))

        time.sleep(2)
        flush_invocation = invoke(
            args.ingress_port, "b7-rate-report 11.0.0.1:443 1 1 /tmp/b7-flush.json", 30
        )
        flush = workload_value(flush_invocation)
        assert_measurement(flush, 1, 1, args.deadline_ms)
        if flush_invocation["execution_id"] is None:
            raise RuntimeError("flush workload omitted its ExecutionId")
        completed_execution_ids.append(flush_invocation["execution_id"])
        wait_children(target, 0, 15)
        residue_measurements.append(measure_execution_residue(
            args.evidence, "final", args.state, completed_execution_ids
        ))

    results["execution_residue"] = {
        "measurement_count": len(residue_measurements),
        "all_before_harness_teardown": True,
        "all_pass": all(item["verdict"] == "PASS" for item in residue_measurements),
        "resource_registry_closed": all(
            item["resource_registry"]["closed"] for item in residue_measurements
        ),
    }

    journal = command("journalctl", "-u", f"{args.unit}.service", "-o", "cat", "--no-pager").decode()
    (args.evidence / "production-events.txt").write_text(journal)
    required = [
        "event.name=cgroup_bpf.startup",
        "event.name=cgroup_bpf.health",
        "event.name=cgroup_bpf.occupancy",
        "cgroup_bpf.resolve_health",
        "event.name=cgroup_bpf.freeze",
        "event.name=cgroup_bpf.destroy",
    ]
    missing = [event for event in required if event not in journal]
    if missing:
        raise RuntimeError(f"production observability omitted {missing}")
    results["observability"] = {
        "source": "production structured events",
        "required": required,
        "all_present": True,
        "direct_bpftool_role": "independent comparison only",
    }
    results["verdict"] = "PASS"
    write_json(args.evidence / "result.json", results)
    (args.evidence / "verdict.txt").write_text("PASS\n")


if __name__ == "__main__":
    main()
