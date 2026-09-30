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
import re
import signal
import socket
import subprocess
import threading
import time
from typing import Any


ANSI_ESCAPE = re.compile(r"\x1b\[[0-9;]*m")
RESOLVE_OUTCOMES = (
    "resolved",
    "not_found",
    "identity_mismatch",
    "revoked",
    "timeout",
    "queue_refusal",
    "unavailable",
    "integrity_failure",
)
RESOLVE_FAILURES = RESOLVE_OUTCOMES[1:]
TCP_SYN = re.compile(
    r"\bIP\s+"
    r"(?P<source>[0-9.]+)\.(?P<source_port>[0-9]+)\s+>\s+"
    r"(?P<destination>[0-9.]+)\.(?P<destination_port>[0-9]+):\s+"
    r"Flags\s+\[S\]"
)


def command(*args: str) -> bytes:
    return subprocess.check_output(args, stderr=subprocess.STDOUT)


def json_command(*args: str) -> Any:
    return json.loads(command(*args))


def write_json(path: pathlib.Path, value: Any) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def distinct_syn_attempts(lines: list[str]) -> dict[str, Any]:
    """Count connection attempts, not SYN packets or capture duplicates."""
    flows: set[tuple[str, int, str, int]] = set()
    raw_packets = 0
    for line in lines:
        match = TCP_SYN.search(line)
        if match is None:
            continue
        raw_packets += 1
        flows.add((
            match.group("source"),
            int(match.group("source_port")),
            match.group("destination"),
            int(match.group("destination_port")),
        ))
    ordered = sorted(flows)
    return {
        "raw_syn_packets": raw_packets,
        "distinct_connection_attempts": len(ordered),
        "duplicate_or_retransmitted_syn_packets": raw_packets - len(ordered),
        "flows": [
            {
                "source": source,
                "source_port": source_port,
                "destination": destination,
                "destination_port": destination_port,
            }
            for source, source_port, destination, destination_port in ordered
        ],
    }


class DistinctSynCapture:
    """Capture target SYNs and retain both raw packets and deduplicated attempts."""

    FILTER = (
        "tcp and dst host 11.0.0.1 and dst port 443 and "
        "(tcp[tcpflags] & (tcp-syn|tcp-ack) == tcp-syn)"
    )

    def __init__(self, root: pathlib.Path) -> None:
        self.pcap = root / "burst-outbound-syn.pcap"
        self.decoded = root / "burst-outbound-syn.txt"
        self.stderr = root / "burst-outbound-syn-capture.stderr"
        self.result = root / "burst-outbound-attempts.json"
        self.process: subprocess.Popen[bytes] | None = None
        self.stderr_handle: Any = None

    def start(self) -> None:
        self.stderr_handle = self.stderr.open("wb")
        self.process = subprocess.Popen(
            [
                "tcpdump", "-i", "any", "-U", "-nn", "-s", "96",
                "-w", str(self.pcap), self.FILTER,
            ],
            stdout=subprocess.DEVNULL,
            stderr=self.stderr_handle,
        )
        deadline = time.monotonic() + 5.0
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                self._close_stderr()
                raise RuntimeError(
                    f"SYN capture exited before readiness: {self.stderr.read_text()}"
                )
            if "listening on" in self.stderr.read_text(errors="replace"):
                return
            time.sleep(0.02)
        self.stop()
        raise RuntimeError("SYN capture did not become ready within 5 seconds")

    def _close_stderr(self) -> None:
        if self.stderr_handle is not None:
            self.stderr_handle.close()
            self.stderr_handle = None

    def stop(self) -> dict[str, Any]:
        if self.process is None:
            raise RuntimeError("SYN capture was not started")
        if self.process.poll() is None:
            self.process.send_signal(signal.SIGINT)
        try:
            status = self.process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait(timeout=5)
            self._close_stderr()
            raise RuntimeError("SYN capture did not stop after SIGINT")
        self._close_stderr()
        if status != 0:
            raise RuntimeError(
                f"SYN capture exited with {status}: {self.stderr.read_text()}"
            )
        decoded = command(
            "tcpdump", "-nn", "-tt", "-r", str(self.pcap), self.FILTER
        ).decode(errors="replace")
        self.decoded.write_text(decoded)
        result = distinct_syn_attempts(decoded.splitlines())
        result.update({
            "capture_interface": "any",
            "capture_filter": self.FILTER,
            "capture_scope": (
                "the controlled burst window to the qualification-only endpoint "
                "11.0.0.1:443"
            ),
            "deduplication_key": [
                "source", "source_port", "destination", "destination_port"
            ],
            "raw_evidence": str(self.pcap),
            "decoded_evidence": str(self.decoded),
        })
        write_json(self.result, result)
        return result


def service_process_identity(unit: str) -> dict[str, int]:
    main_pid = int(command(
        "systemctl", "show", unit, "--property=MainPID", "--value"
    ).decode().strip())
    status = pathlib.Path(f"/proc/{main_pid}/status").read_text()
    match = re.search(r"^Uid:\s+(?P<real>[0-9]+)\s+", status, re.MULTILINE)
    if match is None:
        raise RuntimeError(f"could not read the real UID of {unit} MainPID {main_pid}")
    return {"main_pid": main_pid, "real_uid": int(match.group("real"))}


class Upstream:
    def __init__(self) -> None:
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind(("11.0.0.1", 443))
        self.listener.listen(1024)
        self.listener.settimeout(0.01)
        self.sockets: list[socket.socket] = []
        self.accepted = 0
        self.lock = threading.Lock()
        self.stop = False
        self.thread = threading.Thread(target=self._accept, daemon=True)

    def _accept(self) -> None:
        while not self.stop:
            try:
                stream, _ = self.listener.accept()
                stream.setblocking(False)
                self.sockets.append(stream)
                with self.lock:
                    self.accepted += 1
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

    def accepted_count(self) -> int:
        with self.lock:
            return self.accepted


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
        if value.get("strategy") != "one-shot-no-retry" \
                or value.get("attempts") != value.get("requested") \
                or value.get("retry_count") != 0:
            raise RuntimeError(f"fixed-rate workload retried or omitted attempts: {value}")
        achieved = int(value["succeeded"]) / max(int(value["elapsed_ms"]) / 1000.0, 0.001)
        value["requested_rate_per_second"] = requested_rate
        value["achieved_rate_per_second"] = achieved
        value["minimum_rate_per_second"] = requested_rate * 0.95
        if achieved < requested_rate * 0.95:
            raise RuntimeError(f"achieved rate is below 95% of requested rate: {value}")


def journal_lines(unit: str) -> list[str]:
    return command(
        "journalctl", "-u", f"{unit}.service", "-o", "cat", "--no-pager"
    ).decode(errors="replace").splitlines()


def parse_resolve_health(lines: list[str]) -> list[dict[str, int]]:
    events = []
    fields = RESOLVE_OUTCOMES + (
        "interval_ms",
        "delayed_hit",
        "stale_generation",
        "latency_max_us",
    )
    for raw in lines:
        line = ANSI_ESCAPE.sub("", raw)
        if 'event.name="cgroup_bpf.resolve_health"' not in line:
            continue
        event = {}
        for field in fields:
            match = re.search(rf"(?:^|\s){re.escape(field)}=(\d+)(?:\s|$)", line)
            if match is None:
                raise RuntimeError(f"Resolve health event omitted {field}: {line}")
            event[field] = int(match.group(1))
        events.append(event)
    return events


def sum_resolve_health(events: list[dict[str, int]]) -> dict[str, int]:
    return {
        field: sum(event[field] for event in events)
        for field in RESOLVE_OUTCOMES + ("delayed_hit", "stale_generation")
    }


def invoke_control(port: int, report: str, deadline_ms: int) -> dict[str, Any]:
    invocation = invoke(
        port, f"b7-rate-report 11.0.0.1:443 1 1 {report}", timeout=30
    )
    value = workload_value(invocation)
    assert_measurement(value, 1, 1, deadline_ms)
    if invocation["execution_id"] is None:
        raise RuntimeError("Resolve-health control omitted its ExecutionId")
    return invocation


def reset_resolve_health_window(
    unit: str,
    port: int,
    target: pathlib.Path,
    completed_execution_ids: list[str],
    deadline_ms: int,
    label: str,
) -> int:
    time.sleep(1.1)
    control = invoke_control(port, f"/tmp/b7-health-before-{label}.json", deadline_ms)
    completed_execution_ids.append(control["execution_id"])
    wait_children(target, 0, 15)
    return len(journal_lines(unit))


def finish_resolve_health_window(
    root: pathlib.Path,
    label: str,
    unit: str,
    port: int,
    target: pathlib.Path,
    journal_start: int,
    workload_attempts: int,
    completed_execution_ids: list[str],
    deadline_ms: int,
    prior_controls: int = 0,
) -> dict[str, Any]:
    time.sleep(1.1)
    control = invoke_control(port, f"/tmp/b7-health-after-{label}.json", deadline_ms)
    completed_execution_ids.append(control["execution_id"])
    wait_children(target, 0, 15)
    control_count = prior_controls + 1
    expected = workload_attempts + control_count
    deadline = time.monotonic() + 5.0
    events: list[dict[str, int]] = []
    raw_totals: dict[str, int] = {}
    lines: list[str] = []
    while time.monotonic() < deadline:
        lines = journal_lines(unit)[journal_start:]
        events = parse_resolve_health(lines)
        raw_totals = sum_resolve_health(events)
        observed = sum(raw_totals.get(field, 0) for field in RESOLVE_OUTCOMES)
        if observed >= expected:
            break
        time.sleep(0.05)
    observed = sum(raw_totals.get(field, 0) for field in RESOLVE_OUTCOMES)
    adjusted = raw_totals.copy()
    if observed != expected or adjusted.get("resolved", 0) < control_count:
        record = {
            "label": label,
            "expected_results_including_controls": expected,
            "observed_results_including_controls": observed,
            "control_resolves": control_count,
            "events": events,
            "raw_totals": raw_totals,
            "verdict": "FAIL",
        }
        directory = root / "resolve-health"
        directory.mkdir(exist_ok=True)
        write_json(directory / f"{label}.json", record)
        raise RuntimeError(f"{label}: Resolve health accounting is incomplete: {record}")
    adjusted["resolved"] -= control_count
    record = {
        "label": label,
        "source": "production cgroup_bpf.resolve_health structured events",
        "workload_attempts": workload_attempts,
        "control_resolves_excluded": control_count,
        "event_count": len(events),
        "events": events,
        "raw_totals": raw_totals,
        "workload_totals": adjusted,
        "verdict": "PASS",
    }
    directory = root / "resolve-health"
    directory.mkdir(exist_ok=True)
    write_json(directory / f"{label}.json", record)
    return record


def assert_supported_health(
    record: dict[str, Any], requested: int, root: pathlib.Path
) -> None:
    totals = record["workload_totals"]
    failures = {field: totals[field] for field in RESOLVE_FAILURES}
    if totals["resolved"] != requested or any(failures.values()) \
            or totals["stale_generation"] != 0:
        record["verdict"] = "FAIL"
        write_json(root / "resolve-health" / f"{record['label']}.json", record)
        raise RuntimeError(
            f"{record['label']}: workload exceeded the supported Resolve envelope: {record}"
        )
    record["supported_envelope"] = True
    record["verdict"] = "PASS"
    write_json(root / "resolve-health" / f"{record['label']}.json", record)


def nft_counter(comment: str) -> int:
    ruleset = json_command("nft", "-j", "list", "table", "inet", "soglia_b7_observe")
    return nft_counter_value(ruleset, comment)


def nft_counter_value(ruleset: Any, comment: str) -> int:
    """Read one named rule counter from nft's actual JSON expression layout."""
    counters: list[int] = []
    if not isinstance(ruleset, dict):
        raise RuntimeError("nft counter evidence is not a JSON object")
    for item in ruleset.get("nftables", []):
        if not isinstance(item, dict) or not isinstance(item.get("rule"), dict):
            continue
        rule = item["rule"]
        if rule.get("comment") != comment:
            continue
        rule_counters = [
            expression["counter"]
            for expression in rule.get("expr", [])
            if isinstance(expression, dict)
            and isinstance(expression.get("counter"), dict)
        ]
        if len(rule_counters) != 1 or "packets" not in rule_counters[0]:
            raise RuntimeError(f"nft rule {comment!r} has no unique packet counter")
        counters.append(int(rule_counters[0]["packets"]))
    if len(counters) != 1:
        raise RuntimeError(
            f"expected exactly one nft rule named {comment!r}, found {len(counters)}"
        )
    return counters[0]


def wait_upstream(upstream: Upstream, expected: int) -> int:
    deadline = time.monotonic() + 5.0
    while time.monotonic() < deadline:
        current = upstream.accepted_count()
        if current >= expected:
            return current
        time.sleep(0.01)
    return upstream.accepted_count()


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
    with Upstream() as upstream, \
            concurrent.futures.ThreadPoolExecutor(max_workers=max(maximum, 4)) as pool:
        live_health_start = reset_resolve_health_window(
            args.unit, args.ingress_port, target, completed_execution_ids,
            args.deadline_ms, "live",
        )
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
        live_health = finish_resolve_health_window(
            args.evidence, "live", args.unit, args.ingress_port, target,
            live_health_start, args.live, completed_execution_ids, args.deadline_ms,
        )
        assert_supported_health(live_health, args.live, args.evidence)
        results["live"] = {
            "requested_sockets": args.live,
            "per_execution": per_execution,
            "sampled_children": live_results,
            "measurements": live_values,
            "correct_attribution": True,
            "resolve_health": live_health,
        }
        wait_children(target, 0, 15)
        residue_measurements.append(measure_execution_residue(
            args.evidence, "live", args.state, completed_execution_ids
        ))

        churn_health_start = reset_resolve_health_window(
            args.unit, args.ingress_port, target, completed_execution_ids,
            args.deadline_ms, "churn",
        )
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
        churn_health = finish_resolve_health_window(
            args.evidence, "churn", args.unit, args.ingress_port, target,
            churn_health_start, args.churn, completed_execution_ids, args.deadline_ms,
        )
        assert_supported_health(churn_health, args.churn, args.evidence)
        results["churn"] = {"measurement": churn, "resolve_health": churn_health}
        wait_children(target, 0, 15)
        residue_measurements.append(measure_execution_residue(
            args.evidence, "churn", args.state, completed_execution_ids
        ))

        rate_results = []
        for specification in filter(None, args.rates.split(",")):
            rate, duration = (int(value) for value in specification.split("x", 1))
            rate_label = f"rate-{rate}x{duration}"
            rate_health_start = reset_resolve_health_window(
                args.unit, args.ingress_port, target, completed_execution_ids,
                args.deadline_ms, rate_label,
            )
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
            rate_health = finish_resolve_health_window(
                args.evidence, rate_label, args.unit, args.ingress_port, target,
                rate_health_start, rate * duration, completed_execution_ids,
                args.deadline_ms,
            )
            assert_supported_health(rate_health, rate * duration, args.evidence)
            rate_results.append({
                "measurement": measured,
                "resolve_health": rate_health,
                "one_attempt_per_scheduled_connection": True,
                "refusal_retry": False,
            })
            wait_children(target, 0, 15)
            residue_measurements.append(measure_execution_residue(
                args.evidence, rate_label, args.state,
                completed_execution_ids,
            ))
        results["rates"] = rate_results

        if args.burst:
            burst_health_start = reset_resolve_health_window(
                args.unit, args.ingress_port, target, completed_execution_ids,
                args.deadline_ms, "burst",
            )
            service_identity = service_process_identity(args.unit)
            upstream_before = upstream.accepted_count()
            dns_before = {
                "udp": nft_counter("b7_dns_udp"),
                "tcp": nft_counter("b7_dns_tcp"),
            }
            syn_capture = DistinctSynCapture(args.evidence)
            syn_capture.start()
            try:
                burst = invoke(
                    args.ingress_port,
                    f"b7-burst-report 11.0.0.1:443 {args.burst} /tmp/b7-burst.json",
                    timeout=90,
                )
                if burst["status"] != 200 or not isinstance(burst["body"], dict):
                    raise RuntimeError(f"simultaneous burst failed: {burst}")
                succeeded = int(burst["body"].get("succeeded", -1))
                upstream_after = wait_upstream(upstream, upstream_before + succeeded)
                # Keep the capture open long enough to include a retransmitted SYN if one
                # exists.  The deduplication key ensures it is still one attempt.
                time.sleep(1.5)
            finally:
                outbound_attempts = syn_capture.stop()
            if burst["status"] != 200 or not isinstance(burst["body"], dict):
                raise RuntimeError(f"simultaneous burst failed: {burst}")
            if int(burst["body"].get("max_us", args.deadline_ms * 1000 + 1)) \
                    > args.deadline_ms * 1000:
                raise RuntimeError(f"a successful burst Resolve exceeded its deadline: {burst}")
            if burst["execution_id"] is None:
                raise RuntimeError("burst workload omitted its ExecutionId")
            completed_execution_ids.append(burst["execution_id"])
            failed = int(burst["body"].get("failed", -1))
            requested = int(burst["body"].get("requested", -1))
            dns_after = {
                "udp": nft_counter("b7_dns_udp"),
                "tcp": nft_counter("b7_dns_tcp"),
            }
            immediate_control = invoke_control(
                args.ingress_port, "/tmp/b7-burst-control.json", args.deadline_ms
            )
            completed_execution_ids.append(immediate_control["execution_id"])
            burst_health = finish_resolve_health_window(
                args.evidence, "burst", args.unit, args.ingress_port, target,
                burst_health_start, requested, completed_execution_ids,
                args.deadline_ms, prior_controls=1,
            )
            totals = burst_health["workload_totals"]
            rejected_outbound = upstream_after - upstream_before - succeeded
            rejected_outbound_attempts = (
                outbound_attempts["distinct_connection_attempts"] - succeeded
            )
            dns_delta = {
                protocol: dns_after[protocol] - dns_before[protocol]
                for protocol in dns_before
            }
            characterization_pass = (
                requested == args.burst
                and succeeded + failed == requested
                and totals["resolved"] == succeeded
                and totals["queue_refusal"] == failed
                and all(totals[field] == 0 for field in RESOLVE_FAILURES
                        if field != "queue_refusal")
                and totals["stale_generation"] == 0
                and rejected_outbound == 0
                and rejected_outbound_attempts == 0
                and all(value == 0 for value in dns_delta.values())
                and workload_value(immediate_control)["succeeded"] == 1
            )
            characterization = {
                "classification": "OUTSIDE_SUPPORTED_ENVELOPE_REFUSAL_CHARACTERIZATION",
                "supported_capacity_claim": False,
                "requested": requested,
                "succeeded": succeeded,
                "refused": failed,
                "failure_class": "QueueFull",
                "resolve_health": burst_health,
                "effects": {
                    "upstream_accepts_before": upstream_before,
                    "upstream_accepts_after": upstream_after,
                    "successful_connections": succeeded,
                    "rejected_connection_outbound_accepts": rejected_outbound,
                    "outbound_connection_attempts": outbound_attempts,
                    "rejected_connection_outbound_attempts": rejected_outbound_attempts,
                    "dns_packets_before": dns_before,
                    "dns_packets_after": dns_after,
                    "dns_packet_delta": dns_delta,
                },
                "prior_observer_diagnosis": {
                    "historical_run": "b7-diagnostic-20260930T210309Z-1170989",
                    "historical_successful_connections": 107,
                    "historical_raw_syn_packets": 0,
                    "historical_derived_rejected_syn": -107,
                    "legacy_filter": "meta skuid 65534",
                    "service_process": service_identity,
                    "sandbox_agent_uid": 65534,
                    "cause": (
                        "the legacy parser looked for counter as a sibling of rule.comment, "
                        "but nft -j stores it in rule.expr; it therefore returned zero for "
                        "every commented rule. The observed service real UID is 65534, so "
                        "the skuid filter itself does not explain the historical zero"
                    ),
                    "replacement": (
                        "packet capture of target SYNs with distinct 4-tuple counting; "
                        "retransmissions and capture duplicates do not add attempts"
                    ),
                },
                "immediate_control": immediate_control,
                "verdict": "PASS" if characterization_pass else "FAIL",
            }
            write_json(args.evidence / "burst-characterization.json", characterization)
            if not characterization_pass:
                raise RuntimeError(f"burst refusal characterization failed: {characterization}")
            results["burst"] = {"invocation": burst, "characterization": characterization}
            wait_children(target, 0, 15)
            residue_measurements.append(measure_execution_residue(
                args.evidence, "burst", args.state, completed_execution_ids
            ))

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
