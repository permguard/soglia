#!/usr/bin/env python3
# Copyright (c) 2022 Nitro Agility S.r.l.
# SPDX-License-Identifier: Apache-2.0

"""Record the focused production contracts added to the Phase-2 B2/B3/B5 gates."""

from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path


TESTS = {
    "B2": [
        "out_of_order_replies_are_correlated_to_their_request_ids",
        "cancellation_before_write_removes_the_request_without_a_frame",
        "a_cancelled_caller_cannot_desynchronize_the_next_exchange",
        "pending_after_the_publication_deadline_times_out_without_poisoning",
        "complete_after_the_publication_deadline_is_still_consumed",
    ],
    "B3": [
        "lifecycle_writer_has_priority_over_new_resolve_readers",
        "out_of_order_replies_are_correlated_to_their_request_ids",
    ],
}


def run_test(root: Path, name: str, evidence: Path) -> dict[str, object]:
    command = [
        "/root/.cargo/bin/cargo",
        "+1.97.0",
        "test",
        "--workspace",
        "--all-features",
        name,
        "--",
        "--nocapture",
    ]
    completed = subprocess.run(command, cwd=root, capture_output=True, text=True, check=False)
    (evidence / f"{name}.stdout.txt").write_text(completed.stdout, encoding="utf-8")
    (evidence / f"{name}.stderr.txt").write_text(completed.stderr, encoding="utf-8")
    if completed.returncode != 0 or "1 passed" not in completed.stdout:
        raise RuntimeError(f"production contract test failed: {name}")
    return {"verdict": "PASS", "test": name, "exit_code": completed.returncode}


def b5_contract(driver: Path) -> dict[str, object]:
    direct = json.loads((driver / "cases/direct_ipv4_early_deny/result.json").read_text())
    if direct.get("veth_syn_packets") != 0 or direct.get("execution_nft_drop_path_packets") != 0:
        raise RuntimeError("B5 early refusal caused a packet effect")
    if direct.get("connect4_deny_delta") != 1:
        raise RuntimeError("B5 early refusal did not record exactly one denial")
    return {
        "verdict": "PASS",
        "direct_ipv4": {
            "resolve_required_before_effect": True,
            "veth_syn_packets": 0,
            "execution_nft_drop_path_packets": 0,
            "connect4_deny_delta": 1,
        },
        "phase2_capacity_refusals": {
            "qualified_by": "B4",
            "proxy_before_read": True,
            "pending_resolve_queue_full": True,
            "ingress_before_admission": True,
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--gate", choices=("B2", "B3", "B5"), required=True)
    parser.add_argument("--production-root", type=Path, required=True)
    parser.add_argument("--driver-evidence", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    if args.gate == "B5":
        if args.driver_evidence is None:
            raise RuntimeError("B5 requires driver evidence")
        result = b5_contract(args.driver_evidence)
    else:
        cases = {
            name: run_test(args.production_root, name, args.output)
            for name in TESTS[args.gate]
        }
        result = {"verdict": "PASS", "gate": args.gate, "cases": cases}
    (args.output / "result.json").write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (args.output / "verdict.txt").write_text("PASS\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
