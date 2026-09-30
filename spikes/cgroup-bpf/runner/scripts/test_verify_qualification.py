#!/usr/bin/env python3
# Copyright (c) 2022 Nitro Agility S.r.l.
# SPDX-License-Identifier: Apache-2.0

import hashlib
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).with_name("verify_qualification.py")
SPEC = importlib.util.spec_from_file_location("verify_qualification", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
VERIFY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VERIFY)


class QualificationVerifierTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.runs = [self.make_run(number) for number in range(1, 8)]

    def tearDown(self) -> None:
        self.temporary.cleanup()

    @staticmethod
    def write_json(path: Path, value: object) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value), encoding="utf-8")

    def make_run(self, number: int) -> Path:
        gate = f"B{number}"
        run = self.root / f"b{number}-fixture"
        run.mkdir()
        summary = {
            "gate": gate,
            "run_id": run.name,
            "authoritative": True,
            "verdict": "PASS",
            "cleanup": {"verdict": "PASS"},
            "production_source_baseline": {"commit": "b" * 40, "matches": True},
        }
        if number == 7:
            summary["qualified"] = {"within_envelope_resolve_outcomes_clean": True}
        self.write_json(run / "summary.json", summary)
        (run / "verdict.txt").write_text("PASS\n", encoding="utf-8")
        (run / "source-fingerprint.txt").write_text(
            f"{'a' * 40}\n{VERIFY.EMPTY_DIFF_SHA256}  -\n", encoding="utf-8"
        )
        if number == 5:
            self.write_json(
                run / "driver/proxy-steering-boundary.json",
                {
                    "verdict": "PASS",
                    "proxy_steering_layer": "outside BPF",
                    "no_writes_to_destination_fields": True,
                    "bpf_bind_absent": True,
                    "runtime": {"destinations_match": True},
                },
            )
        if number == 6:
            case = run / "cases/sandbox_sigkill"
            self.write_json(
                case / "target-offline-contract.json",
                {
                    "verdict": "PASS",
                    "open_after_removal": {"result": -1, "errno": 116},
                    "retained_cgroup_procs_write": {"result": -1, "errno": 19},
                    "retained_clone_into_cgroup": {"result": -1, "errno": 2},
                },
            )
            self.write_json(
                case / "result.json",
                {
                    "verdict": "PASS",
                    "target_released": {
                        "exact_link_detaches_verified": 6,
                        "new_authorization_maps_empty": True,
                        "new_generation": 2,
                    },
                },
            )
            self.write_json(case / "state-after-restart.json", {"phase": "READY", "generation": 2})
            (case / "journal.txt").write_text(
                "event.name=cgroup_bpf.startup result=PASS generation=2 duration_ms=1 swept=1 readiness=READY\n",
                encoding="utf-8",
            )
        if number == 7:
            totals = {name: 0 for name in VERIFY.NEGATIVE_RESOLVE_OUTCOMES}
            totals["resolved"] = 1
            self.write_json(run / "profiles/M0/resolve-health/live.json", {"verdict": "PASS", "workload_totals": totals})
            self.write_json(
                run / "profiles/M3/burst-characterization.json",
                {
                    "verdict": "PASS",
                    "succeeded": 3,
                    "refused": 1,
                    "effects": {
                        "dns_packet_delta": {"tcp": 0, "udp": 0},
                        "outbound_connection_attempts": {"distinct_connection_attempts": 3},
                    },
                    "resolve_health": {"workload_totals": {"queue_refusal": 1}},
                },
            )
        self.write_sums(run)
        return run

    @staticmethod
    def write_sums(run: Path) -> None:
        entries = []
        for path in sorted(path for path in run.rglob("*") if path.is_file() and path.name != "SHA256SUMS"):
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            entries.append(f"{digest}  ./{path.relative_to(run)}")
        (run / "SHA256SUMS").write_text("\n".join(entries) + "\n", encoding="utf-8")

    def assert_reason(self, fragment: str) -> None:
        with self.assertRaisesRegex(VERIFY.VerificationError, fragment):
            VERIFY.verify(self.runs)

    def test_valid_qualification_passes(self) -> None:
        result = VERIFY.verify(self.runs)
        self.assertEqual(result["verdict"], "PASS")

    def test_broken_checksum_fails(self) -> None:
        (self.runs[0] / "verdict.txt").write_text("tampered\n", encoding="utf-8")
        self.assert_reason("checksum mismatch")

    def test_different_baseline_fails(self) -> None:
        summary = json.loads((self.runs[1] / "summary.json").read_text(encoding="utf-8"))
        summary["production_source_baseline"]["commit"] = "c" * 40
        self.write_json(self.runs[1] / "summary.json", summary)
        self.write_sums(self.runs[1])
        self.assert_reason("different production baselines")

    def test_case_fail_fails(self) -> None:
        (self.runs[2] / "verdict.txt").write_text("FAIL\n", encoding="utf-8")
        self.write_sums(self.runs[2])
        self.assert_reason("verdict is 'FAIL'")

    def test_queue_refusal_inside_envelope_fails(self) -> None:
        path = self.runs[6] / "profiles/M0/resolve-health/live.json"
        value = json.loads(path.read_text(encoding="utf-8"))
        value["workload_totals"]["queue_refusal"] = 1
        self.write_json(path, value)
        self.write_sums(self.runs[6])
        self.assert_reason("queue_refusal=1")


if __name__ == "__main__":
    unittest.main()
