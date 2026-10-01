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
        self.runs.append(self.make_uninstall_run())

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
        (run / "stop-classification.txt").write_text("NATIVE\n", encoding="utf-8")
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
                    "requested": 4,
                    "succeeded": 3,
                    "refused": 1,
                    "effects": {
                        "dns_packet_delta": {"tcp": 0, "udp": 0},
                        "rejected_connection_outbound_attempts": 0,
                        "rejected_connection_outbound_accepts": 0,
                        "outbound_connection_attempts": {
                            "distinct_connection_attempts": 3,
                            "raw_syn_packets": 4,
                            "duplicate_or_retransmitted_syn_packets": 1,
                        },
                    },
                    "resolve_health": {"workload_totals": {"queue_refusal": 1}},
                    "immediate_control": {"body": {"succeeded": 1}},
                },
            )
        self.write_sums(run)
        return run

    def make_uninstall_run(self) -> Path:
        run = self.root / "uninstall-fixture"
        run.mkdir()
        cases = {
            name: "PASS"
            for name in (
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
            )
        }
        self.write_json(
            run / "summary.json",
            {
                "gate": "UNINSTALL",
                "run_id": run.name,
                "authoritative": True,
                "verdict": "PASS",
                "cleanup": {"verdict": "PASS"},
                "production_source_baseline": {"commit": "b" * 40, "matches": True},
                "cases": cases,
            },
        )
        (run / "verdict.txt").write_text("PASS\n", encoding="utf-8")
        (run / "source-fingerprint.txt").write_text(
            f"{'a' * 40}\n{VERIFY.EMPTY_DIFF_SHA256}  -\n", encoding="utf-8"
        )
        (run / "stop-classification.txt").write_text("NATIVE\n", encoding="utf-8")
        self.write_json(
            run / "cases/known_compatible/residue-before-harness-teardown.json",
            {"measured_before_harness_teardown": True, "owned_residue": False},
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
        self.assertTrue(all(run["systemd_prune_races"] == 0 for run in result["runs"]))

    def test_systemd_prune_race_is_counted(self) -> None:
        path = self.runs[0] / "stop-classification.txt"
        path.write_text("SYSTEMD_PRUNE_RACE\n", encoding="utf-8")
        self.write_sums(self.runs[0])
        result = VERIFY.verify(self.runs)
        self.assertEqual(result["runs"][0]["systemd_prune_races"], 1)

    def test_invalid_stop_classification_fails(self) -> None:
        path = self.runs[0] / "stop-classification.txt"
        path.write_text("IGNORED_CHURN\n", encoding="utf-8")
        self.write_sums(self.runs[0])
        self.assert_reason("invalid stop classification")

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

    def test_b5_tamper_with_recomputed_checksum_fails(self) -> None:
        path = self.runs[4] / "driver/proxy-steering-boundary.json"
        value = json.loads(path.read_text(encoding="utf-8"))
        value["runtime"]["destinations_match"] = False
        self.write_json(path, value)
        self.write_sums(self.runs[4])
        self.assert_reason("runtime destinations differ")

    def test_b6_tamper_with_recomputed_checksum_fails(self) -> None:
        path = self.runs[5] / "cases/sandbox_sigkill/result.json"
        value = json.loads(path.read_text(encoding="utf-8"))
        value["target_released"]["exact_link_detaches_verified"] = 5
        self.write_json(path, value)
        self.write_sums(self.runs[5])
        self.assert_reason("six exact link detaches")

    def test_b7_tamper_with_recomputed_checksum_fails(self) -> None:
        path = self.runs[6] / "profiles/M3/burst-characterization.json"
        value = json.loads(path.read_text(encoding="utf-8"))
        value["effects"]["rejected_connection_outbound_attempts"] = 1
        self.write_json(path, value)
        self.write_sums(self.runs[6])
        self.assert_reason("refused connections produced outbound attempts")

    def tamper_b7(self, mutate: object, reason: str) -> None:
        path = self.runs[6] / "profiles/M3/burst-characterization.json"
        value = json.loads(path.read_text(encoding="utf-8"))
        assert callable(mutate)
        mutate(value)
        self.write_json(path, value)
        self.write_sums(self.runs[6])
        self.assert_reason(reason)

    def test_b7_rejected_accept_tamper_fails(self) -> None:
        self.tamper_b7(
            lambda value: value["effects"].__setitem__("rejected_connection_outbound_accepts", 1),
            "refused connections produced outbound accepts",
        )

    def test_b7_requested_accounting_tamper_fails(self) -> None:
        self.tamper_b7(lambda value: value.__setitem__("requested", 5), "requested count differs")

    def test_b7_control_success_tamper_fails(self) -> None:
        self.tamper_b7(
            lambda value: value["immediate_control"]["body"].__setitem__("succeeded", 0),
            "control connection did not succeed",
        )

    def test_b7_syn_accounting_tamper_fails(self) -> None:
        self.tamper_b7(
            lambda value: value["effects"]["outbound_connection_attempts"].__setitem__("raw_syn_packets", 5),
            "raw SYN accounting is inconsistent",
        )

    def test_b7_burst_verdict_tamper_fails(self) -> None:
        self.tamper_b7(lambda value: value.__setitem__("verdict", "FAIL"), "burst verdict is not PASS")

    def test_uninstall_case_tamper_fails(self) -> None:
        path = self.runs[7] / "summary.json"
        value = json.loads(path.read_text(encoding="utf-8"))
        value["cases"]["normal_service_stop"] = "FAIL"
        self.write_json(path, value)
        self.write_sums(self.runs[7])
        self.assert_reason("normal_service_stop is not PASS")

    def test_uninstall_residue_tamper_fails(self) -> None:
        path = self.runs[7] / "cases/known_compatible/residue-before-harness-teardown.json"
        value = json.loads(path.read_text(encoding="utf-8"))
        value["owned_residue"] = True
        self.write_json(path, value)
        self.write_sums(self.runs[7])
        self.assert_reason("does not prove zero residue")


if __name__ == "__main__":
    unittest.main()
