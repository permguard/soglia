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
        self.runs = [self.make_run(number) for number in range(1, 9)]
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
        if number == 1:
            summary["qualified"] = {
                "unnamed_external_ancestor_preserved": True,
                "unnamed_external_changed_tag_refused": True,
            }
        if number == 7:
            summary["qualified"] = {"within_envelope_resolve_outcomes_clean": True}
        if number == 8:
            summary["profile"] = {
                "max_pending_resolves": 64,
                "resolve_workers": 4,
                "target_rate_per_second": 500,
                "duration_seconds": 60,
                "p99_us": 10_000,
                "achieved_rate_per_second": 500,
            }
        self.write_json(run / "summary.json", summary)
        (run / "verdict.txt").write_text("PASS\n", encoding="utf-8")
        (run / "source-fingerprint.txt").write_text(
            f"{'a' * 40}\n{VERIFY.EMPTY_DIFF_SHA256}  -\n", encoding="utf-8"
        )
        (run / "stop-classification.txt").write_text("NATIVE\n", encoding="utf-8")
        if number == 1:
            self.write_json(
                run / "cases/unnamed_external/result.json",
                {
                    "verdict": "PASS",
                    "positive": {
                        "startup_ready": True,
                        "effective_on_execution_subtree": True,
                        "bpftool_name": "ABSENT_OR_EMPTY",
                        "program_id": 101,
                        "tag": "1111111111111111",
                        "program_preserved_by_uninstall": True,
                        "link_preserved_by_uninstall": True,
                    },
                    "negative": {
                        "replacement_name": "ABSENT_OR_EMPTY",
                        "program_id": 102,
                        "tag": "2222222222222222",
                        "tag_differs_from_original": True,
                        "refusal_class": "UNKNOWN",
                        "exit_code": 21,
                        "replacement_preserved_during_refusal": True,
                    },
                    "control": {
                        "original_identity_restored": True,
                        "startup_ready": True,
                        "uninstall_preserved_external_program": True,
                    },
                    "cleanup": {"soglia_owned_resources_absent": True},
                },
            )
            contract_cases = {
                name: {
                    "verdict": "PASS",
                    "refusal_class": "INCOMPATIBLE",
                    "stable_exit_code": 20,
                    "durable_inventory_byte_identical": True,
                }
                for name in ("wrong_version", "wrong_max_pending", "wrong_workers", "malformed", "absent")
            }
            self.write_json(
                run / "cases/resolver_contract/result.json",
                {
                    "verdict": "PASS",
                    "typed_exit_code": 20,
                    "ready_emitted": False,
                    "backend_start_called": False,
                    "cases": contract_cases,
                },
            )
        if number == 2:
            self.write_json(
                run / "phase2-contract/result.json",
                {
                    "verdict": "PASS",
                    "cases": {
                        name: {"verdict": "PASS"}
                        for name in (
                            "out_of_order_replies_are_correlated_to_their_request_ids",
                            "cancellation_before_write_removes_the_request_without_a_frame",
                            "a_cancelled_caller_cannot_desynchronize_the_next_exchange",
                            "pending_after_the_publication_deadline_times_out_without_poisoning",
                            "complete_after_the_publication_deadline_is_still_consumed",
                        )
                    },
                },
            )
        if number == 3:
            self.write_json(
                run / "phase2-contract/result.json",
                {
                    "verdict": "PASS",
                    "cases": {
                        "lifecycle_writer_has_priority_over_new_resolve_readers": {"verdict": "PASS"},
                        "out_of_order_replies_are_correlated_to_their_request_ids": {"verdict": "PASS"},
                    },
                },
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
            self.write_json(
                run / "phase2-contract/result.json",
                {
                    "verdict": "PASS",
                    "direct_ipv4": {
                        "resolve_required_before_effect": True,
                        "veth_syn_packets": 0,
                        "execution_nft_drop_path_packets": 0,
                    },
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
        if number == 8:
            fault_names = {
                "duplicate_id", "unknown_id", "out_of_order", "cancel_before_write",
                "cancel_after_write", "partial_frame", "wrong_version",
                "writer_or_exchange_watchdog", "worker_blocked", "worker_panic",
                "malformed_result", "lifecycle_write_contention", "helper_exit",
            }
            self.write_json(
                run / "profiles/B8/b8-characterization.json",
                {
                    "verdict": "PASS",
                    "supported_profile": {
                        "measurement": {
                            "requested": 30_000,
                            "succeeded": 30_000,
                            "failed": 0,
                            "expected_status": 403,
                        },
                        "correct_correlations": True,
                        "negative_outcomes": 0,
                        "post_resolve_decision": "policy_denied",
                        "effects": {
                            "outbound_accept_delta": 0,
                            "dns_packet_delta": {"tcp": 0, "udp": 0},
                            "outbound_attempts": {"distinct_connection_attempts": 0},
                        },
                    },
                    "burst": {
                        "verdict": "PASS", "requested": 4, "succeeded": 3, "refused": 1,
                        "effects": {
                            "rejected_connection_outbound_attempts": 0,
                            "rejected_connection_outbound_accepts": 0,
                            "dns_packet_delta": {"tcp": 0, "udp": 0},
                        },
                    },
                    "baseline_return": {"verdict": "PASS"},
                    "mixed": {"limits_respected": True},
                    "fault_injection": {
                        "verdict": "PASS",
                        "cases": {name: {"verdict": "PASS"} for name in fault_names},
                    },
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

    def test_b1_unnamed_external_tag_tamper_with_recomputed_checksum_fails(self) -> None:
        path = self.runs[0] / "cases/unnamed_external/result.json"
        value = json.loads(path.read_text(encoding="utf-8"))
        value["negative"]["tag"] = value["positive"]["tag"]
        value["negative"]["tag_differs_from_original"] = False
        self.write_json(path, value)
        self.write_sums(self.runs[0])
        self.assert_reason("replacement tag did not change")

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

    def test_b8_p99_tamper_with_recomputed_checksum_fails(self) -> None:
        path = self.runs[7] / "summary.json"
        value = json.loads(path.read_text(encoding="utf-8"))
        value["profile"]["p99_us"] = 20_001
        self.write_json(path, value)
        self.write_sums(self.runs[7])
        self.assert_reason("client p99 exceeds 20 ms")

    def test_b8_fault_tamper_with_recomputed_checksum_fails(self) -> None:
        path = self.runs[7] / "profiles/B8/b8-characterization.json"
        value = json.loads(path.read_text(encoding="utf-8"))
        value["fault_injection"]["cases"]["worker_panic"]["verdict"] = "FAIL"
        self.write_json(path, value)
        self.write_sums(self.runs[7])
        self.assert_reason("fault cases are not PASS")

    def test_b8_resolve_only_outbound_tamper_with_recomputed_checksum_fails(self) -> None:
        path = self.runs[7] / "profiles/B8/b8-characterization.json"
        value = json.loads(path.read_text(encoding="utf-8"))
        value["supported_profile"]["effects"]["outbound_attempts"][
            "distinct_connection_attempts"
        ] = 1
        self.write_json(path, value)
        self.write_sums(self.runs[7])
        self.assert_reason("Resolve-only supported load caused an external effect")

    def test_uninstall_case_tamper_fails(self) -> None:
        path = self.runs[8] / "summary.json"
        value = json.loads(path.read_text(encoding="utf-8"))
        value["cases"]["normal_service_stop"] = "FAIL"
        self.write_json(path, value)
        self.write_sums(self.runs[8])
        self.assert_reason("normal_service_stop is not PASS")

    def test_uninstall_residue_tamper_fails(self) -> None:
        path = self.runs[8] / "cases/known_compatible/residue-before-harness-teardown.json"
        value = json.loads(path.read_text(encoding="utf-8"))
        value["owned_residue"] = True
        self.write_json(path, value)
        self.write_sums(self.runs[8])
        self.assert_reason("does not prove zero residue")


if __name__ == "__main__":
    unittest.main()
