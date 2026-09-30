# Copyright (c) 2022 Nitro Agility S.r.l.
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for B7 Resolve-health evidence classification."""

from __future__ import annotations

import importlib.util
import pathlib
import tempfile
import unittest


SCRIPT = pathlib.Path(__file__).with_name("b7-profile.py")
SPEC = importlib.util.spec_from_file_location("b7_profile", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
B7 = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(B7)


def health_line(**overrides: int) -> str:
    fields = {
        "interval_ms": 1001,
        "resolved": 3,
        "delayed_hit": 0,
        "not_found": 0,
        "identity_mismatch": 0,
        "stale_generation": 0,
        "revoked": 0,
        "timeout": 0,
        "queue_refusal": 0,
        "unavailable": 0,
        "integrity_failure": 0,
        "latency_max_us": 42,
    }
    fields.update(overrides)
    values = " ".join(f"{name}={value}" for name, value in fields.items())
    return (
        "\x1b[32mINFO\x1b[0m snapshot "
        "\x1b[3mevent.name\x1b[0m=\x1b[0m\"cgroup_bpf.resolve_health\" "
        f"{values}"
    )


class B7ProfileTests(unittest.TestCase):
    def test_nft_counter_reads_the_counter_expression_beside_a_rule_comment(
        self,
    ) -> None:
        ruleset = {
            "nftables": [
                {"metainfo": {"version": "1.0.9"}},
                {
                    "rule": {
                        "comment": "b7_dns_udp",
                        "expr": [
                            {"match": {"op": "=="}},
                            {"counter": {"packets": 17, "bytes": 1020}},
                        ],
                    }
                },
            ]
        }
        self.assertEqual(B7.nft_counter_value(ruleset, "b7_dns_udp"), 17)

    def test_distinct_syn_attempts_ignore_retransmissions_and_capture_duplicates(
        self,
    ) -> None:
        lines = [
            "1.000000 lo Out IP 11.0.0.1.40000 > 11.0.0.1.443: "
            "Flags [S], seq 1, win 65495, length 0",
            "2.000000 lo Out IP 11.0.0.1.40000 > 11.0.0.1.443: "
            "Flags [S], seq 1, win 65495, length 0",
            "2.000001 lo In  IP 11.0.0.1.40000 > 11.0.0.1.443: "
            "Flags [S], seq 1, win 65495, length 0",
            "3.000000 lo Out IP 11.0.0.1.40001 > 11.0.0.1.443: "
            "Flags [S], seq 2, win 65495, length 0",
            "3.000001 lo In  IP 11.0.0.1.443 > 11.0.0.1.40001: "
            "Flags [S.], seq 3, ack 2, win 65483, length 0",
        ]
        result = B7.distinct_syn_attempts(lines)
        self.assertEqual(result["raw_syn_packets"], 4)
        self.assertEqual(result["distinct_connection_attempts"], 2)
        self.assertEqual(result["duplicate_or_retransmitted_syn_packets"], 2)
        self.assertEqual(
            [flow["source_port"] for flow in result["flows"]], [40000, 40001]
        )

    def test_parses_and_sums_ansi_resolve_health(self) -> None:
        events = B7.parse_resolve_health([
            health_line(resolved=3),
            health_line(resolved=2, queue_refusal=1),
        ])
        totals = B7.sum_resolve_health(events)
        self.assertEqual(totals["resolved"], 5)
        self.assertEqual(totals["queue_refusal"], 1)

    def test_supported_workload_rejects_any_negative_outcome(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            (root / "resolve-health").mkdir()
            record = {
                "label": "rate",
                "workload_totals": {
                    **{field: 0 for field in B7.RESOLVE_OUTCOMES},
                    "resolved": 9,
                    "queue_refusal": 1,
                    "delayed_hit": 0,
                    "stale_generation": 0,
                },
                "verdict": "PASS",
            }
            with self.assertRaises(RuntimeError):
                B7.assert_supported_health(record, 10, root)
            self.assertEqual(record["verdict"], "FAIL")

    def test_rate_measurement_must_be_one_shot(self) -> None:
        value = {
            "requested": 30,
            "attempts": 31,
            "retry_count": 1,
            "strategy": "retry",
            "succeeded": 30,
            "failed": 0,
            "elapsed_ms": 30000,
            "max_us": 100,
        }
        with self.assertRaises(RuntimeError):
            B7.assert_measurement(value, 1, 30, 2000)


if __name__ == "__main__":
    unittest.main()
