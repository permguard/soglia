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
