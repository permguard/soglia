#!/usr/bin/env python3
# Copyright (c) 2022 Nitro Agility S.r.l.
# SPDX-License-Identifier: Apache-2.0

"""Tests for the B8 characterization ramp contract."""

from __future__ import annotations

import importlib.util
import pathlib
import unittest


SCRIPT = pathlib.Path(__file__).with_name("b8-characterize.py")
SPEC = importlib.util.spec_from_file_location("b8_characterize", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
B8 = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(B8)


class B8CharacterizationTests(unittest.TestCase):
    def test_ramp_extends_beyond_the_old_two_thousand_per_second_cap(self) -> None:
        self.assertEqual(B8.RAMP_REQUESTED_RATES[:6], (500, 750, 1000, 1250, 1500, 2000))
        self.assertGreater(B8.RAMP_RATE_CAP_PER_SECOND, 2000)
        self.assertEqual(B8.RAMP_REQUESTED_RATES[-1], B8.RAMP_RATE_CAP_PER_SECOND)

    def test_breakpoint_reasons_are_explicit(self) -> None:
        measured = {"failed": 1, "p99_us": 20_001}
        self.assertEqual(
            B8.breakpoint_reasons(measured, requested=1000, achieved=949.0),
            [
                "negative_outcome",
                "p99_above_20_ms",
                "achieved_rate_below_95_percent",
            ],
        )

    def test_healthy_step_has_no_breakpoint_reason(self) -> None:
        measured = {"failed": 0, "p99_us": 20_000}
        self.assertEqual(B8.breakpoint_reasons(measured, requested=1000, achieved=950.0), [])


if __name__ == "__main__":
    unittest.main()
