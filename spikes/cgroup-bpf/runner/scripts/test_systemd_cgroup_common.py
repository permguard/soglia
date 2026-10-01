#!/usr/bin/env python3
# Copyright (c) 2022 Nitro Agility S.r.l.
# SPDX-License-Identifier: Apache-2.0

import subprocess
import unittest
from pathlib import Path


SCRIPT = Path(__file__).with_name("systemd-cgroup-common.sh")


def is_stopped_state(state: str) -> bool:
    command = f'source "$1"; systemd_cgroup_is_stopped_state "$2"'
    result = subprocess.run(
        ["bash", "-c", command, "bash", str(SCRIPT), state],
        check=False,
    )
    return result.returncode == 0


class SystemdCgroupCommonTests(unittest.TestCase):
    def test_terminal_states_are_accepted(self) -> None:
        self.assertTrue(is_stopped_state("inactive"))
        self.assertTrue(is_stopped_state("failed"))

    def test_running_and_transitional_states_are_rejected(self) -> None:
        for state in ("active", "activating", "deactivating", "reloading", "maintenance"):
            with self.subTest(state=state):
                self.assertFalse(is_stopped_state(state))


if __name__ == "__main__":
    unittest.main()
