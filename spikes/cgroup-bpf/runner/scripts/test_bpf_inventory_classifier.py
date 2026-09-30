#!/usr/bin/env python3
# Copyright (c) 2022 Nitro Agility S.r.l.
# SPDX-License-Identifier: Apache-2.0

import unittest

from bpf_inventory_classifier import PRODUCTION_PROGRAMS, classify


def item(program_id, name="sd_devices", kind="cgroup_device", tag="external-tag"):
    return {"id": program_id, "name": name, "type": kind, "tag": tag}


def tree(program_id, path="/sys/fs/cgroup/system.slice/fwupd.service"):
    return [{"cgroup": path, "programs": [{"id": program_id, "name": "sd_devices"}]}]


def production():
    return [item(index, name, "cgroup", f"production-{index}") for index, name in enumerate(sorted(PRODUCTION_PROGRAMS), 100)]


PINS_CLEAR = {"path": "/sys/fs/bpf/soglia-b4", "exists": False, "entries": []}
PINS_EMPTY_EXISTING = {
    "path": "/sys/fs/bpf/soglia-b4",
    "exists": True,
    "entries": ["/sys/fs/bpf/soglia-b4"],
}


class ClassifierTests(unittest.TestCase):
    def classify(self, before, after, *, before_tree=None, after_tree=None, before_links=None, after_links=None, prod=None):
        return classify(
            before,
            after,
            before_links or [],
            after_links or [],
            before_tree or [],
            after_tree or [],
            PINS_CLEAR,
            PINS_CLEAR,
            production() if prod is None else prod,
            "/sys/fs/cgroup/system.slice/soglia-b4.service",
        )

    def test_external_addition_is_clean(self):
        result = self.classify([], [item(7)], after_tree=tree(7))
        self.assertEqual(result["classification"], "EXTERNAL_ADDITION")
        self.assertTrue(result["programs_added"][0]["proof_complete"])

    def test_unattached_addition_fails(self):
        self.assertEqual(self.classify([], [item(7)])["classification"], "FAIL")

    def test_addition_inside_soglia_subtree_fails(self):
        result = self.classify([], [item(7)], after_tree=tree(7, "/sys/fs/cgroup/system.slice/soglia-b4.service/executions"))
        self.assertEqual(result["classification"], "FAIL")

    def test_production_tag_addition_fails(self):
        added = item(7, tag="production-100")
        self.assertEqual(self.classify([], [added], after_tree=tree(7))["classification"], "FAIL")

    def test_external_removal_is_clean(self):
        result = self.classify([item(7)], [], before_tree=tree(7))
        self.assertEqual(result["classification"], "EXTERNAL_REMOVAL")
        self.assertTrue(result["programs_removed"][0]["proof_complete"])

    def test_external_removal_with_an_existing_empty_pin_root_is_clean(self):
        result = classify(
            [item(7)],
            [],
            [],
            [],
            tree(7),
            [],
            PINS_EMPTY_EXISTING,
            PINS_CLEAR,
            production(),
            "/sys/fs/cgroup/system.slice/soglia-b4.service",
        )
        self.assertEqual(result["classification"], "EXTERNAL_REMOVAL")
        self.assertTrue(result["programs_removed"][0]["proof_complete"])

    def test_external_removal_with_a_pin_below_the_root_fails(self):
        pinned = {
            "path": "/sys/fs/bpf/soglia-b4",
            "exists": True,
            "entries": [
                "/sys/fs/bpf/soglia-b4",
                "/sys/fs/bpf/soglia-b4/unexpected-pin",
            ],
        }
        result = classify(
            [item(7)],
            [],
            [],
            [],
            tree(7),
            [],
            pinned,
            PINS_CLEAR,
            production(),
            "/sys/fs/cgroup/system.slice/soglia-b4.service",
        )
        self.assertEqual(result["classification"], "FAIL")


if __name__ == "__main__":
    unittest.main()
