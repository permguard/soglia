#!/usr/bin/env python3
# Copyright (c) 2022 Nitro Agility S.r.l.
# SPDX-License-Identifier: Apache-2.0

"""Tests for qualification configuration preflight."""

from __future__ import annotations

import importlib.util
import pathlib
import tempfile
import unittest


SCRIPT = pathlib.Path(__file__).with_name("preflight_qualification_configs.py")
SPEC = importlib.util.spec_from_file_location("preflight_qualification_configs", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
PREFLIGHT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PREFLIGHT)


class QualificationConfigPreflightTests(unittest.TestCase):
    def test_all_harness_yaml_templates_render_without_unresolved_shell(self) -> None:
        scripts = SCRIPT.parent
        rendered = [
            PREFLIGHT.render(template, source)
            for source, template in PREFLIGHT.templates(scripts)
        ]
        self.assertGreaterEqual(len(rendered), 18)
        self.assertTrue(all("$" not in yaml for yaml in rendered))

    def test_dynamic_b7_and_uninstall_variants_are_all_declared(self) -> None:
        b7 = PREFLIGHT.variants("b7-qualification.sh:275")
        uninstall = PREFLIGHT.variants("uninstall-qualification.sh:109")
        self.assertEqual([name for name, _ in b7], ["M0", "M1", "M2", "M3", "B8", "drift"])
        self.assertEqual([name for name, _ in uninstall], ["cgroup-bpf", "netns-nft"])

    def test_invalid_generated_configuration_is_an_infrastructure_error(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            script = root / "invalid.sh"
            script.write_text(
                """#!/usr/bin/env bash
cat > \"$config\" <<YAML
runtime:
  state_dir: /run/soglia
  max_concurrency: 2
  max_queue: 2
network:
  backend: cgroup-bpf
  max_proxy_connections: 65
cgroup_bpf:
  max_tracked_sockets: 64
agents: {}
YAML
""",
                encoding="utf-8",
            )
            validator = root / "validator"
            validator.write_text("#!/bin/sh\nexit 13\n", encoding="utf-8")
            validator.chmod(0o755)
            with self.assertRaisesRegex(
                PREFLIGHT.PreflightError, "production parser rejected generated YAML"
            ):
                PREFLIGHT.preflight(root, validator, "B1")


if __name__ == "__main__":
    unittest.main()
