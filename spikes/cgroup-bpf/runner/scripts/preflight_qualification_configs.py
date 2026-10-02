#!/usr/bin/env python3
# Copyright (c) 2022 Nitro Agility S.r.l.
# SPDX-License-Identifier: Apache-2.0

"""Render every harness YAML heredoc and validate it with the production parser."""

from __future__ import annotations

import argparse
import ast
import json
import pathlib
import re
import subprocess
import tempfile
from typing import Any


HEREDOC = re.compile(r"^\s*cat\s+>\s+.+?\s+<<-?['\"]?(YAML)['\"]?\s*$")
ARITHMETIC = re.compile(r"\$\(\((.*?)\)\)")
VARIABLE = re.compile(r"\$(?:\{([A-Za-z_][A-Za-z0-9_]*)\}|([A-Za-z_][A-Za-z0-9_]*))")

VALUES: dict[str, str | int] = {
    "backend": "cgroup-bpf",
    "bpftool_path": "/usr/sbin/bpftool",
    "cgroup": "/sys/fs/cgroup/soglia-preflight",
    "cgroup_root": "/sys/fs/cgroup/soglia-preflight",
    "concurrency": 4,
    "id": "preflight",
    "ingress": 18080,
    "max_pending_resolves": 64,
    "max_proxy_connections": 64,
    "ordinal": 1,
    "owner_cgroup": "/sys/fs/cgroup/soglia-preflight",
    "pin_parent": "/sys/fs/bpf/soglia-preflight",
    "pin_root": "/sys/fs/bpf/soglia-preflight",
    "port": 18080,
    "profile": "M0",
    "proxy_ip": "10.200.255.1",
    "proxy_port": 15001,
    "resolve_workers": 4,
    "root": "/sys/fs/cgroup/soglia-preflight",
    "root_cgroup": "/sys/fs/cgroup/soglia-preflight",
    "rootfs": "/var/empty",
    "runc_path": "/usr/sbin/runc",
    "runtime": "/run/soglia-preflight",
    "runtime_cgroup": "/sys/fs/cgroup/soglia-preflight",
    "runtime_parent": "/run/soglia-preflight",
    "sockets": 64,
    "unit": "soglia-preflight",
    "unit_cgroup": "/sys/fs/cgroup/soglia-preflight",
}


class PreflightError(RuntimeError):
    """A generated configuration could not be validated before VM launch."""


def evaluate_arithmetic(expression: str, values: dict[str, str | int]) -> int:
    expanded = expression
    for name, value in values.items():
        if isinstance(value, int):
            expanded = re.sub(rf"\b{re.escape(name)}\b", str(value), expanded)
    tree = ast.parse(expanded, mode="eval")

    def evaluate(node: ast.AST) -> int:
        if isinstance(node, ast.Expression):
            return evaluate(node.body)
        if isinstance(node, ast.Constant) and isinstance(node.value, int):
            return node.value
        if isinstance(node, ast.BinOp) and isinstance(
            node.op, (ast.Add, ast.Sub, ast.Mult, ast.FloorDiv)
        ):
            left, right = evaluate(node.left), evaluate(node.right)
            if isinstance(node.op, ast.Add):
                return left + right
            if isinstance(node.op, ast.Sub):
                return left - right
            if isinstance(node.op, ast.Mult):
                return left * right
            return left // right
        raise PreflightError(f"unsupported shell arithmetic in generated YAML: {expression}")

    return evaluate(tree)


def render(
    template: str,
    source: str,
    overrides: dict[str, str | int] | None = None,
) -> str:
    values = VALUES | (overrides or {})
    rendered = ARITHMETIC.sub(
        lambda match: str(evaluate_arithmetic(match.group(1), values)), template
    )

    def replace(match: re.Match[str]) -> str:
        name = match.group(1) or match.group(2)
        if name not in values:
            raise PreflightError(f"{source}: unresolved generated-YAML variable ${name}")
        return str(values[name])

    rendered = VARIABLE.sub(replace, rendered)
    if "$" in rendered:
        raise PreflightError(f"{source}: unresolved shell expression remains in generated YAML")
    return rendered


def variants(source: str) -> list[tuple[str, dict[str, str | int]]]:
    if source.startswith("uninstall-qualification.sh:"):
        return [("cgroup-bpf", {}), ("netns-nft", {"backend": "netns-nft"})]
    if source.startswith("b7-qualification.sh:"):
        return [
            (
                "M0",
                {"profile": "M0", "concurrency": 1, "sockets": 64, "max_proxy_connections": 64},
            ),
            (
                "M1",
                {"profile": "M1", "concurrency": 4, "sockets": 512, "max_proxy_connections": 512},
            ),
            (
                "M2",
                {"profile": "M2", "concurrency": 4, "sockets": 4096, "max_proxy_connections": 512},
            ),
            (
                "M3",
                {"profile": "M3", "concurrency": 32, "sockets": 4096, "max_proxy_connections": 512},
            ),
            (
                "B8",
                {"profile": "B8", "concurrency": 4, "sockets": 4096, "max_proxy_connections": 512},
            ),
            (
                "drift",
                {"profile": "drift", "concurrency": 1, "sockets": 64, "max_proxy_connections": 64},
            ),
        ]
    return [("default", {})]


def templates(scripts_root: pathlib.Path) -> list[tuple[str, str]]:
    found: list[tuple[str, str]] = []
    for path in sorted(scripts_root.glob("*.sh")):
        lines = path.read_text(encoding="utf-8").splitlines()
        index = 0
        while index < len(lines):
            match = HEREDOC.match(lines[index])
            if match is None:
                index += 1
                continue
            delimiter = match.group(1)
            start = index + 1
            index = start
            while index < len(lines) and lines[index].strip() != delimiter:
                index += 1
            if index == len(lines):
                raise PreflightError(f"{path}:{start}: unterminated {delimiter} heredoc")
            body = "\n".join(lines[start:index]) + "\n"
            if re.search(r"^runtime:\s*$", body, re.MULTILINE) and re.search(
                r"^network:\s*$", body, re.MULTILINE
            ):
                source = f"{path.name}:{start + 1}"
                found.append((source, body))
            index += 1
    if not found:
        raise PreflightError(f"no qualification YAML templates found under {scripts_root}")
    return found


def preflight(
    scripts_root: pathlib.Path,
    validator: pathlib.Path,
    gate: str,
) -> dict[str, Any]:
    discovered = templates(scripts_root)
    with tempfile.TemporaryDirectory(prefix="soglia-config-preflight-") as temporary:
        directory = pathlib.Path(temporary)
        paths: list[pathlib.Path] = []
        sources: list[str] = []
        number = 0
        for source, template in discovered:
            for variant, overrides in variants(source):
                number += 1
                path = directory / f"config-{number:02d}.yaml"
                path.write_text(render(template, source, overrides), encoding="utf-8")
                paths.append(path)
                sources.append(f"{source}[{variant}]")
        completed = subprocess.run(
            [str(validator), *(str(path) for path in paths)],
            capture_output=True,
            text=True,
            check=False,
        )
        if completed.returncode != 0:
            detail = completed.stderr.strip() or completed.stdout.strip()
            raise PreflightError(f"production parser rejected generated YAML: {detail}")
    return {
        "schema": 1,
        "gate": gate,
        "verdict": "PASS",
        "classification": "CONFIG_PREFLIGHT",
        "production_parser": str(validator),
        "configurations": len(sources),
        "sources": sources,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--scripts-root", type=pathlib.Path, required=True)
    parser.add_argument("--validator", type=pathlib.Path, required=True)
    parser.add_argument("--gate", required=True)
    parser.add_argument("--json-output", type=pathlib.Path, required=True)
    args = parser.parse_args()
    try:
        result = preflight(args.scripts_root, args.validator, args.gate)
    except (OSError, PreflightError) as error:
        result = {
            "schema": 1,
            "gate": args.gate,
            "verdict": "INFRA_ERROR",
            "classification": "CONFIG_PREFLIGHT",
            "reason": str(error),
        }
        args.json_output.write_text(
            json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        print(f"INFRA_ERROR: {error}")
        return 13
    args.json_output.write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(
        f"CONFIG_PREFLIGHT gate={args.gate} configurations={result['configurations']} PASS"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
