#!/usr/bin/env python3
# Copyright (c) 2022 Nitro Agility S.r.l.
# SPDX-License-Identifier: Apache-2.0

"""Classify qualification-host BPF program inventory changes from raw evidence."""

from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path
from typing import Any


PRODUCTION_PROGRAMS = {
    "soglia_sock_create",
    "soglia_connect4",
    "soglia_connect6",
    "soglia_sendmsg4",
    "soglia_sendmsg6",
    "soglia_sockops",
}


def load(path: Path) -> Any:
    with path.open(encoding="utf-8") as source:
        return json.load(source)


def program(program: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": program.get("id"),
        "name": program.get("name"),
        "type": program.get("type"),
        "tag": program.get("tag"),
    }


def signature(program: dict[str, Any]) -> tuple[Any, Any, Any]:
    return (program.get("name"), program.get("type"), program.get("tag"))


def stable(programs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted((program(item) for item in programs), key=lambda item: json.dumps(item, sort_keys=True))


def signatures(programs: list[dict[str, Any]]) -> list[tuple[Any, Any, Any]]:
    return sorted((signature(item) for item in programs), key=repr)


def non_systemd(programs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [item for item in stable(programs) if not str(item.get("name") or "").startswith("sd_")]


def systemd_without_ids(programs: list[dict[str, Any]]) -> list[tuple[Any, Any, Any]]:
    return sorted(
        (signature(item) for item in programs if str(item.get("name") or "").startswith("sd_")),
        key=repr,
    )


def multiset_difference(
    left: list[dict[str, Any]], right: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    remaining = Counter(signature(item) for item in right)
    difference: list[dict[str, Any]] = []
    for item in sorted(left, key=lambda value: (repr(signature(value)), value.get("id", -1))):
        key = signature(item)
        if remaining[key]:
            remaining[key] -= 1
        else:
            difference.append(program(item))
    return difference


def pin_state(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {"valid": False, "path": None, "exists": None, "entries": []}
    entries = value.get("entries")
    exists = value.get("exists")
    path = value.get("path")
    return {
        "valid": (
            isinstance(path, str)
            and bool(path)
            and isinstance(exists, bool)
            and isinstance(entries, list)
        ),
        "path": path,
        "exists": exists,
        "entries": entries if isinstance(entries, list) else [],
    }


def attachments(tree: Any, program_id: Any) -> list[dict[str, Any]]:
    found: list[dict[str, Any]] = []
    if not isinstance(tree, list):
        return found
    for node in tree:
        if not isinstance(node, dict):
            continue
        cgroup = node.get("cgroup")
        for attached in node.get("programs", []):
            if isinstance(attached, dict) and attached.get("id") == program_id:
                found.append({"cgroup": cgroup, "program": attached})
    return found


def inside_subtree(path: Any, subtree: str) -> bool:
    if not isinstance(path, str):
        return True
    normalized = subtree.rstrip("/")
    return path == normalized or path.startswith(f"{normalized}/")


def prove_external(
    changed: dict[str, Any],
    *,
    production_tags: set[str],
    production_tags_complete: bool,
    links: Any,
    tree: Any,
    pins: dict[str, Any],
    cgroup_subtree: str,
    direction: str,
) -> dict[str, Any]:
    program_id = changed.get("id")
    matching_links = []
    if isinstance(links, list):
        matching_links = [item for item in links if isinstance(item, dict) and item.get("prog_id") == program_id]
    direct_attachments = attachments(tree, program_id)
    outside_only = bool(direct_attachments) and all(
        not inside_subtree(item.get("cgroup"), cgroup_subtree) for item in direct_attachments
    )
    tag = changed.get("tag")
    tag_distinct = (
        production_tags_complete
        and isinstance(tag, str)
        and bool(tag)
        and tag not in production_tags
    )
    pin_root_clear = pins["valid"] and (
        (not pins["exists"] and not pins["entries"])
        or (pins["exists"] and pins["entries"] == [pins["path"]])
    )
    proof_complete = tag_distinct and pin_root_clear and not matching_links and outside_only
    return {
        "direction": direction,
        "program": changed,
        "confirmation": {"name": changed.get("name"), "type": changed.get("type")},
        "production_tag_distinct": tag_distinct,
        "soglia_pin_root": pins,
        "links_using_program": matching_links,
        "direct_cgroup_attachments": direct_attachments,
        "attached_only_outside_soglia_subtree": outside_only,
        "proof_complete": proof_complete,
    }


def classify(
    before_programs: Any,
    after_programs: Any,
    before_links: Any,
    after_links: Any,
    before_tree: Any,
    after_tree: Any,
    before_pins: Any,
    after_pins: Any,
    production_programs: Any,
    cgroup_subtree: str,
) -> dict[str, Any]:
    if not isinstance(before_programs, list) or not isinstance(after_programs, list):
        return {"schema": 1, "classification": "FAIL", "reason": "invalid program inventory"}

    production = [program(item) for item in production_programs] if isinstance(production_programs, list) else []
    production_names = {str(item.get("name")) for item in production}
    production_tags = {str(item.get("tag")) for item in production if item.get("tag")}
    production_tags_complete = PRODUCTION_PROGRAMS.issubset(production_names) and len(production_tags) >= 6
    exact = stable(before_programs) == stable(after_programs)
    churn = (
        not exact
        and signatures(before_programs) == signatures(after_programs)
        and non_systemd(before_programs) == non_systemd(after_programs)
        and systemd_without_ids(before_programs) == systemd_without_ids(after_programs)
    )
    added = multiset_difference(after_programs, before_programs)
    removed = multiset_difference(before_programs, after_programs)
    before_pin_state = pin_state(before_pins)
    after_pin_state = pin_state(after_pins)
    addition_proofs = [
        prove_external(
            item,
            production_tags=production_tags,
            production_tags_complete=production_tags_complete,
            links=after_links,
            tree=after_tree,
            pins=after_pin_state,
            cgroup_subtree=cgroup_subtree,
            direction="ADDED",
        )
        for item in added
    ]
    removal_proofs = [
        prove_external(
            item,
            production_tags=production_tags,
            production_tags_complete=production_tags_complete,
            links=before_links,
            tree=before_tree,
            pins=before_pin_state,
            cgroup_subtree=cgroup_subtree,
            direction="REMOVED",
        )
        for item in removed
    ]

    if exact:
        classification = "MATCH"
    elif churn:
        classification = "EXTERNAL_CHURN"
    elif added and not removed and all(item["proof_complete"] for item in addition_proofs):
        classification = "EXTERNAL_ADDITION"
    elif removed and not added and all(item["proof_complete"] for item in removal_proofs):
        classification = "EXTERNAL_REMOVAL"
    else:
        classification = "FAIL"

    return {
        "schema": 1,
        "classification": classification,
        "cgroup_subtree": cgroup_subtree,
        "production_programs": production,
        "production_tags_complete": production_tags_complete,
        "programs_added": addition_proofs,
        "programs_removed": removal_proofs,
        "exact_inventory_match": exact,
        "external_churn_match": churn,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--before-programs", type=Path, required=True)
    parser.add_argument("--after-programs", type=Path, required=True)
    parser.add_argument("--before-links", type=Path, required=True)
    parser.add_argument("--after-links", type=Path, required=True)
    parser.add_argument("--before-tree", type=Path, required=True)
    parser.add_argument("--after-tree", type=Path, required=True)
    parser.add_argument("--before-pins", type=Path, required=True)
    parser.add_argument("--after-pins", type=Path, required=True)
    parser.add_argument("--production-programs", type=Path, required=True)
    parser.add_argument("--cgroup-subtree", required=True)
    arguments = parser.parse_args()
    result = classify(
        load(arguments.before_programs),
        load(arguments.after_programs),
        load(arguments.before_links),
        load(arguments.after_links),
        load(arguments.before_tree),
        load(arguments.after_tree),
        load(arguments.before_pins),
        load(arguments.after_pins),
        load(arguments.production_programs),
        arguments.cgroup_subtree,
    )
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
