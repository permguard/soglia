<!-- Copyright (c) 2022 Nitro Agility S.r.l. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# S13 spike ownership and recovery contract

This contract is experimental qualification machinery. It does not implement or select a production `CgroupBpfBackend`.

## Trust roots and identity

The ownership record lives below a root-owned, non-symlink `/run/soglia` directory with mode `0700`. Its per-run directory is mode `0700`; `state.json` is a root-owned regular file with mode `0600`, published by write, file sync, atomic rename and directory sync.

An owned state is identified by all of the following, never by a pathname or name prefix alone:

- magic `SOGLIA_CGROUP_BPF_SPIKE_STATE`, schema version 1 and ABI version 1;
- a random 128-bit `state_id` and monotonically increasing nonzero generation;
- exact BPF object SHA-256 and exact per-run pin root;
- exact target cgroup path, inode, cgroup v2 file handle and mount identity;
- exact map IDs, program identities and link identities in the READY manifest;
- a 48-byte `soglia_meta` value binding magic, schema, ABI, state ID and generation.

The expected inventory is ten named maps and six named links. Map type, key width, value width, capacity and flags are validated before state can be considered compatible.

## State machine

Startup performs this order:

1. classify existing state as `Fresh`, `KnownCompatible`, `TargetReleased`, `Incompatible` or `Unknown`;
2. for known compatible residue, validate the trusted record, kernel identities, metadata and exact inventory, then remove only those recorded objects and prove their absence; for proposed `TargetReleased` residue, apply the stricter released-target proof below before any removal;
3. atomically publish durable `INTENT` for a new generation;
4. create the expected maps, programs, links and pins;
5. bind `soglia_meta` and validate the kernel contract;
6. atomically publish the durable READY manifest;
7. publish `startup.ready` last.

Fresh and known-compatible states may proceed. Incompatible or unknown state fails closed without altering its kernel objects or contents. A pin root without a trusted record is unknown. An unexpected object beneath an otherwise recorded root is also unknown. Cleanup by broad prefix, guessed name or stale generation is forbidden.

## Crash recovery

S13 exercises interruption after durable INTENT, after pin creation, after kernel validation and after durable READY but before readiness publication. At every boundary readiness must still be absent. The next start must classify the residue as known compatible, validate it, sweep its exact recorded generation, create generation `N+1`, and publish readiness only after the new READY record is durable.

Stale policy, cookie or tuple entries are never inherited into the next generation. Old kernel IDs must be absent before readiness, and a stale generation cannot authorize a new request.

### Released-target recovery

`TargetReleased` is the production recovery path for the case in which a real systemd restart has released the cgroup named by the durable attachment-target record. The offline-target form below is implemented but remains unqualified until B1-B6 are repeated on the schema-3 backend. It does not weaken the cgroup-ID check and is not a pathname-based ownership inference.

The classifier may return `TargetReleased` only after the Sandbox kill-all barrier and only when every predicate below is proven:

- the durable record is otherwise fully trusted and compatible, including schema, ABI, state ID, generation, object/configuration hashes, pin root and exact recorded map, program and link IDs;
- the durable record contains the exact cgroup v2 file handle obtained with `name_to_handle_at` while the attachment target was live, including handle type, length and bytes, plus the non-reusable mount identity obtained with `statx(STATX_MNT_ID_UNIQUE)` on the same live target fd; a reusable mount ID is never accepted; `open_by_handle_at` on that exact handle now returns exactly `ESTALE`;
- every recorded link pin opens the exact recorded link, program and attach type, and direct `BPF_OBJ_GET_INFO_BY_FD` reports only the recorded old target ID or zero, never another live or unknown ID; every value is recorded and no object is modified while classifying; `bpftool`, its exit status and text parsing are never ownership sources;
- the current `executions/` cgroup has an ID different from the recorded attachment-target ID;
- the current `executions/` cgroup is empty, is below the current systemd unit's delegated cgroup, and satisfies the normal ownership, mode and no-internal-process checks;
- there is no unexpected pin, map, program, link, policy entry or per-Execution ownership record outside the exact durable inventory;
- the Sandbox kill-all barrier proved every old Execution process dead and every old Execution pathname absent, and the production launch path still cannot pass an Execution-created socket FD outside the Execution.
- the environment's offline-cgroup capability was qualified on disposable FDs opened before removal: a retained `cgroup.procs` FD rejects PID writes with `ENODEV`, and a retained directory FD rejects `clone3(CLONE_INTO_CGROUP)` with `ENOENT`; neither path creates or moves a process.

Only after all predicates pass may recovery call `BPF_LINK_DETACH` on each descriptor opened from its exact recorded pin. Every detach must succeed; the immediate `BPF_OBJ_GET_INFO_BY_FD` result must report cgroup ID zero with the link ID, program ID and attach type unchanged. Only then may recovery remove the exact recorded links, programs, maps and pins. It must prove every old ID and pin absent, create generation `N+1` against the current empty attachment target, prove the new policy, cookie and tuple maps empty, and publish READY last. No old map entry, `BindingKey` or authorization is imported.

If the old handle is openable or returns anything other than `ESTALE`, any recorded link reports an ID other than its recorded old ID or zero, a recorded identity differs, or the current target is non-empty or belongs to another unit, the classification is `Unknown`. Unknown state remains byte-for-byte and ID-for-ID untouched. A detach error or post-detach identity mismatch also stops recovery without broad cleanup.

B6 additionally scans the complete live cgroup2 hierarchy and records that no live path reports the old ID. This is corroborating harness evidence, not a production classification predicate: `ESTALE` from `open_by_handle_at` on the exact durable handle is the direct kernel answer for that cgroup, while a hierarchy scan is costly on large hosts and can already be stale when it completes.

Non-authoritative run `b6-target-offline-final-20260929T234729Z-67073` on Linux 6.8.0-142-generic aarch64 with systemd 255 supplies the diagnostic basis: `ESTALE` from the stored pre-loss handle, no live path for the old ID, six links retaining only that old ID while the target was offline, and six successful direct `BPF_LINK_DETACH` operations that preserved link/program/attach identity and changed cgroup ID to zero. B5 authoritative run `b5-20260929T140856Z-8731` supplies the current no-socket-FD-transfer evidence. Both are environment-specific and must be repeated by B1/B5/B6 for every supported production environment.

## Refusal and cleanup

Malformed schema or ABI is `Incompatible`; missing trust, mismatched pin root/cgroup/kernel identity/metadata, foreign inventory, or a released target that fails any `TargetReleased` predicate is `Unknown`. Both refusal classifications leave the observed state byte-for-byte and ID-for-ID unchanged.

Normal cleanup first revalidates ownership, removes only the exact manifest, verifies BPF program/link/map baselines, and then removes the ownership record and run-owned directories. Any unverifiable or unowned residue produces `CLEANUP_FAIL` rather than a broad deletion.
