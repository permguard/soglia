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
- exact target cgroup path and inode;
- exact map IDs, program identities and link identities in the READY manifest;
- a 48-byte `soglia_meta` value binding magic, schema, ABI, state ID and generation.

The expected inventory is ten named maps and six named links. Map type, key width, value width, capacity and flags are validated before state can be considered compatible.

## State machine

Startup performs this order:

1. classify existing state as `Fresh`, `KnownCompatible`, `Incompatible` or `Unknown`;
2. for known compatible residue, validate the trusted record, kernel identities, metadata and exact inventory, then remove only those recorded objects and prove their absence;
3. atomically publish durable `INTENT` for a new generation;
4. create the expected maps, programs, links and pins;
5. bind `soglia_meta` and validate the kernel contract;
6. atomically publish the durable READY manifest;
7. publish `startup.ready` last.

Fresh and known-compatible states may proceed. Incompatible or unknown state fails closed without altering its kernel objects or contents. A pin root without a trusted record is unknown. An unexpected object beneath an otherwise recorded root is also unknown. Cleanup by broad prefix, guessed name or stale generation is forbidden.

## Crash recovery

S13 exercises interruption after durable INTENT, after pin creation, after kernel validation and after durable READY but before readiness publication. At every boundary readiness must still be absent. The next start must classify the residue as known compatible, validate it, sweep its exact recorded generation, create generation `N+1`, and publish readiness only after the new READY record is durable.

Stale policy, cookie or tuple entries are never inherited into the next generation. Old kernel IDs must be absent before readiness, and a stale generation cannot authorize a new request.

## Refusal and cleanup

Malformed schema or ABI is `Incompatible`; missing trust, mismatched pin root/cgroup/kernel identity/metadata, or foreign inventory is `Unknown`. Both classifications leave the observed state byte-for-byte and ID-for-ID unchanged.

Normal cleanup first revalidates ownership, removes only the exact manifest, verifies BPF program/link/map baselines, and then removes the ownership record and run-owned directories. Any unverifiable or unowned residue produces `CLEANUP_FAIL` rather than a broad deletion.
