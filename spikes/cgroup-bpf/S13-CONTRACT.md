<!-- Copyright (c) 2022 Nitro Agility S.r.l. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# S13 spike-only pinned-state ownership and compatibility contract

This is an experimental contract for the Phase-1 spike. It is not the production
`CgroupBpfBackend` design.

## Trust boundary

The trust anchor is `/run/soglia/cgroup-bpf-spike/state.json`, not bpffs. Soglia already owns
`/run/soglia` as a root-owned mode `0700` state directory. The spike requires every directory in
this record path to be a real directory (not a symlink), owned by uid/gid 0 and mode `0700`; the
record must be root-owned, mode `0600`, and atomically published through a complete temporary file,
file `fsync`, rename, and directory sync. Startup runs as root and refuses the state if any of these
checks fail.

This boundary does not claim protection after an attacker can arbitrarily change all root-owned
Soglia state and kernel objects. It prevents a foreign bpffs object, pathname, or copied
`soglia_meta` value from becoming ownership proof by itself.

## Minimum record and metadata

The trusted JSON record contains:

| Field | Purpose |
| --- | --- |
| `magic` | Reject a different record type in the trusted slot. |
| `schema_version` | Define the JSON parsing and write-ahead state-machine contract. |
| `abi_version` | Select the hard-coded expected map/program/link contract. |
| `state_id` | Random 128-bit identity binding this record to one bpffs state set. |
| `generation` | Distinguish the prior state set from the state created after recovery. |
| `phase` | `INTENT` before any bpffs creation, `READY` only after validation. |
| `pin_root` | Bind the record to one exact bpffs root; it is not ownership proof by itself. |
| `object_sha256` | Bind a compatible READY set to the exact spike BPF build used to create it. |
| `cgroup_path` / `cgroup_inode` | Bind the recorded link set to its original cgroup subject. |
| object IDs | Bind the READY record to the exact kernel maps, programs and links validated before readiness. |

`soglia_meta` has six `u64` slots: magic bytes, schema version, ABI version, the opaque 128-bit
`state_id` in two slots, and generation. It is compared byte-for-byte with the trusted record and is
never read by a BPF program or by Resolve. It is corroboration and binding, not a standalone trust
anchor.

No separate build-version field exists inside `soglia_meta`: the trusted record carries the object
SHA-256, while the loader validates the live kernel contracts. Duplicating that digest in the map
would not add an independent trust source.

## Kernel-observed ABI contract

The ABI version fixes the exact expected pin inventory. Every security-relevant map is checked via
`bpftool map show pinned` for type, key size, value size, maximum entries and flags. The loader also
checks the six direct cgroup attachments, program names/types, link type, attach type, program ID and
target cgroup inode from kernel-observed state. An extra file, missing file, unexpected directory,
ID mismatch, or contract mismatch fails closed.

Compatibility means only that the residue is recognizable and safe to sweep. No old map, program
or link is reused for authorization.

## Write-ahead and crash classification

Creation/recovery order is:

1. validate the trusted state directory and classify the old record/pin root;
2. for known-compatible residue, validate it, unpin its exact recorded objects, and verify their
   kernel IDs and pin root are absent;
3. generate a new `state_id` and increment generation;
4. atomically publish `INTENT` before creating the bpffs root;
5. create and pin the expected maps/programs/links;
6. write the matching `soglia_meta` binding;
7. validate the complete kernel-observed object contract;
8. atomically replace `INTENT` with `READY`, including exact object IDs;
9. publish `startup.ready` last.

Crash outcomes:

| Crash point | Next-start classification |
| --- | --- |
| Before `INTENT` | No record and no root is fresh. A root without a record is unknown. |
| During record publication | A temporary record is not ownership proof. With no root it is removable test residue; with a root startup fails unknown. |
| After `INTENT`, before bpffs | Trusted known-compatible intent with no objects; advance generation and recreate. |
| During pin creation | Trusted intent plus only expected, contract-matching objects; sweep exact observed subset. Any unexpected object fails closed and remains. |
| After pins/meta, before `READY` | Trusted intent and matching state binding; validate, sweep, recreate. |
| After `READY`, before runtime readiness | Trusted compatible READY residue; sweep/recreate. No admission marker exists. |
| After runtime readiness | Normal prior-generation residue; the same validation and sweep occurs. |

There is never a no-record interval between sweeping a compatible generation and publishing the new
intent: the old record remains until it is atomically replaced by the new intent.

## Classification and cleanup

- No record and no pin root: fresh; create clean state.
- Matching trusted record, meta and exact kernel contract: known compatible; sweep, verify absence,
  create a new state ID/generation, then become ready.
- Trusted record with unsupported schema/ABI/build/object contract: known incompatible; fail closed,
  do not migrate, delete, or publish readiness.
- Pin root without a valid matching trusted record, mismatched meta/state identity, or an unexpected
  object: unknown; fail closed and leave it untouched.

Broad deletion by `soglia*` prefix is prohibited. The recovery path removes only the exact expected
objects after the trusted record, metadata binding and kernel contracts establish ownership. A
foreign control object is removed only by the S13 test harness that created it and rechecks its ID.

Old tuple, cookie, policy, owner or generation state is never copied into the new maps. A successful
compatible recovery proves old map IDs disappeared, fresh IDs were allocated, authorization maps
are empty, the old tuple lookup is absent, and the new generation differs before readiness.
