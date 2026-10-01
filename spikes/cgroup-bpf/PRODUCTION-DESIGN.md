<!-- Copyright (c) 2022 Nitro Agility S.r.l. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Candidate A production `CgroupBpfBackend` design

## Status and decision

Status: `PHASE_1_RELEASE_QUALIFIED` on production baseline `17d8fc732bfdbdc99d7924193965c427e52a0b68`.

Candidate A, socket cookie to cgroup identity, was selected explicitly after the completed candidate review on 2026-09-27.
This document defines the normative production contract and its B1-B7 qualification gates.
The production implementation is feature-gated and `cgroup-bpf` is enabled by the default build.

The normative inputs are:

- the final S0-S14 evidence and reproducibility review in [REPORT.md](REPORT.md);
- the candidate-independent production requirements in [REPORT.md](REPORT.md#candidate-independent-production-requirements);
- the ownership and crash-recovery invariants in [S13-CONTRACT.md](S13-CONTRACT.md);
- the existing production `EnforcementBackend`, Supervisor, Sandbox, proxy and helper-loss contracts.

Where this design is stricter than the spike, the stricter rule is intentional.
In particular, the production `connect4` program must deny when the Candidate-A cookie insertion fails, and must not preserve the spike's diagnostic A/B/C/D multiplexing.

## Security claim and non-goals

The production attribution claim is this chain:

```text
trusted Sandbox creates a paused agent
  -> Enforcer independently proves host PID membership in the exact Execution cgroup
  -> six Soglia programs are effective on that cgroup
  -> connect4 copies kernel current-cgroup identity into cookie-owned state
  -> sockops publishes that identity under the proxy-accepted TCP tuple
  -> the privileged resolver validates tuple, cookie, cgroup and Execution generation
  -> the proxy obtains a revocable binding to exactly one live Execution
```

No agent-provided value participates in that chain.
Source IP, veth identity and network-namespace identity may be logged as cross-checks but never authorize a connection or repair missing BPF state.

cgroup-BPF provides early deny and trusted attribution.
nftables remains the final post-rewrite destination barrier, and the owned network namespace and veth remain separate confinement layers.
BPF does not perform routing, proxy steering, DNS policy, HTTP policy or TLS identity enforcement.
The Enforcer is not a traffic hop.

An absent, delayed, full, stale, ambiguous or unverifiable attribution state denies before the proxy reads application bytes, performs DNS, creates an outbound connection or authorizes through any fallback.

## Component boundaries

| Component                     | Production responsibility                                                                                         | Must not do                                                                                     |
| ----------------------------- | ----------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------- |
| Supervisor                    | Orders lifecycle, owns admission and revocation, and enters the one-way helper-loss transition                    | Interpret paths supplied by an agent or continue after a privileged-helper invariant fails      |
| Sandbox helper                | Owns delegated cgroup creation, OCI bundle, paused `runc create`, PID observation, start, kill and cgroup removal | Attach BPF, choose network policy or claim that runc configuration alone proves membership      |
| Enforcer / `CgroupBpfBackend` | Owns netns/veth/nft, BPF load/attach/maps/pins, exact ownership records, activation, freeze, Resolve and cleanup  | Start the agent, trust IP identity, remove unknown kernel state or weaken nft final enforcement |
| Kernel BPF programs           | Enforce socket-family/destination rules, capture cookie attribution and publish/clean tuple state                 | Route traffic, authorize an Execution without active policy or evict live identity state        |
| Egress proxy                  | Resolve before reading bytes, apply destination policy, perform DNS/outbound work and hold revocable bindings     | Read BPF pins directly, accept an IP fallback or proceed after Resolve timeout/mismatch         |
| Root-owned state and bpffs    | Bind one exact backend generation to exact kernel objects and support recovery                                    | Establish ownership from a name, prefix, program name or pin path alone                         |

`CgroupBpfBackend` is a composite network backend, not a BPF-only replacement for `NetnsNftBackend`.
It retains the proven namespace, veth and nft responsibilities and replaces IP-based proxy attribution with Candidate A.
Backend choice is a validated configuration value; omitted configuration selects `cgroup-bpf`.
When `cgroup-bpf` is selected, any capability, recovery or initialization failure fails startup; the runtime must never fall back silently to `NetnsNftBackend`.
`NetnsNftBackend` remains available only as the explicit `network.backend: netns-nft` compatibility choice.

The privileged Enforcer exposes two logically separate inherited-socketpair services:

1. a lifecycle service for prepare, activate, freeze and destroy;
2. a bounded attribution service for tuple Resolve.

The attribution service prevents the unprivileged proxy from receiving writable BPF map descriptors or opening bpffs paths.
Loss of either authenticated inherited channel is Enforcer loss and triggers the existing one-way fail-closed runtime transition.

## Attachment topology and program contract

One shared production object supplies six programs attached to the Soglia-owned `executions/` cgroup. Every Aya link uses `CgroupAttachMode::Single`: on the qualified link-based kernel API this passes zero `link_create.flags`, while `cgroup_bpf_link_attach` installs the link internally with `BPF_F_ALLOW_MULTI`. Passing Aya `AllowMultiple` is forbidden because the qualified kernel rejects that nonzero link-create flag with `EINVAL`. A unit test fixes this mode for all six hooks:

1. `cgroup/sock_create` admits only the IPv4 TCP socket shape needed by the architecture and denies other families/types;
2. `cgroup/connect4` admits only the configured proxy IPv4 address and port for an `ACTIVE` Execution;
3. `cgroup/connect6` denies IPv6 connections;
4. `cgroup/sendmsg4` denies IPv4 datagram egress;
5. `cgroup/sendmsg6` denies IPv6 datagram egress;
6. `sockops` publishes and removes Candidate-A tuple state.

Absent policy is `FROZEN` by construction.
There is no permissive default, no IP fallback and no production equivalent of the spike-only relax variants.

The BPF object carries Apache-2.0 licensing and uses only the helper/program/map set qualified by the final spike.
GPL-only task-BTF or cgroup-pointer paths are not design dependencies.

The configured proxy address is stored in network byte order and the configured proxy port in host byte order.
The production ABI must define the accepted tuple as agent source IPv4 and proxy destination IPv4 in network byte order, with both ports represented as host-order `u16` values plus explicit padding.
`sockops.local_port` is range-checked and converted to `u16`; `sockops.remote_port` is converted with the full-width `bpf_ntohl` path proven after the S1 diagnostic and then range-checked.
The proxy builds the same key from accepted peer and local socket addresses.

## Identity and generation model

The kernel cgroup ID is necessary but not sufficient because an ID may eventually be reused.
Every Execution therefore receives a cryptographically random 128-bit `execution_nonce` generated by trusted userspace.

The active identity is the triple:

```text
(cgroup_id, execution_nonce, backend_generation)
```

The triple is one indivisible `BindingKey` in the production ABI.
No component may authorize on one or two fields, compare a field through fallback logic, or combine fields observed from different records or generations.
`backend_generation` belongs to the S13 host-wide state record.
`execution_nonce` belongs to one Execution record and is copied into policy, cookie and tuple values.
Resolve succeeds only when all three components match the current root-owned records and the current live binding.

Activation has one authorization linearization point: the whole frozen policy value is replaced by one whole `ACTIVE` value only after the durable Enforcer record and live Supervisor `BindingKey` exist while the agent remains paused.
Freeze linearizes in the opposite direction by revoking the live binding before replacing the whole policy value with `FROZEN`.
There is no claim of a transaction spanning multiple kernel and userspace maps; safety comes from this ordering, the paused process, whole-value updates and fail-closed validation of every copy.

The full `ExecutionId` remains in trusted userspace and is not an agent-visible or kernel-derived identity.
The Enforcer's durable record owns the exact mapping from the identity triple to `ExecutionId` for privileged validation and cleanup.
The Supervisor maintains a separate live attribution table keyed by the same triple and owns revocation of the resulting proxy binding.
Resolve returns the validated identity triple, not an IP-derived identity, and the proxy obtains an `ExecutionId` only when the live Supervisor table agrees exactly.

## Maps, ownership and sizing

All production maps are created once per backend generation, pinned below that generation's exact pin root and listed in the durable READY manifest.
They are never shared with another Soglia instance or adopted from an untrusted path.

| Map name          | Type                 | Key                                      | Value                                                                 | Capacity                         |
| ----------------- | -------------------- | ---------------------------------------- | --------------------------------------------------------------------- | -------------------------------- |
| `soglia_policy`   | `HASH`               | `u64 cgroup_id`                          | state, execution nonce, backend generation                            | `P`                              |
| `soglia_cookie_a` | `HASH`               | `u64 socket_cookie`                      | cgroup ID, execution nonce, backend generation                        | `C`                              |
| `soglia_tuples`   | `HASH`               | canonical accepted IPv4 TCP tuple        | cookie, cgroup ID, execution nonce, generation and publication time   | `C`                              |
| `soglia_counters` | `ARRAY`              | fixed counter index                      | monotonic atomic `u64`                                                | fixed ABI count                  |
| `soglia_denies`   | `HASH`               | cgroup ID and execution nonce            | atomic deny counters by reason                                        | `P`                              |
| `soglia_events`   | `RINGBUF`            | none                                     | bounded diagnostic event                                              | configured bytes, default 64 KiB |
| `soglia_meta`     | `ARRAY`              | zero                                     | magic, schema, ABI, state ID, generation and object/config hashes     | one                              |

`P` is checked arithmetic over `runtime.max_concurrency + runtime.cleanup_failure_threshold`.
This includes live and quarantined Executions whose identities cannot yet be released.

`C` is a new validated configuration value, `cgroup_bpf.max_tracked_sockets`, with an initial default of 4096 to preserve the tested spike envelope.
Both cookie and tuple maps use exactly `C`, no eviction and no LRU behavior.
The requested value, estimated memory, successfully created kernel capacities and high-water marks are exposed at startup.
The backend never raises memlock, file-descriptor or other host limits to make a configuration pass.
If the requested maps cannot be created under the real limits, readiness fails.

A global `C` means one hostile Execution can consume attribution capacity and deny new proxy connections from other Executions.
That is a bounded availability risk, not an authorization bypass, and remains a residual risk for the first implementation.
Per-Execution quotas must not be claimed until their counter lifecycle is independently designed and qualified.

Program and link inventory is constant: six programs and six links per backend generation, not per Execution.
The design therefore avoids Candidate C's measured `6N` program/link multiplication.
The READY record contains the exact count and identity of every map, program, link and pin.
B7 must qualify this exact production topology with the production object: one shared set of six programs and six links attached at the `executions/` subtree for every tested Execution count, with no per-Execution program or link instances.
S9 and S10 constrain foreign-ancestor behavior, but they are not evidence that this production shared-attachment topology works or scales.

## Candidate-A cookie lifecycle

At `connect4`, the program obtains the kernel current cgroup ID and looks up `soglia_policy`.
It denies unless the entry exists, is `ACTIVE`, has the current backend generation and targets exactly the configured proxy endpoint.

For an admitted socket, it obtains the socket cookie and inserts a complete identity value into `soglia_cookie_a` with `BPF_NOEXIST`.
Insertion failure, including capacity exhaustion or a stale cookie collision, increments a non-droppable counter, emits a best-effort event and returns deny from `connect4`.
The program never overwrites an existing cookie attribution and never admits a socket whose Candidate-A state was not published.

At `BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB`, `sockops` looks up the cookie.
It publishes the canonical tuple with `BPF_NOEXIST`; tuple collision or exhaustion is recorded and leaves the connection unattributed.
Because the TCP connection to the local proxy may already exist at this point, publication failure is contained by bounded Resolve: the proxy closes it without reading application bytes or creating any outbound effect.

At TCP close, `sockops` deletes the tuple only when its stored cookie and full identity match the closing socket, then deletes that socket's cookie entry.
A late close from an older socket cannot delete a later tuple with the same four-tuple.

Execution destroy performs a second, userspace-owned sweep of both maps for the exact execution nonce after the cgroup is empty.
This covers missing close callbacks and crash residue.
Failure to enumerate, delete or prove absence quarantines the Execution and stops reuse of its tag, slot, cgroup identity and nonce.

## Tuple Resolve contract

The proxy accepts a TCP connection and derives the canonical tuple from `peer_addr` and `local_addr` before constructing an HTTP connection or reading a byte.
It sends only that tuple over the inherited attribution channel.

Resolve retries a non-blocking one-shot lookup only inside a bounded publication window, initially no more than the two seconds qualified by S1b.
The bound must be configurable only within a safe implementation-defined maximum and must be included in the startup fingerprint.
The publication deadline starts when the proxy begins Resolve and includes bounded-queue and IPC-gate waiting.
Each accepted request carries a process-monotonic `request_id` that the Enforcer must echo; a missing or different ID poisons the channel and is `Unavailable`.
The one-shot exchange watchdog is a fixed one second, independent of the publication time remaining, because an exchange performs only an Enforcer `try_lock` and at most one BPF map lookup; its socket read/write timeouts use the same fixed bound. Retries are spaced by two milliseconds, preserving the qualified publication cadence without retaining either the IPC gate or backend lock between attempts.
The publication deadline decides only whether another attempt may begin. If an exchange started before the deadline completes after it, `Pending` becomes a connection-local `Timeout`, while `Complete` is consumed as returned because the Enforcer may already have atomically consumed the tuple.
The task doing the blocking write/read owns the IPC gate until the correlated response is consumed, even if its async caller is cancelled.
An exchange watchdog, framing error or correlation failure permanently poisons and shuts down that channel; recovery is only by the S8 restart and sweep path.

A successful Resolve atomically consumes the tuple entry and validates all of the following:

1. the destination is the configured proxy address and port;
2. the tuple value contains a nonzero cookie and current backend generation;
3. the cookie map still contains the same cgroup ID, execution nonce and generation;
4. the policy map contains the same identity in `ACTIVE` state;
5. the root-owned live Execution record maps that exact identity to one `ExecutionId`;
6. the Supervisor binding for that Execution is live and not revoked.

Every identity comparison is a whole-`BindingKey` equality check.
A reused cgroup ID with a different nonce, a reused nonce in a different backend generation, a stale cookie or tuple from an older generation, or any mixed/torn triple is a mismatch and cannot yield an `ExecutionId`.
The comparison fails before a diagnostic `ResolveMismatch` enum identifies cgroup ID, nonce, generation, cookie, tuple, ownership-record or policy disagreement; no decision is ever made from that diagnostic field or from error text.
The trusted Resolve channel returns `Resolved`, `NotFound`, `IdentityMismatch`, `Revoked`, `Timeout` or `IntegrityFailure`.
The Supervisor adds `QueueFull` and `Unavailable` for its bounded queue and authenticated channel.
Only `Resolved` yields an identity; every other result closes the accepted socket without parsing application data, DNS, outbound connect or IP-derived fallback.

`Timeout` means tuple publication did not finish within the configured wait and denies only that connection.
Trusted timeout telemetry distinguishes at least one observed `TupleAbsent` from `BackendBusy` throughout the whole window; this distinction is never sent to the agent.
A broken channel or an active one-shot exchange that exceeds its watchdog is `Unavailable`, not `Timeout`, and enters the S8 one-way fail-closed transition.
`IdentityMismatch` denies and emits a trusted diagnostic event but does not change runtime health because old generation state may still be awaiting exact cleanup.
`Revoked` means live-binding revocation or policy freeze won the Resolve/freeze race and denies without being confused with absence or helper loss.
`IntegrityFailure` is reserved for owned state that cannot be decoded or verified, including malformed map values, a zero socket cookie in a published tuple, incompatible runtime ABI, multiple live ownership records correlating with one tuple or another unverifiable ownership record.
It denies, stops admission, cancels effect-producing work, marks the runtime not ready and requires process restart with the normal sweep-before-READY sequence.
Mismatch details remain in trusted logs and qualification evidence and are never returned to the agent.

After successful Resolve, the per-connection proxy binding carries `ExecutionId` plus a revocation receiver.
Freeze or runtime cancellation closes HTTP work and open tunnels through that receiver even though the tuple entry has already been consumed.
The cookie entry remains until the client socket closes or exact Execution cleanup removes it.
A tuple published after a Resolve timeout remains fail-closed: the sockops close callback deletes it only when its cookie matches, and exact Execution destroy sweeps every tuple and cookie carrying that BindingKey.
If a stale entry is encountered first by a later connection, atomic lookup-and-delete consumes it and the complete cookie/policy/ownership `BindingKey` validation denies it; TCP cannot concurrently establish the identical four-tuple while the old socket remains live.
A stale tuple carrying an earlier Execution identity must never resolve a later Execution even when the four-tuple and cgroup ID are reused.

## Startup capability probe

`probe_capabilities` is a mandatory gate and must report a typed reason rather than infer support from a kernel version.
It verifies:

- effective root privilege in the Enforcer helper;
- a unified cgroup v2 hierarchy and the actual systemd delegation prepared by the Sandbox helper;
- the exact delegated-root, `executions/` path, inode, ownership, controller and no-internal-process invariants;
- mounted bpffs, root-owned non-symlink state/pin ancestors and BTF required by the production build;
- BPF syscall access, link creation and the exact six program types, helpers, callbacks and map types used by the production object;
- cgroup v2 `name_to_handle_at`/`open_by_handle_at` support and privilege, a non-reusable mount identity obtained from the same live target fd with `statx(STATX_MNT_ID_UNIQUE)`, plus direct `BPF_LINK_DETACH` followed by `BPF_OBJ_GET_INFO_BY_FD` on an exact disposable pinned link;
- offline-cgroup admission semantics on exact disposable FDs opened while the cgroup is live: after removal, writing a PID through the already-open `cgroup.procs` FD must fail with `ENODEV`, and `clone3(CLONE_INTO_CGROUP)` through the already-open directory FD must fail with `ENOENT`; either operation succeeding or returning another errno is `Unsupported`;
- multi-compatible child attachment and effective visibility from a disposable empty probe cgroup, with inherited state read using `bpftool cgroup show <probe> effective` rather than the subtree-oriented `cgroup tree` command;
- `BPF_NOEXIST`, atomic tuple lookup-and-delete and required map enumeration behavior;
- nftables and network-namespace facilities retained as the final barrier;
- requested map capacities, memlock/JIT allocation and process FD headroom under the actual service limits;
- absence of unexpected direct programs/links at the Soglia attachment target and a recorded fingerprint of non-owned ancestor BPF state;
- exact production object hash, Apache-2.0 license, schema and ABI compatibility.

The executable feature probe uses only an exact registered disposable cgroup and exact registered kernel objects.
It must clean them and prove their absence before startup can continue.
An exclusive program on an ancestor must surface as the typed `IncompatibleBpfTopology` refusal carrying the failed hook and kernel errno; production logic must not classify it by matching human-readable error text.
Probe failure means no readiness; unsupported kernel capability stays distinguishable from incompatible/unknown owned state and from an infrastructure failure.

## Host-wide initialize and S13 recovery

The Sandbox helper initializes first, kills recorded Execution processes and proves all Execution cgroups empty before the Enforcer is allowed to replace any prior BPF generation.
This ordering is mandatory because old pinned policy may still be active after a previous Enforcer loss.

The production ownership root is a root-owned, non-symlink directory below `/run/soglia` with mode `0700`.
The state file is a root-owned regular file with mode `0600`, published by write, file sync, atomic rename and directory sync.
The generation pin root is below a root-owned Soglia bpffs directory and is never discovered by prefix deletion.

The state record extends the S13 contract with:

- magic, schema version, BPF ABI version, random state ID and monotonic nonzero generation;
- production object SHA-256, build identity and configuration fingerprint;
- delegated-root and attachment-target paths plus inodes, and the exact attachment-target cgroup v2 file handle and mount identity;
- exact map definitions, IDs and pins;
- exact program IDs, names, types and tags;
- exact link IDs, attach types, target cgroup IDs and pins;
- exact proxy endpoint, `P`, `C`, ring size and Resolve bound;
- every live or quarantined Execution record and its lifecycle state.

Startup classifies prior state as `Fresh`, `KnownCompatible`, `TargetReleased`, `Incompatible` or `Unknown`.
Fresh state may proceed.
Known-compatible state is revalidated against the trusted record, kernel identities, metadata and exact inventory, swept only by recorded identity, and proven absent before replacement.
Incompatible or unknown state fails closed without changing its kernel objects, map contents, pins or record.
A pin root without a trusted record, an unexpected object, a mismatched tag/hash/inode or a stale generation is unknown.

### `TargetReleased` classification

`TargetReleased` is the production classification for the qualified systemd behavior in which `Restart=on-failure` releases the old delegated `executions/` cgroup and creates the same path with a different cgroup ID. It preserves `KillMode=mixed`: Executions remain descendants of the runtime service cgroup and systemd's kill barrier runs before recovery. The offline-target form below is implemented but is not production-qualified until B1-B6 are repeated on the schema-3 backend.

The simpler kernel behavior was observed in non-authoritative diagnostic run `b6-kernel-target-20260929T192357Z-r7` on Linux 6.8.0-142-generic aarch64 with systemd 255: a released empty target made every pinned link report cgroup ID zero. The real Sandbox-loss topology can retain the recorded nonzero link cgroup ID after the pathname has been removed. Run `b6-target-offline-final-20260929T234729Z-67073` reproduced that state after a 512 MiB file workload was run inside an Execution: the durable target ID was absent from the live hierarchy, `open_by_handle_at` on the pre-loss handle returned `ESTALE`, all six links reported only the recorded old ID throughout observation, and direct `BPF_LINK_DETACH` on each exact recorded pin succeeded and changed only its reported cgroup ID to zero while preserving link ID, program ID and attach type. Its 61 recorded checksums passed. A minimal comparison run let the links converge to zero without explicit detach. This supports an offline-target predicate rather than an unbounded wait for link convergence; it is evidence for that environment, not a portability claim.

The durable attachment-target record must therefore include the exact cgroup v2 file handle returned by `name_to_handle_at` while the target is live, including handle type, handle length and handle bytes, plus the non-reusable mount identity returned by `statx(STATX_MNT_ID_UNIQUE)` on the same live target fd, in addition to the path and cgroup ID. The handle call deliberately uses no mount-ID flag: the qualified Ubuntu 6.8 kernel returns `EINVAL` for `AT_HANDLE_MNT_ID_UNIQUE` while supporting `STATX_MNT_ID_UNIQUE`. A reusable mount ID is never accepted. Adding these fields requires an explicit durable-state schema bump; older READY records are `Incompatible`, never silently upgraded. The startup capability probe must prove that the privileged recovery process can obtain the handle and unique mount identity and can call `open_by_handle_at` on it. A missing, truncated or unparsable handle, a missing unique mount identity, a different cgroup2 mount, or an unsupported handle operation is `Unsupported` before first durable state and `Unknown` for existing state; pathname absence alone is never enough.

Classification order is strict:

1. validate the durable record, trust root, schema/ABI, state/generation, object/configuration hashes, pin root and complete recorded inventory without modifying anything;
2. if the current attachment-target ID equals the recorded ID, use the existing `KnownCompatible` path and require every normal live-attachment predicate;
3. if the IDs differ, consider `TargetReleased` only after the Sandbox kill-all barrier has proven every recorded Execution process dead and every old Execution pathname absent;
4. open the recorded attachment-target handle on the cgroup2 mount with `open_by_handle_at` and require exactly `ESTALE`; either an openable handle or a different error is `Unknown`;
5. open every recorded link by its exact pin and read link information directly with `BPF_OBJ_GET_INFO_BY_FD`; require its link ID, program ID and attach type to match the record, and require its cgroup ID to be either the exact recorded old target ID or zero, never any other live or unknown ID; record every value and perform no mutation while classifying; production must never use `bpftool`, its exit status or text parsing as an ownership source;
6. require all recorded maps and programs to match exactly, every expected pin to exist, and no unexpected owned or foreign object below the generation root;
7. require the current `executions/` target to have an ID different from the recorded target, be empty, belong below the current systemd unit's delegated cgroup, and satisfy the normal ownership, mode and no-internal-process invariants.

Only this complete conjunction is `TargetReleased`. Recovery then calls `BPF_LINK_DETACH` on the descriptor opened from each exact recorded link pin. Each call must succeed, and an immediate `BPF_OBJ_GET_INFO_BY_FD` must report cgroup ID zero while preserving the recorded link ID, program ID and attach type. Only after all six detach verifications pass may recovery remove the exact recorded links, programs, maps and pins, prove their IDs and pins absent, create generation `N+1` against the new target, prove the new policy/cookie/tuple maps empty and publish READY last. It never adopts the old generation or copies an authorization entry. A detach error or post-detach identity mismatch stops recovery as `Unknown`; cleanup is not broadened to compensate.

An openable old handle, an error other than `ESTALE`, a link pointing to any ID other than its recorded old ID or zero, a link/program/map identity mismatch, an unexpected object, a missing expected pin, a non-empty replacement target or a target outside the current unit is `Unknown`. Before the first explicit detach, the backend must leave all observed kernel objects, map contents, pins and durable bytes unchanged and refuse readiness. Pathname absence, a name match, a failed query or `bpftool` output is not equivalent to the kernel proofs above.

The B6 harness also scans the complete live cgroup2 hierarchy and records that no live path reports the old ID. This is corroborating qualification evidence, not a production classification predicate. `ESTALE` from `open_by_handle_at` on the exact durable handle is the kernel's direct answer about that cgroup; a hierarchy-wide scan adds host-size-dependent cost and can already be stale when it finishes.

The safety argument also depends on the production FD boundary: no socket created by an Execution may be transferred to or retained by a process outside that Execution. B5 authoritative run `b5-20260929T140856Z-8731` records an agent start table containing only stdin `/dev/null` and stdout/stderr pipes, and `driver/runtime-fd-boundary.json` proves the runtime uses neither preserved socket FDs nor `SCM_RIGHTS`. The Sandbox kill-all barrier therefore closes every Execution-owned socket before `TargetReleased` classification. A future FD-passing feature, pidfd-based FD acquisition or any other cross-boundary socket transfer invalidates this assumption and requires re-design and re-qualification; privileged host compromise remains outside this backend's threat boundary.

The meaning of `ESTALE` is qualified independently rather than assumed from pathname removal. B1/B6 must open a test cgroup directory and its `cgroup.procs` while live, remove the cgroup, and prove that a PID write through the retained `cgroup.procs` FD fails with `ENODEV` and `clone3(CLONE_INTO_CGROUP)` through the retained directory FD fails with `ENOENT`, with no child created or process moved. These are the exact results observed on the supported Linux 6.8 environment. A successful admission or any other errno invalidates the offline-target capability and prevents `TargetReleased` recovery.

For a new generation, initialize runs and cleans the complete disposable attach probe before publishing durable `INTENT`. It then publishes `INTENT`, creates maps/programs/links/pins, initializes `soglia_meta`, validates the live kernel contract, publishes the durable READY manifest and exposes backend readiness last.
If an operation returns an ordinary synchronous error after `INTENT`, the same call removes only the exact recorded links/maps/pins, proves owned attachments and the generation root absent, and removes the record last. A process crash at any point does not execute this rollback and deliberately preserves `INTENT` for S13 recovery.
Policy and attribution maps start empty, so the new generation denies every Execution until its staged activation completes.
No stale authorization entry is imported.

On orderly Enforcer channel close, every known policy is changed to `FROZEN` before exit when the kernel objects remain accessible.
Global links and maps stay pinned until exact recovery or an explicit administrative removal after all Execution cgroups are proven empty.
Unexpected Enforcer death therefore leaves the early-deny object alive as demonstrated by S7, while S8 runtime cancellation and Sandbox kill remove effect-producing processes.

## Per-Execution lifecycle and ordering

The current production sequence starts the Enforcer before `runc` creates the Execution cgroup.
Candidate A requires a staged protocol so live membership can be proved before agent code runs.
Implementation therefore requires an explicit Sandbox reserve/create/start split and an Enforcer activate operation; this document does not make that code change.

The production contract must expose these conceptual operations even if their final Rust types are refined during implementation review:

- Sandbox `reserve(id, agent)` creates and records the empty cgroup;
- Enforcer `prepare_execution(id, slot, agent)` creates network state and a frozen identity record;
- Sandbox `create_paused(id)` performs `runc create` and returns the trusted host PID observation;
- Enforcer `activate_execution(id, pid)` independently proves placement and returns the identity triple;
- Sandbox `start(id)` releases the paused process only after activation;
- Enforcer `freeze(tag)` and `destroy_execution(tag)` retain the existing monotonic lifecycle meaning;
- Enforcer `resolve(tuple)` is available only over the separate bounded attribution channel.

The `EnforcementBackend` and helper protocols will therefore need an explicit activation phase when implementation is authorized.
This is a deliberate contract change, not behavior to hide inside the current one-shot `prepare`/`start` calls.

The required state machine is:

```text
ALLOCATED
  -> CGROUP_RESERVED
  -> NETWORK_PREPARED_FROZEN
  -> CONTAINER_CREATED_PAUSED
  -> MEMBERSHIP_VERIFIED
  -> ACTIVE
  -> FROZEN
  -> PROCESS_EMPTY
  -> DESTROYED
```

### Prepare

1. The Supervisor allocates an `ExecutionId`, tag, slot and random execution nonce.
2. The Sandbox durably records intent, creates the exact empty Execution cgroup, applies resource limits and returns its derived path and inode as an observation, not as sole proof.
3. `CgroupBpfBackend::prepare_execution` independently derives the same cgroup from trusted configuration and tag, checks the inode and emptiness, records Enforcer intent, creates netns/veth/nft state and inserts a `FROZEN` policy with `BPF_NOEXIST`.
4. The Sandbox performs `runc create` but not `runc start`, leaving the init process paused, and returns the trusted host PID plus its own cgroup observation.
5. The Enforcer's activation operation reads `/proc/<pid>/cgroup`, the exact target `cgroup.procs`, target inode and relevant netns identity; it also revalidates six direct/effective Soglia links and the frozen policy.
6. The Enforcer refuses unless the actual PID is in exactly the intended Execution cgroup below the attachment target and every identity matches the durable record.
7. The trusted userspace identity binding is installed before policy activation, and activation changes only that exact policy value from `FROZEN` to `ACTIVE`.
8. The Sandbox performs `runc start` only after activation succeeds.
9. The Supervisor releases invocation traffic only after start succeeds; a failure at any earlier point enters freeze/kill/destroy and never reports the Execution ready.

Requests continue to carry identifiers and trusted observations, never caller-selected paths or commands.
Both helpers derive resource paths from the validated shared configuration.

### Freeze

Freeze is idempotent and monotonic.
The Supervisor first revokes the proxy binding so no new request is authorized and every open HTTP exchange/tunnel is cancelled.
The Enforcer then atomically changes the exact policy from `ACTIVE` to `FROZEN`; absence, mismatch or a generation disagreement is a failure, not success.
From that transition, all new socket attempts deny.
Existing proxy sockets are contained by binding revocation and runtime cancellation, and the Sandbox subsequently freezes and kills the complete cgroup.

If the target cgroup is already absent, the backend may treat traffic as denied only after it validates the matching record and proves that no policy, cookie or tuple state can still authorize the Execution.
It must not convert an unknown or mismatched record into an idempotent success.

### Destroy

Destroy runs only after the Sandbox has killed the cgroup and proven it empty.
The Sandbox may remove OCI state, bundle and the empty cgroup before network destroy, while the Enforcer retains the recorded cgroup ID, inode and nonce for exact cleanup.

The Enforcer revalidates the record, removes exact cookie and tuple entries for the execution nonce, removes the frozen policy and deny counters, removes its nft/veth/netns resources and proves each resource absent.
Only then does it remove the per-Execution Enforcer record.
The Supervisor releases the revocation binding, slot, tag and concurrency permit last.

Any unverifiable removal quarantines the identity and slot, preserves the record, increments the cleanup-failure count and may stop all admission under the existing threshold.
No cleanup step uses a wildcard, name prefix or untrusted pin path.

## Fail-closed behavior

| Failure or ambiguity                              | Required behavior                                                                                              |
| ------------------------------------------------- | -------------------------------------------------------------------------------------------------------------- |
| Policy absent, frozen, mismatched or map full     | Do not start or admit the Execution; socket hooks deny                                                         |
| Cookie insert fails or cookie already exists      | `connect4` denies; counter is non-droppable                                                                    |
| Tuple insert fails or tuple already exists        | Proxy Resolve times out/misses and closes before reading or causing effects                                    |
| Tuple/cookie/policy/record values disagree        | Resolve denies, records the mismatch and initiates health failure if owned-state integrity may be compromised  |
| Resolve channel fails or exceeds its bound        | Close the accepted connection and enter Enforcer-loss handling for a channel failure                           |
| Event ring is full                                | Enforcement is unchanged; increment the non-droppable dropped-event counter                                    |
| Required link/map/program disappears or changes   | Stop admission, cancel proxy work, kill Executions and refuse readiness until exact recovery                   |
| nft final barrier cannot be installed or verified | No readiness and no Execution activation                                                                       |
| Cleanup cannot prove absence                      | Quarantine resources and stop admission at the configured threshold                                            |
| Prior state is incompatible or unknown            | Leave it untouched, publish no readiness and require operator inspection                                       |

The direct BPF decision does not depend on event delivery, userspace health or map enumeration.
Diagnostic loss may reduce observability but cannot create an allow path.

## Enforcer-loss interaction

The existing S8 production fix remains normative.
The parent watches the Enforcer child independently of RPC traffic.
An unexpected exit or lifecycle/Resolve channel failure linearizes a one-way transition that stops admission, cancels ingress and egress work, closes active proxy connections and tunnels, closes the Sandbox channel and waits for its kill-all barrier.

Pinned BPF links/maps and nft state remain kernel-resident.
If the Enforcer died before freezing policy, active policy still admits only exact proxy connections, while the proxy is cancelled and the Sandbox kills all agents.
It does not create a direct-outbound path.

Restart readiness requires Sandbox kill/sweep first, then S13 classification and exact Enforcer recovery, empty attribution maps, new generation validation, live resolver service and final helper liveness checks. If systemd released the old attachment target, readiness additionally requires the complete proposed `TargetReleased` proof; the replacement target is never accepted merely because its pathname matches.
No ingress or egress listener is announced ready before those gates complete.

## Foreign-BPF coexistence assumptions

Soglia owns the six direct links at its exact `executions/` attachment target.
Any unrecorded direct program or link there is unknown state and startup refuses without detaching it.

Non-owned programs may exist at strict ancestors.
The Enforcer records their program/link identity and stable name/type/tag fingerprint before attach and at health checks.
The supported assumption is limited to the ancestor ALLOW and destination-rewrite composition exercised by S9 and S10.
No execution-order claim is inferred from `bpftool` listing order.

The child Soglia decision must still deny disallowed traffic after an ancestor ALLOW.
An ancestor rewrite may change what the child observes, so nftables validates the final post-rewrite destination and remains the security boundary against rewrite exposure.
Unknown direct-target coexistence, changed recorded ancestor program tags, owned-inventory drift or other unclassified ancestor changes fail readiness or runtime health; there is no broad name allow-list.

Privileged host software can always replace kernel policy and remains outside the agent threat model.

## Resource limits and availability

Startup records and checks:

- policy and tracked-socket capacities;
- map memory requested and kernel object information returned;
- program, link, map and pin counts;
- memlock and nofile soft/hard limits without modifying them;
- Enforcer and parent FD counts plus reserved headroom;
- expected maximum concurrent Executions and quarantined identities;
- ring-buffer bytes and Resolve queue bound;
- object load/attach and recovery latency.

The attribution service uses a bounded request queue and bounded parallelism.
Queue saturation is a Resolve denial, never an unbounded allocation or fallback.

The first implementation's availability envelope is the exact configuration passed by B7.
It must not claim support above the largest qualified `max_concurrency`, `max_tracked_sockets`, Resolve rate, FD budget or kernel-memory budget.
S14's Candidate-C `EMFILE` boundary is not directly inherited by Candidate A, but it remains a requirement to measure actual FDs rather than assume loader cost.

The declared B7 support matrix is:

| Profile | `max_concurrency` | `max_tracked_sockets` | Execution-count checkpoints | Simultaneous live sockets proved | Connection churn | Resolve workload |
| ------- | ----------------- | --------------------- | --------------------------- | ------------------------------- | ---------------- | ---------------- |
| M0      | 1                 | 64                    | 0, 1                        | 48                              | 64               | 1/s for 30 s     |
| M1      | 4                 | 512                   | 0, 1, 2, 4                  | 384                             | 1,024            | 50/s for 30 s    |
| M2      | 4                 | 4,096                 | 0, 1, 2, 4                  | 512                             | 8,192            | 100/s for 30 s, then 250/s for 30 s |
| M3      | 32                | 4,096                 | 0, 1, 8, 16, 32             | 32, one per live Execution     | 8,192 | 250/s for 30 s; 256 simultaneous requests are characterized outside the supported envelope |

This matrix declares maps configured for as many as 4,096 tracked sockets, but qualifies only 512 simultaneously live sockets; it makes no claim that 4,096 sockets were held live at once.
The 512-live-socket boundary is imposed by the production service environment measured by qualification: `RLIMIT_NOFILE` has a soft limit of 1,024 because the production systemd unit does not set `LimitNOFILE` and therefore inherits systemd's default.
Raising that limit is a separate product and production-unit decision and requires a new resource qualification; B7 does not tune it to force PASS.

The supported simultaneous-new-connection envelope is bounded independently by the
Candidate-A Resolve queue, whose depth is `max_concurrency`.  M3 therefore proves 32
simultaneous new admissions, one from each of 32 live Executions, without a queue
refusal.  The separate 256-request burst deliberately exceeds that envelope and is a
fail-closed refusal characterization, not supported capacity: successes and
`QueueFull` refusals are recorded without a throughput threshold, every refusal must
be exactly `QueueFull`, rejected connections must cause no DNS or outbound effect, and
a control connection immediately after the burst must resolve successfully.

## Observability and health

The production backend exposes bounded, non-secret metrics and structured events for:

- startup probe result, recovery classification, state ID/generation and readiness phase;
- exact owned program/link/map counts and inventory drift;
- active/frozen/quarantined policy entries;
- cookie and tuple occupancy, high-water marks and capacity;
- hook entry, deny reason, cookie-insert failure, tuple-insert failure, publication and close cleanup;
- Resolve hit, delayed hit, miss, timeout, identity mismatch, stale generation, queue refusal and latency;
- ring events dropped;
- per-Execution freeze/destroy sweeps and cleanup failures;
- Enforcer loss, cancellation barrier and restart recovery;
- non-owned ancestor BPF fingerprint and classified external churn.

High-cardinality cookies and raw `ExecutionId` values are not metric labels.
Structured diagnostic logs may include a bounded correlation token, but must not expose policy secrets or agent data.

The production BPF ABI reserves fixed `soglia_counters` indices for every hook entry, enforcement failure, publication/close cleanup and deny reason.
ABI 2 expands this array from 11 to 26 entries; an ABI-1 durable generation is incompatible and is never migrated implicitly.
The Enforcer drains the bounded `soglia_events` ring during each health interval, validates only its fixed reason/width ABI and aggregates it without logging the embedded cookie or `BindingKey`.
Each drain is capped by the configured ring capacity divided by the fixed event width; events beyond that per-interval budget remain for the next health interval.
The same health snapshot reads the non-droppable counters and reports exact owned inventory, policy-state cardinality, occupancy/high-water/capacity, ring consumption/drop totals and a digest of the ancestor fingerprint.
The Supervisor records every typed Resolve outcome, delayed success and stale-generation mismatch into fixed counters and fixed latency buckets, emitting at most one aggregate snapshot per health interval together with the real `interval_ms` covered by that snapshot.
Failure to read the counter map or a malformed ring event indicates an observability-map integrity failure: the health check fails and the runtime enters the same fail-closed transition as other owned-state integrity failures.

The Enforcer periodically revalidates exact link attachment, map IDs, metadata, target inode and ownership record.
Integrity drift triggers the same one-way fail-closed transition as helper loss.
Capacity thresholds warn before full, but a warning never changes enforcement.

## Evidence-to-design traceability

- S0 requires real delegation proof, exact six-hook attach/effective verification and explicit coexistence classification.
- S1 requires live PID membership, canonical port encoding and the complete Candidate-A Resolve chain.
- S1b requires bounded delayed publication and no effects while unresolved.
- S2 requires concurrent uniqueness and zero cross-attribution.
- S3 requires cookie/tuple close cleanup and generation-safe reuse.
- S4 requires BPF direct IPv4 deny independently of the nft barrier.
- S5 requires each hook's responsibility and fail-closed omission behavior.
- S6 fixes the BPF/nft/proxy/lifecycle enforcement boundaries used by this design.
- S7 requires pinned enforcement to survive loader loss.
- S8 requires autonomous helper-loss cancellation and restart-before-readiness ordering.
- S9 and S10 bound the supported foreign-ancestor composition and preserve nft post-rewrite enforcement, but do not qualify the production shared attach topology.
- S11 requires complete lifecycle cleanup and independent absence proof.
- S12 requires explicit bounded maps, observable update failure and isolated Candidate-A full-map qualification before production enablement.
- S13 supplies exact ownership, compatibility, crash recovery and READY-last rules.
- S14 requires measured resource accounting under real limits even though its per-Execution Candidate-C formula is not used.

## Qualification matrix B1-B7

All B tests exercise the production object and production backend path.
Spike-only permissive programs may be used only as external causal controls and never replace or weaken production code.
Each gate records raw commands, environment/source fingerprints, owned-resource provenance, observations, verdict and independent cleanup.
`FAIL`, `UNPROVEN`, `UNSUPPORTED`, infrastructure failure or cleanup failure stops qualification and cannot count as success.

| Gate | Qualification area                           | Required result                                                                                        |
| ---- | -------------------------------------------- | ------------------------------------------------------------------------------------------------------ |
| B1   | Capability, delegation and fresh startup     | Exact production probe and READY-last initialization pass; every unsupported/incompatible case refuses |
| B2   | Placement and Candidate-A trusted chain      | Paused PID to exact cgroup to cookie to tuple to correct Execution is proven without fallback          |
| B3   | Concurrency, lifecycle and identity reuse    | No cross-attribution or stale authorization across load, FIN/RST/kill, teardown and fresh generations  |
| B4   | Fail-closed capacity and publication         | Isolated policy/cookie/tuple/Resolve failures deny before application, DNS or outbound effects         |
| B5   | Enforcement layers and foreign composition   | BPF early deny, nft final barrier, namespace confinement and supported ancestor coexistence are causal |
| B6   | Loss, crash recovery and readiness           | Loader/Enforcer/Supervisor loss and every ownership crash boundary recover or refuse exactly           |
| B7   | Resource envelope, observability and cleanup | Configured maxima remain correct and bounded, health signals work and zero owned residue is proven     |

### B1 — capability, delegation and fresh startup

B1 runs the exact production feature probe on every supported kernel/distro/architecture target.
It proves actual delegation, disposable exact-hook attach/effective state, required helpers/map operations, bpffs/state trust roots, nft availability, requested capacity under unchanged limits and exact cleanup.
It also proves typed refusal for missing delegation, missing helper/program support, insufficient limits, unexpected direct-target BPF and incompatible/unknown state.
PASS requires no listener/readiness before the durable READY manifest and live resolver are validated.

### B2 — placement and Candidate-A trusted chain

B2 creates a production Execution through the staged reserve, frozen prepare, paused create, independent membership proof, activation and start sequence.
It records the actual host PID, `/proc/<pid>/cgroup`, target `cgroup.procs`, target inode, netns identity, direct/effective hooks, policy value, cookie value, canonical tuple, accepted proxy tuple and Resolve result.
Exactly one controlled connection must resolve to the correct `ExecutionId` before any application byte is read.
Wrong cgroup and PID must be typed placement refusals and must never reach Resolve.
The Resolve cases must assert their exact typed result: nonce and generation faults are their corresponding `IdentityMismatch`, a missing referenced cookie is `IdentityMismatch(Cookie)`, the wrong tuple byte order is bounded `Timeout`, and IP-only identity is `NotFound`.
B2 records the measured timeout duration and the configured publication deadline and verifies the wait remains within that deadline with only an explicit bounded scheduling/IPC measurement tolerance; none of these expected denials may change runtime health.
B2 also opens multiple simultaneous connections for which no tuple can be published and requires every one to return bounded `Timeout`, with no `Unavailable`, application read, DNS, outbound effect or health transition.

### B3 — concurrency, lifecycle and identity reuse

B3 runs at the configured concurrent-Execution limit with many overlapping proxy sockets and checks unique cookies, correct tuples and zero mismatch/cross-attribution.
It exercises successful close, FIN, RST, connect failure, agent kill, frozen teardown, source-port reuse, cgroup-ID/inode reuse attempts and fresh backend/Execution generations.
B3 forces cgroup-ID reuse where the test environment permits and proves that the new cgroup ID plus fresh nonce and current generation can become a new valid binding only after the old binding is destroyed.
B3 separately injects every single-field mismatch class: current cgroup ID with stale nonce, current cgroup ID and nonce with stale backend generation, stale cgroup ID with current nonce and generation, and stale cookie/tuple values carrying an old complete or mixed `BindingKey`.
It also races Resolve with freeze so the live-binding revocation and whole-policy transition are exercised at their defined linearization points.
PASS requires whole-`BindingKey` comparison at policy, cookie, tuple, durable-record and live-binding boundaries; every mismatch must deny without fallback, old close callbacks must not delete new state, stale entries must not authorize a new Execution, revocation must close existing work and exact destroy must return occupancy to baseline.

### B4 — fail-closed capacity and publication

B4 independently fills each authorization-relevant map while the others retain headroom.
The Candidate-A cookie map full case is mandatory because S12 filled cookie and tuple maps together and did not isolate it.
B4 uses the unchanged production object with a deliberately small but valid production `max_tracked_sockets` configuration; it does not use a test-only BPF map variant.
Its deterministic production case opens and resolves exactly `C` long-lived proxy connections, keeps their client sockets open so all `C` cookie entries remain live, and verifies that Resolve consumption has returned the tuple map below capacity before attempting connection `C+1`.
Connection `C+1` must fail synchronously at the production `connect4` cookie insertion with the cookie-full counter incremented, no TCP establishment or proxy accept, no tuple publication, no application read, DNS or outbound effect, and no new or overwritten cookie/tuple state.
After the original sockets close, exact cleanup must return both maps to baseline and a fresh connection must succeed, proving capacity rather than another layer caused the denial.
It also covers policy full, tuple full, duplicate cookie, duplicate tuple, delayed publication, missing publication, Resolve queue full, Resolve timeout and event-ring overflow.
PASS requires observable failures, denial before application read/DNS/outbound effect, no IP fallback, no stale authorization and successful freed-entry reuse after exact cleanup.

### B5 — enforcement layers and foreign composition

B5 repeats production direct IPv4, IPv6 stream, IPv4/IPv6 datagram and proxy-path controls.
It causally separates BPF denial from nft denial, temporarily exposes only the exact nft test barrier, and proves nft still blocks a post-ancestor-rewrite destination.
It covers the qualified foreign ancestor ALLOW and rewrite cases, verifies no ordering claim, and proves that unexpected direct-target programs/links are refused without deletion.
PASS requires that proxy steering remains outside BPF and that restoration/cleanup is exact.

### B6 — loss, crash recovery and readiness

B6 kills the loader/Enforcer, Supervisor and Sandbox at controlled lifecycle points, including active connections and unresolved proxy accepts.
It repeats the S13 boundaries after durable INTENT, pin creation, kernel validation and durable READY before readiness, plus partial per-Execution prepare/activate/destroy boundaries.
PASS requires immediate admission stop and effect cancellation, Sandbox kill-all, pinned early enforcement, exact known-compatible generation recovery, empty authorization maps, READY last and byte-for-byte preservation/refusal of incompatible or unknown state.

B6 must additionally exercise `TargetReleased` in the real production systemd topology with `Delegate=yes`, `KillMode=mixed` and `Restart=on-failure`, and must qualify all of these cases:

- positive Enforcer-loss recovery: systemd kills all old agents; the recorded target handle returns `ESTALE`; the harness corroborates that the old ID is absent from the live hierarchy; all six recorded links report only the old ID or zero before exact explicit detach and zero afterwards; the replacement `executions/` is empty and has a different ID; exact old objects are removed; generation `N+1` has empty authorization maps and READY is last;
- the same positive transition at every host-wide S13 crash boundary and every per-Execution prepare/activate/destroy boundary for which the service target is released;
- an old handle that is still openable or does not return `ESTALE`, or any recorded link that reports an ID other than its exact old ID or zero, produces typed `Unknown`, preserves every byte and kernel ID, and never publishes readiness;
- any recorded link/program/map identity mismatch, an unexpected pin/object, a non-empty new target, a target outside the current unit, an explicit detach error or a post-detach identity mismatch likewise fails closed;
- the harness retains the corroborating scan showing the old cgroup ID absent from the live hierarchy, the differing new ID, the old handle result and every `BPF_OBJ_GET_INFO_BY_FD` value before and after explicit detach for all six links as raw evidence;
- a negative case keeps one recorded link attached to a live cgroup and must return `Unknown` without detaching any link;
- the no-cross-boundary-socket-FD assumption is rechecked against the production Sandbox launch path and live agent FD table;
- retained-FD negative controls prove `ENODEV` for a `cgroup.procs` write and `ENOENT` for `clone3(CLONE_INTO_CGROUP)`, with no admitted process;
- repeated refusal under `Restart=on-failure` records systemd restart behavior without admitting work or creating application, DNS or outbound effects.

The direct-removal and true-systemd cases from `b6-kernel-target-20260929T192357Z-r7` qualify the underlying kernel signal only. They do not qualify the production recovery implementation or make B6 PASS.

### B7 — resource envelope, observability and cleanup

B7 runs the declared supported matrix of `max_concurrency`, `max_tracked_sockets`, connection churn and Resolve rate under production service limits.
At every Execution-count point, B7 loads the real production object once, attaches exactly the six shared links to the real Soglia `executions/` subtree, and records direct/effective attachment state for the subtree and representative children before releasing traffic.
B7 must prove constant host-wide inventory of six Soglia programs and six Soglia links, zero per-Execution program/link instances, correct attribution for every sampled child and unchanged effective enforcement as Execution count grows.
This is an independent production qualification gate; S9/S10 foreign-ancestor PASS results are requirements for B5 and do not satisfy or waive the B7 topology proof.
It measures map memory, occupancy/high-water, FDs, program/link/map/pin counts, load/recovery latency, Resolve latency and event loss without tuning the host to force PASS.
Resolve latency is recorded as p50, p95, p99 and maximum for every rate point; these observations do not create an unevidenced latency objective.
PASS requires every successful Resolve to remain within the configured deadline and at least 95% of the requested rate to be achieved for each declared workload.
For every workload inside the declared envelope, B7 sums the production
`cgroup_bpf.resolve_health` outcomes for that workload and requires zero queue
refusals, timeouts, unavailable results, identity mismatches, stale generations,
revocations, misses and integrity failures.  Fixed-rate clients make exactly one
attempt per scheduled connection and never retry a refusal to manufacture the 95%
rate result.  The out-of-envelope 256-request burst is assessed only by the explicit
refusal-characterization contract above.
It injects both required integrity-drift classes: an unexpected foreign direct link on the production target and the detach of one of the six owned Soglia links.
Each must trigger the same one-way fail-closed health transition as helper loss, stop admission and effect-producing work, and must not be silently repaired in process.
It then runs representative full lifecycles and proves zero Soglia-owned process, cgroup, runtime, netns/veth/nft, BPF, pin, map-entry and ownership-record residue.
PASS requires the constant shared-attachment model as well as the measured resource envelope, and does not generalize beyond the tested topology or limits.

B1-B7 do not replace the existing full regression obligations for both backends, T1-T9/H1-H4 or the T10 no-eBPF build.
The legacy `NetnsNftBackend` remains available and unchanged until those regressions pass and a separate explicit enablement decision is made.

## Production uninstallation contract

The proposed production entry point is `soglia uninstall -f <config>`.  It is a
privileged, host-local ownership operation, not a best-effort file removal command.
It uses the configured runtime and bpffs roots only to locate the trusted durable
state; every object it may remove must then be proved from that state and from its
current kernel identity.  `soglia uninstall --dry-run -f <config>` performs the
same discovery, classification and validation and reports the exact removal plan,
but performs no detach, unlink, network operation or directory mutation.

Uninstall is permitted only while the Soglia runtime is stopped.  It must prove
all of the following before its first mutation:

- the configured systemd unit is inactive, has no main process and has no process
  in its runtime or delegated Execution cgroups;
- no Supervisor, Sandbox or Enforcer helper channel or ownership lock is live;
- every recorded Execution has been killed, its cgroup is empty and no effectful
  proxy work remains;
- the state root, state file, generation root and every parent used for ownership
  validation retain the required root ownership, type, mode and no-symlink
  properties.

A live or unprovably stopped runtime is an `Infrastructure` refusal.  Uninstall
never attempts to stop the service itself: service control and confirmation of
the stopped state remain explicit operator actions.

The command reuses the S13 classifier and the same full record-to-kernel checks as
startup recovery.  For `KnownCompatible`, it validates every recorded map,
program, link and pin by ID, type, tag, attach target and exact path; validates all
per-Execution records and `BindingKey` values; freezes authorization; removes
per-Execution resources in lifecycle order; detaches the six exact recorded links;
and removes only the exact recorded pins, state files and directories after they
become empty.  There is no wildcard, prefix-based discovery, program-name
ownership, recursive deletion or untrusted pin path.

`TargetReleased` is accepted only when the complete qualified offline-target
predicate succeeds.  The command opens every exact recorded link pin, verifies
its identity and old target, performs exact `BPF_LINK_DETACH`, verifies cgroup ID
zero afterwards and then removes the recorded generation.  A partially detached
released generation is handled by the same old-ID-or-zero rule as recovery.
`Incompatible` and `Unknown` are never force-cleaned: the command returns the
typed refusal, preserves the state and every kernel object byte-for-byte and
ID-for-ID, and prints the trusted state path plus operator guidance for inspection.
A missing host capability needed to prove ownership is `Unsupported`; an I/O or
host-service failure is `Infrastructure`.  There is deliberately no `--force`
mode that converts an unproved object into an owned object.

The stable process statuses are shared with startup: `Incompatible` 20,
`Unknown` 21, `Unsupported` 22, `Infrastructure` 23 and
`IncompatibleBpfTopology` 24.  A fully removed installation and an already-fresh
host both return zero, with the latter reported as an idempotent no-op.  The
machine-readable result includes the original classification, every validated
resource identity, the planned and completed operations and the final
verification.

Success requires independent final absence checks after the state transition:
no recorded program, link or map ID remains; no recorded pin or ownership record
exists; no Soglia nft table, owned netns/veth, runtime bundle, cgroup or process
remains; and the configured Soglia state and pin parents are either absent or
empty as dictated by their ownership.  Non-owned BPF, cgroup, network and nft
state is snapshotted before and after and must match or satisfy the same narrowly
proved external-churn classification used by qualification.  Failure of final
verification is a nonzero cleanup failure and must retain a durable interruption
record sufficient for an exact retry; it must not broaden the next retry's
ownership authority.

Uninstall qualification is separate from B1-B7 and must cover:

- a fresh host, a complete known-compatible generation and a released target,
  including interruption and retry at every detach/unlink boundary;
- live-runtime, non-empty-cgroup and effectful-work refusals before mutation;
- every `Incompatible`, `Unknown`, `Unsupported` and infrastructure class,
  including orphan pins, identity/tag mismatch, foreign objects and an openable
  old target, with byte-for-byte and ID-for-ID preservation;
- dry-run equivalence: its validated plan equals the subsequent real plan while
  producing no state change;
- exact positive cleanup and non-owned-state preservation measured before any
  qualification-harness teardown.

Release compatibility is a normative gate for this durable state.  Every release
must recognize, validate, recover and uninstall the immediately preceding
release's durable-state schema and production BPF ABI, or ship an explicit,
fail-closed migration that is qualified from that exact predecessor.  A release
that can only classify the predecessor as `Incompatible`, leaving an operator
without a verified recovery and uninstall path, is not releasable.  Compatibility
or migration tests must cover both a live recorded generation and an interrupted
uninstall; there is no implicit schema rewrite or best-effort ABI cleanup.

## Default-backend enablement design

The release configuration enables the Cargo `cgroup-bpf` feature by default and
`NetworkBackend::default()` is `NetworkBackend::CgroupBpf`.
`NetworkBackend::NetnsNft` remains a supported explicit value.

Default does not mean fallback.  The normal startup capability probe, delegation
validation and S13 recovery run before READY.  If the default cgroup-BPF backend
is unsupported, incompatible, unknown or unavailable, startup returns its typed
refusal and stops.  It must not instantiate `NetnsNftBackend`, reinterpret an
error as absence or silently downgrade attribution.  The operator-facing
`Unsupported` detail names the missing capability and says that an intentional
compatibility deployment must set `network.backend: netns-nft` explicitly and
restart.  The same rule applies when the default-feature binary is installed on
an unqualified kernel.

T10 becomes a two-build dependency contract:

1. the default production build includes only the reviewed eBPF dependencies
   required by `CgroupBpfBackend`; the allow-list is exact and continues to reject
   PIC, gRPC and TLS crates and any unrelated networking/control-plane stack;
2. a build with `--no-default-features` (and any explicitly required non-BPF
   baseline features) must compile and pass the original T10 rule with no eBPF
   crates at all, while retaining explicit `netns-nft` operation.

Both checks inspect the resolved graph and the linked production binary rather
than matching package names in source text.  Adding cgroup-BPF to default features
does not authorize PIC, gRPC, TLS, automatic feature fallback or an eBPF
dependency in the no-cgroup-BPF build.

The operator-visible release change consists of the new default, the supported
kernel/systemd/cgroup-v2 prerequisites, the stable refusal codes, the explicit
`netns-nft` opt-in and the uninstall/dry-run workflow.  The README, architecture
documentation and the “Run Soglia” page must describe those points and must not
claim automatic compatibility fallback.  Documentation changes are delivered
only after the implementation and qualification results exist.

The release commit must pass normal static/unit checks, both T10 build modes,
T1-T9 and H1-H4 against both explicit backends, the uninstall qualification and
`spike:qualify` B1 through B7 on fresh VMs.  The B1-B7 evidence must name that
single production baseline, record one clean harness commit for the whole run and
pass the automated evidence verifier.  Any subsequent production change to
features, backend selection, lifecycle, helper protocol, BPF object, ownership or
cleanup invalidates the affected qualification and requires the complete relevant
gate set to be repeated before release.

## Residual risk and open review points

- Candidate A still depends on tested-kernel semantics for socket cookies, sockops callbacks, cgroup IDs and link attachment; B1 must define the supported platform matrix.
- Fixed hash capacity converts hostile socket churn into bounded cross-Execution availability pressure, while preserving authorization safety.
- `sockops` cannot undo an already established local proxy TCP connection after tuple publication fails; security depends on the proxy's proven no-read/no-effect Resolve gate.
- cgroup connect hooks do not terminate an already established socket at freeze; revocation, proxy cancellation, Sandbox kill and nft confinement jointly close that gap.
- A privileged host actor can alter BPF, nft or cgroups and is outside the untrusted-agent threat model, but unexpected drift must still stop Soglia.
- The separate attribution RPC adds latency and a bounded queue whose production envelope is not known until B7.
- The exact `max_tracked_sockets` default and supported ceiling remain availability-policy choices; 4096 is a tested starting value, not a universal sizing proof.
- Full kernel/distro/architecture portability, upgrades between BPF ABI versions and rolling multi-instance coordination remain unqualified.
- Phase-0 CONNECT mediation still does not provide L7 TLS identity or prevent domain-fronting behavior after an allowed tunnel is established.

Implementation and default enablement were explicitly authorized against this contract.
The final B1-B7 plus uninstall qualification and the full T1-T10/H1-H4 dual-backend regressions passed on production baseline `17d8fc732bfdbdc99d7924193965c427e52a0b68`.
