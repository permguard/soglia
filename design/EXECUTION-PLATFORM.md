<!-- Copyright (c) 2022 Nitro Agility S.r.l. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Execution platform design

## Status and scope

Status: `DESIGN_FOR_REVIEW`.

This document defines the target execution platform after the Phase 1 release qualification recorded in `spikes/cgroup-bpf/REPORT.md`.
It is normative for later production design, implementation and qualification work, but it does not change the qualified Phase 1 behavior.
Every phase below becomes releasable only when its gate is included in `spike:qualify` and passes in a clean environment.

## Operating rules

- Diagnostic and qualification-harness work proceeds autonomously within an approved design.
- Work stops for a production design decision, a semantic or ABI change, or a release commit ready for review.
- A work item is complete only when its CI-equivalent checks pass in a clean environment.
- Nicola runs `spike:qualify`; an executor must not start it without that explicit action.
- Every executor report begins with `[ID] PASS`, `[ID] BLOCKED` or `[ID] DECISION`.
- Every commit has `Nicola Gallo <nicola.gallo@nitroagility.com>` as both author and committer, and an executor does not push.

## Objective

Soglia creates exactly one Execution for one call.
An Execution may be prepared before the call, but it remains unused and without call authority until claimed.
It is isolated as an independent service: it has no local host access, reaches only declared network APIs, and owns one fixed-size private volume.
The system returns to a measured baseline after load, including after millions of calls, without resource accumulation.
Load beyond a declared budget produces bounded typed refusal and never an OOM, disk-full condition, unbounded wait or runtime crash.

## Isolation invariants

| ID  | Normative invariant                                                                                       |
| --- | --------------------------------------------------------------------------------------------------------- |
| I1  | Agent code runs as a normal user, with no capabilities, with `no_new_privs`, and inside a user namespace. |
| I2  | The system filesystem visible to the Execution is read-only.                                              |
| I3  | Every Execution gets one fixed-size volume that is never shared and is deleted with that Execution.       |
| I4  | The Execution can reach only declared network APIs, never the host, cloud metadata or another Execution.  |
| I5  | Every Execution has separate namespaces and an explicit least-privilege seccomp policy.                   |
| I6  | Every Execution has hard CPU, memory, process and I/O limits.                                             |
| I7  | An Execution is single-use and its destruction is verified before its slot or response is released.       |
| I8  | A reusable template never executes agent code and never observes call input.                              |

The invariants compose.
No backend profile may claim conformance by replacing one invariant with another or by silently falling back to a weaker profile.

## Resource invariants

| ID  | Normative invariant                                                                                                  |
| --- | -------------------------------------------------------------------------------------------------------------------- |
| R1  | After load stops, every measured resource returns to its declared baseline within a fixed deadline.                  |
| R2  | At steady state, the slope of every cumulative resource measurement is statistically indistinguishable from zero.    |
| R3  | Every queue, cache, map, log and pool has a declared hard bound and a defined saturation result.                     |
| R4  | Memory and disk are reserved before admission and are never overcommitted.                                           |
| R5  | Exhausted budget produces an immediate or deadline-bounded typed refusal, never OOM, disk full or unbounded waiting. |
| R6  | Volume, bundle and ephemeral keys are deleted immediately after use and their absence is verified.                   |
| R7  | Logs are size-limited, rate-limited where necessary, and rotated under a declared retention budget.                  |
| R8  | Runtime RSS, thread count and file-descriptor count remain stable under steady admitted load and refusal load.       |

### Required measurements

Every capacity and soak gate records time series for the following resources:

- process memory, cgroup memory and kernel slab;
- live cgroups, dying cgroups and `nr_dying_descendants`;
- network namespaces and their teardown backlog;
- veth devices and routes;
- nftables tables, chains, sets, elements and rules;
- occupancy, capacity and high-water marks of every BPF map;
- conntrack entries;
- ephemeral-port availability and `TIME_WAIT` sockets per destination;
- open file descriptors by process and type;
- threads and tasks by process;
- zombie processes;
- filesystem inode consumption;
- volume, bundle, runtime-state and log disk usage;
- journal size and retention;
- runtime and helper RSS.

The measurement implementation must distinguish active work, cleanup in progress and residue after the cleanup deadline.
Harness teardown happens only after residue has been measured.

## Proposed time budgets

These numbers are initial qualification targets and become supported guarantees only after their gates produce measurements.

| Operation                                    | Proposed budget                             |
| -------------------------------------------- | ------------------------------------------- |
| Claim of a prepared runc Execution           | p99 below 50 ms                             |
| Clone and restore of a Firecracker microVM   | p99 below 150 ms                            |
| Destruction and verified absence             | p99 below 200 ms, outside the response path |
| Return of all measured resources to baseline | below 60 s after load stops                 |
| Admission when a pool is exhausted           | immediate typed refusal without waiting     |

The response path may release the caller before asynchronous physical teardown only after authority has been revoked atomically and the cleanup work has been durably owned by a bounded reaper.
Until that later design is qualified, the current Phase 1 rule that verifies teardown before releasing the response remains authoritative.

## Profiles and no-fallback rule

The supported sandbox profiles are `runc`, `gvisor` and `firecracker`.
The selected profile is always explicit in resolved configuration and evidence.
`runc` is the default and remains available on hosts without KVM.
Failure of a selected profile's capability probe is a typed refusal and never triggers automatic fallback.

The host has one fail-closed Soglia proxy shared by all profiles.
Every profile must prove that the proxy is its only egress path and that no application byte, DNS lookup or outbound connection occurs before trusted attribution and authorization succeed.

## Template and artifact contract

A template is an inert, versioned preparation artifact.
It contains no call input, invocation nonce, credential, randomness state or agent process that has executed.
Claiming a template binds a fresh identity and injects per-call state only after all template invariants have been revalidated.

For the runc profile, an agent is an OCI image referenced by immutable digest.
Soglia verifies the configured signature and provenance policy before admitting the image.
The image archive is stored read-only and unpacked once per verified digest into an immutable rootfs shared only as read-only filesystem data.
Writable state lives solely in the Execution's private fixed-size volume and bounded tmpfs mounts.

## Phase plan and qualification gates

### Phase 2: parallel Resolve and resource admission

Phase 2 implements deferred Resolve option B.
It introduces a separately configurable `max_pending_resolves`, a request-ID-correlated pipelined channel and a stateless bounded Enforcer worker pool.
The gate proves correlation, poisoning on protocol anomalies, saturation as typed `QueueFull`, no pre-Resolve side effect, and R3 through R5 for ingress, proxy and Resolve resources.

### Phase 3: complete runc isolation

Phase 3 closes I1 through I8 for the runc profile.
It adds the user namespace, a least-privilege seccomp allow-list, fixed-size private volumes, hard I/O limits, aggregate reservation, and the OCI digest/signature/unpack-once contract.
Its gate proves each invariant independently, including negative tests for a mutable image, invalid signature, shared volume, host access and exhausted aggregate budget.

### Phase 4: single-use warm pool and soak

Phase 4 adds a pool of prepared but never-used Executions.
A pooled Execution is claimed once, revalidated before claim and destroyed after the call; it is never returned to the pool.
The gate includes all crash boundaries, exhaustion refusal, the proposed latency budgets, a 24-hour steady-state soak and a high-churn run long enough to assess R1, R2, R7 and R8.

### Phase 5: layer-7 mediation

Phase 5 adds mediated TLS with a Soglia CA, a Credential Anchor, per-request policy, PIC continuity and explicit Connectors.
Each destination selects exactly one mode: `mediate`, `passthrough` or `deny`.
The gate proves that mode selection is explicit, credentials are destination- and request-bound, PIC cannot be bypassed, and unclassified destinations fail closed.

### Phase 6: stronger sandbox profiles

Phase 6 evaluates gVisor first and then Firecracker.
The Firecracker profile uses one microVM per call restored from a qualified snapshot, one TAP per VM, the same host proxy, the Firecracker jailer, and an encrypted ephemeral disk whose key is destroyed with the Execution.
The host VMM process runs in its own Soglia cgroup and cgroup-BPF denies `sock_create` for that process, so the VMM cannot bypass the TAP and proxy boundary.
Each profile gets its own capability probe, resource envelope, recovery contract and qualification gate.

## Architectural decisions

### No fork zygote

A fork-based zygote is excluded.
Fork inherits address-space layout, random-generator state, memory contents, file descriptors and namespace membership in ways that are difficult to prove empty and independent.
Copy-on-write does not make inherited secrets or state safe.

### Snapshot clones with post-restore identity

Firecracker snapshot cloning is adopted conditionally because it offers the required cold-start envelope behind a VM boundary.
Every restored clone receives VMGenID-equivalent uniqueness, entropy reseeding and all secrets only after restore.
Snapshots rotate on a bounded schedule and whenever their kernel, agent template, policy-relevant configuration or measured trust basis changes.
No credential, disk key, request data or live authorization is present in a snapshot.

### Explicit profile selection

`runc`, `gvisor` and `firecracker` are distinct named profiles.
The runtime records the selected profile in durable ownership state and evidence.
Capability failure, stale state or unsupported configuration refuses startup without fallback.

### One fail-closed proxy

All profiles use one host proxy and the same destination-policy semantics.
Sandbox-specific attribution may differ, but authorization, forbidden-address checks, DNS timing and the rule of no effect before authorization do not.

## Declared trade-offs

- Stronger lifecycle and artifact verification enlarge the privileged code and the amount that must be qualified.
- A warm pool consumes memory, cgroups, namespaces, file descriptors and policy capacity while idle.
- Snapshot clones share an initial memory layout and therefore an initial ASLR layout, even though secrets and entropy are injected after restore.
- The default `cgroup-bpf` backend has narrower kernel and host portability than explicit `netns-nft` compatibility mode.
- A single proxy is an operational concentration point, so it requires bounded admission, fail-closed health handling and measured capacity.
- Fixed reservations reduce utilization efficiency in exchange for deterministic failure behavior.

## Work-item map

The predicted iterations include implementation, diagnostic correction and authoritative qualification loops.
They are planning estimates rather than permission to combine production decisions.

| ID       | Deliverable                                                           | Predicted iterations |
| -------- | --------------------------------------------------------------------- | -------------------- |
| SOG-2.01 | Execution-platform design and audit of the current implementation     | 1                    |
| SOG-2.02 | Resolve option-B protocol, bounds, health and failure design          | 2                    |
| SOG-2.03 | Bounded Supervisor pipeline and stateless Enforcer worker pool        | 3                    |
| SOG-2.04 | R3-R5 capacity, saturation and fault-injection harness                | 2                    |
| SOG-2.05 | Full qualification, operator documentation and Phase 2 release        | 2                    |
| SOG-3.01 | OCI digest, signature, provenance and immutable unpack-store design   | 2                    |
| SOG-3.02 | User namespace and seccomp allow-list implementation                  | 3                    |
| SOG-3.03 | Fixed-size private Execution-volume lifecycle                         | 3                    |
| SOG-3.04 | I/O limits, aggregate reservation and typed budget refusal            | 3                    |
| SOG-3.05 | I1-I8 runc qualification and Phase 3 release                          | 3                    |
| SOG-4.01 | Single-use warm-pool lifecycle and sizing design                      | 2                    |
| SOG-4.02 | Pool prepare, claim, replenish and expiry implementation              | 3                    |
| SOG-4.03 | Pool crash recovery, stale-state and fail-closed fault matrix         | 3                    |
| SOG-4.04 | Twenty-four-hour soak and high-churn resource-slope qualification     | 3                    |
| SOG-4.05 | Latency-envelope qualification and Phase 4 release                    | 2                    |
| SOG-5.01 | L7 trust model, CA and destination-mode design                        | 2                    |
| SOG-5.02 | Mediated TLS and Credential Anchor implementation                     | 4                    |
| SOG-5.03 | Per-request policy and PIC continuity                                 | 4                    |
| SOG-5.04 | Explicit Connectors and `mediate`/`passthrough`/`deny` modes          | 3                    |
| SOG-5.05 | L7 adversarial qualification and Phase 5 release                      | 3                    |
| SOG-6.01 | gVisor profile design, integration and qualification                  | 3                    |
| SOG-6.02 | Firecracker threat model, jailer and lifecycle design                 | 3                    |
| SOG-6.03 | Snapshot, VMGenID, reseed and rotation implementation                 | 4                    |
| SOG-6.04 | TAP proxy boundary, encrypted disk and VMM cgroup-BPF confinement     | 4                    |
| SOG-6.05 | Firecracker isolation, resource and recovery qualification            | 4                    |
| SOG-X.01 | Cross-profile `spike:qualify`, clean-environment CI and release audit | 3                    |

## Gate composition

Every new gate is added to `spike:qualify`; no phase creates a separate path that bypasses the aggregate verifier.
The aggregate verifier pins one production baseline and one clean harness fingerprint for the entire run.
Every gate measures residue before harness teardown, verifies checksums and records its environment fingerprint.
An outcome of `FAIL`, `UNPROVEN`, `UNSUPPORTED`, `INFRA_ERROR` or `CLEANUP_FAIL` stops the run and leaves later gates `NOT_EXECUTED`.
The release audit checks the same commands in a clean CI-equivalent environment before work is reported complete.
