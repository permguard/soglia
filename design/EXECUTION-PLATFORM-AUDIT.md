<!-- Copyright (c) 2022 Nitro Agility S.r.l. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Execution platform implementation audit

## Scope and method

This audit compares the repository at commit `62a3160c9d3d0fbf5ad22d8cdccb461f0f6e1813` with the invariants in `design/EXECUTION-PLATFORM.md`.
`PRESENT` means the complete invariant exists and has a directly relevant test or qualification gate.
`PARTIAL` means useful controls exist but at least one normative clause is absent or unqualified.
`ABSENT` means the defining mechanism is not implemented, even if adjacent controls reduce its risk.
Line references name the audited commit and will naturally move as the source changes.

Phase 1 release qualification is evidence for its recorded scope, not evidence for the later template, pool, volume or long-soak requirements.
Its authoritative summary is at `spikes/cgroup-bpf/REPORT.md:1073-1113`.

## Isolation invariants

| ID | Status  | Finding                                  | Closure    |
| -- | ------- | ---------------------------------------- | ---------- |
| I1 | PARTIAL | Identity controls exist; no userns.      | Phase 3    |
| I2 | PRESENT | Rootfs is read-only; tmpfs is bounded.   | Maintain   |
| I3 | ABSENT  | No exclusive fixed-size volume.          | Phase 3    |
| I4 | PRESENT | Qualified network boundary is complete.  | Maintain   |
| I5 | PARTIAL | Namespaces exist; seccomp is deny-list.  | Phase 3    |
| I6 | PARTIAL | CPU/memory/PID/FD, but no I/O reserve.   | Phase 3    |
| I7 | PRESENT | Current lifecycle is verified one-shot.  | Phase 4    |
| I8 | ABSENT  | No inert verified image template exists. | Phases 3-4 |

### Isolation evidence and gaps

- **I1:** `bundle.rs:137-169` and `runc.rs:167-185` prove UID/GID, empty capabilities and `noNewPrivileges`; `bundle.rs:256` proves that the user namespace is absent.
- **I2:** `bundle.rs:106-120,158,276-293` and the privileged runc test cover the current read-only rootfs and bounded tmpfs model.
- **I3:** `bundle.rs:106-120` and `backend.rs:590-608` provide tmpfs and bundle deletion, but no volume identity, capacity, durable lifecycle or deletion proof.
- **I4:** `rules.rs:68-168`, `policy/mod.rs:171-225`, T2-T5, H1-H3 and B2/B5/B7 prove the current runc boundary; every later profile must repeat it.
- **I5:** `bundle.rs:16-69,162-205,238-257` creates PID, network, IPC, UTS, mount and cgroup namespaces, but lacks userns and a least-privilege seccomp allow-list.
- **I6:** `config.rs:318-343`, `backend.rs:779-808`, H4 and B7 prove several per-Execution limits, but not cgroup I/O limits or aggregate reservation.
- **I7:** `supervisor.rs:350-370`, sandbox `backend.rs:575-610`, enforcer `backend.rs:688-715`, T1/T6-T8 and B3/B6/B7/uninstall prove the current one-call lifecycle.
- **I8:** `config.rs:281-315` and `backend.rs:832-933` configure a mutable rootfs and directly create the agent; digest, signature, inert-template and input-boundary proofs are absent.

### Isolation conclusions

The strongest current properties are the read-only root, the network boundary and the verified one-shot lifecycle.
The largest gaps are the missing user namespace, default-allow seccomp, missing I/O control, missing private volume and missing immutable template supply chain.
Those gaps prevent the current implementation from claiming the complete I1-I8 platform contract despite the valid Phase 1 network qualification.

## Resource invariants

| ID | Status  | Finding                                      | Closure    |
| -- | ------- | -------------------------------------------- | ---------- |
| R1 | PARTIAL | Per-call cleanup, but no sustained baseline. | Phase 4    |
| R2 | ABSENT  | No 24-hour slope test.                       | Phase 4    |
| R3 | PARTIAL | Core bounds exist; several queues do not.    | Phases 2-4 |
| R4 | PARTIAL | Limits exist without host reservation.       | Phase 3    |
| R5 | PARTIAL | Queue refusal exists; host budgets do not.   | Phases 2-3 |
| R6 | PARTIAL | Bundles/networks delete; volumes do not.     | Phases 3-6 |
| R7 | PARTIAL | Agent output capped; journal unbounded.      | Phase 4    |
| R8 | PARTIAL | Admission bounded; connection tasks are not. | Phases 2-4 |

### Resource evidence and gaps

- **R1:** `supervisor.rs:355-369`, T6-T8 and B6/B7 prove per-call residue cleanup, but not return of every measurement within 60 seconds after sustained load.
- **R2:** `REPORT.md:1204-1225` defers the required 24-hour kernel/process resource slope test.
- **R3:** `config.rs:61-104,169-190`, `supervisor.rs:180-186`, `cgroup_bpf.rs:1294-1306` and B4/B7 prove invocation, Resolve and BPF bounds; proxy tasks, registries, collections and journals still need local bounds.
- **R4:** `config.rs:318-343`, sandbox `backend.rs:779-797`, H4 and B7 apply per-Execution limits without reserving aggregate host memory or disk.
- **R5:** `supervisor.rs:307-329`, `helpers.rs:423-471`, `runc.rs:196-212`, T9 and B4/B7 prove typed queue saturation, but not pre-admission memory, disk or pool budgets.
- **R6:** sandbox `backend.rs:575-610`, enforcer `backend.rs:688-715`, T6-T8 and B6/B7/uninstall prove current object removal; private volumes and ephemeral keys do not exist yet.
- **R7:** sandbox `backend.rs:38-43,873-889,985-998` caps agent relay output at 64 KiB, while `main.rs:214-219` has no declared journal rotation or retention budget.
- **R8:** `supervisor.rs:180-186`, sandbox `backend.rs:985-998` and B7 bound many live objects, but accepted connection tasks remain unbounded and lack a long soak.

### Resource conclusions

Phase 1 proves bounded BPF objects, typed saturation and exact cleanup for its declared envelope.
It does not prove zero long-run slope, host-level reservation, volume capacity or stable process resources over millions of calls.
The Phase 2 and Phase 3 changes must establish hard bounds before the Phase 4 soak can measure meaningful steady-state behavior.

## Current bounds and missing bounds

### Declared bounds already present

- Invocation admission uses `runtime.max_concurrency` and `runtime.max_queue` through two semaphores at `crates/soglia-supervisor/src/supervisor.rs:180-186`.
- Candidate-A Resolve admission uses a semaphore at `crates/soglia-supervisor/src/helpers.rs:255-264,386-404`, currently sized from `runtime.max_concurrency` at `src/main.rs:567-585`.
- IPC frames are capped at 1 MiB at `crates/soglia-core/src/ipc.rs:21-22`.
- Ingress and egress bodies, tunnel bytes and timeouts are configured at `crates/soglia-core/src/config.rs:107-125,194-220`.
- Agent process count, memory, CPU and file descriptors are configured at `crates/soglia-core/src/config.rs:318-343`.
- BPF policy, deny, cookie, tuple and ring capacities are set before load at `crates/soglia-enforcer/src/cgroup_bpf.rs:1294-1306`.
- Agent log relay emission is capped at 64 KiB at `crates/soglia-sandbox/src/backend.rs:38-43,985-998`.

### Queues, caches and maps without a declared hard bound

| Structure                  | Required closure                        | Phase      |
| -------------------------- | --------------------------------------- | ---------- |
| Ingress connection tasks   | Connection semaphore and typed refusal. | Phase 2    |
| Egress connection tasks    | Bound accepted and pending attribution. | Phase 2    |
| IP attribution map         | Local ceiling plus health assertion.    | Phase 2    |
| Candidate-A binding map    | Local ceiling plus health assertion.    | Phase 2    |
| Sandbox live registry      | Admission and quarantine ceiling.       | Phase 3    |
| nft live registry          | Pre-insertion execution ceiling.        | Phase 3    |
| cgroup-BPF live registry   | Explicit observable local ceiling.      | Phases 2-3 |
| Agent configuration maps   | Item and encoded-byte ceilings.         | Phase 3    |
| Destination policy lists   | Policy and DNS-answer ceilings.         | Phases 2-5 |
| Runtime stderr and journal | Rate, size and retention budgets.       | Phase 4    |

The ingress growth site is `ingress.rs:81-119`, where every accepted connection gets a Tokio task before invocation admission.
The egress growth site is `egress.rs:145-163`, where every accepted proxy socket gets a task before attribution completes.
The IP and Candidate-A tables at `attribution.rs:100-178` rely on correct upstream lifecycle rather than local capacity checks.
The Sandbox registry at `backend.rs:186-200,439-450`, nft registry at enforcer `backend.rs:328-368` and cgroup-BPF registry at `cgroup_bpf.rs:116-129,350-378` likewise lack defensive local ceilings.
Agent maps at `config.rs:55-58,281-315` and policy collections at `config.rs:129-142,194-232` plus `policy/mod.rs:120-159` have no item-count limits.
Structured stderr at `main.rs:214-219,292-298` has no repository-owned rotation or retention contract.

The in-memory lifecycle registries are indirectly constrained by Supervisor admission today.
They remain listed because R3 requires each component to reject excess state locally rather than depend only on an upstream invariant.

No production cache was found.
Introducing image, template, connector, credential or snapshot caches requires a declared entry count, byte budget, expiry rule and saturation behavior before implementation.

## Tests serialized with `--test-threads=1`

The CI currently serializes every workspace unit test at `.github/workflows/ci.yml:43-46`.
The privileged acceptance runner separately serializes ignored tests for both backends at `dev/linux/acceptance.sh:17-23`.
Those two uses have different causes and should not be treated as one permanent constraint.

| Test group             | Cause                           | Required isolation                 |
| ---------------------- | ------------------------------- | ---------------------------------- |
| Candidate-A unit tests | Real-time scheduler contention. | Deterministic clock and barriers.  |
| Phase-0 acceptance     | Fixed host-global resources.    | Disposable privileged environment. |
| runc privileged test   | Kernel-global runtime objects.  | Private delegated environment.     |
| netns-nft test         | Fixed network and nft objects.  | Private netns or disposable host.  |

The Candidate-A timing cases are `helpers.rs:978-1264`.
They use private socketpairs but real 20-60 ms sleeps, publication deadlines and watchdogs, so they need an injectable or paused clock plus explicit resolver barriers before ordinary parallel unit testing is restored.
The affected cases include missing-tuple concurrency, pending/complete replies across the deadline, caller cancellation and watchdog expiry.

Phase-0 T1-T10/H1-H4 uses fixed ports, `/run/soglia-phase0`, a process singleton, a fixed cgroup root, `soglia0`, `upstream0`, nftables and test services.
Its one-at-a-time contract is in `tests/phase0.rs:4-48`; it should remain in one disposable privileged VM/container unless every resource is parameterized.

The sandbox test at `crates/soglia-sandbox/tests/runc.rs:107-120` owns delegated cgroups, runc state, `/run/netns`, veth and nftables and therefore needs a private delegated container or VM.
The enforcer test at `crates/soglia-enforcer/tests/netns_nft.rs:4-12` owns fixed `soglia0`, `inet soglia_host`, netns and veth objects and needs a private network boundary or suite-level disposable host.

The immediate unit-test fix is not to serialize unrelated tests globally.
It is to remove wall-clock scheduling from the Candidate-A timing tests and restore the ordinary parallel test runner.
Privileged kernel integration suites should remain isolated at a disposable environment boundary even if their internal names later become unique.

## Clean-environment portability finding closed by SOG-1.03

The first clean CI run after making `cgroup-bpf` the default exposed two assumptions that were hidden by the qualification VMs.
An effective external BPF program in the CI container had no `name` field in `bpftool prog show`, so the startup inventory rejected the host before it could attach Soglia's programs.
An unprivileged unit test also created a mode-0700 temporary directory and incorrectly expected it to satisfy the production requirement that an unrecorded pin root be owned by root.

Commit `7dd0840e4d51078c01ab26343c9eebfd315e5e5e` closes both findings without weakening an owned-resource check.
An external program name is optional evidence, but two reported names must agree when both are present, and the external fingerprint still requires the exact program ID, type, tag and attach type.
The six Soglia-owned programs retain their existing exact recorded and kernel identity checks.
The pin-root test now exercises the pure classification rule without pretending to have root ownership, while the filesystem test continues to prove that an untrusted directory is `Unknown`.

The clean Linux image then passed workspace tests and Clippy, the two T10 builds, and T1-T10/H1-H4 with both `netns-nft` and `cgroup-bpf`.
This is the concrete application of the rule in `EXECUTION-PLATFORM.md`: VM qualification alone does not finish a work item; its CI-equivalent checks must also pass in a clean environment.

The second SOG-1.03 iteration made those environment claims directly observable and added the missing regression case.
The B1 diagnostic `b1-20261001T143637Z-1561543` is PASS and includes an unnamed external `cgroup_device` program on `system.slice`, inherited by the Execution subtree.
`bpftool` reported program ID 24829, tag `57cd311f2e27366b` and an empty name.
Startup and uninstall preserved that program and its link byte-for-byte in the selected identity fields.
Replacing it with another unnamed program, ID 24910 and tag `711788109f1edac6`, produced typed `Unknown` exit 21 without modifying the replacement.
Restoring the original program identity restored READY startup, and the case and B1 cleanup both passed.
The aggregate qualification verifier now requires this evidence and has a negative test that recomputes checksums after falsifying the changed-tag assertion.

The unprivileged workspace tests ran in a disposable `ubuntu:24.04` amd64 container with the repository mounted read-only.
The output recorded Ubuntu 24.04.5 LTS, `uid=10001(ci)`, `id_u=10001`, and a successful `cargo test --workspace --locked -- --test-threads=1` covering 175 unit tests with zero failures; the two privileged integration tests were explicitly ignored.
The complete 505-line diagnostic output had SHA-256 `4b02b125a6a812943831bec1b9573b99975883dc0004aea1dcf068a2a56f2b43`.
The CI test step now prints the runner identity and fails unless its UID is nonzero before running the same command.

The privileged acceptance ran inside image `sha256:5e036fc3424426949d24b7b24a8bbb55f4368bd08cbf88685c3f1119ddddb9c6` through `dev/linux/cgroup-init.sh`.
Its output recorded `acceptance_environment=dev/linux privileged=true uid=0` and an effective external program `{id:18,type:cgroup_device,tag:b11459a0e11ca14c,name:""}` created with a zeroed kernel program name.
T1-T10/H1-H4 then passed 15/15 first with `netns-nft` and again 15/15 with `cgroup-bpf`; each backend's privileged enforcer and sandbox integration tests also passed.
The complete 218-line diagnostic output had SHA-256 `496b5ebb39d97a73e2aafc422a7091861769c62b69cb1cf1e23cd7700a9b0e79`.
The acceptance entry point now creates and proves that unnamed external program before either backend pass and removes only its exact pinned link and program afterward.

## Gate coverage and closure order

| Phase         | Evidence focus                                     |
| ------------- | -------------------------------------------------- |
| Phase 2       | Queue bounds, saturation and refusal side effects. |
| Phase 3       | I1-I8, OCI trust, volumes, I/O and reservation.    |
| Phase 4       | Pool lifecycle, crashes, soak and resource slopes. |
| Phase 5       | L7 trust, request policy and downgrade resistance. |
| Phase 6       | Profile isolation, disks, snapshots and VMM/TAP.   |
| Cross-profile | Aggregate qualification and clean-environment CI.  |

Phase 2 must record independent ingress, egress and Resolve bounds, exact saturation outcomes, stable task/FD counts and zero side effects for refusals.
Phase 3 needs a positive and negative I1-I8 matrix, OCI digest/signature provenance, volume isolation/deletion, I/O limits and aggregate reservations.
Phase 4 needs pool claim/destroy latency distributions, every crash boundary, a 24-hour soak, resource slopes and the 60-second baseline verdict.
Phase 5 needs CA, Credential Anchor, PIC and Connector boundaries, per-request authorization and destination-mode downgrade tests.
Phase 6 needs profile-specific isolation, TAP enforcement, VMM confinement, encrypted-disk key deletion and snapshot uniqueness.
Cross-profile release evidence is one `spike:qualify` result plus dual-backend regressions and clean-environment CI on the same release commit.

## Audit verdict

The Phase 1 platform is a qualified one-shot runc execution path with strong network enforcement and verified teardown.
It is not yet the complete execution platform defined by I1-I8 and R1-R8.
The required order is Phase 2 bounds, Phase 3 isolation and reservation, then Phase 4 long-run proof; later profiles must reuse the invariants rather than weaken them.
