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

| ID  | Status  | Current evidence                                                                                                                                      | Current test or gate                           | Precise gap                                                                                                                                                                    | Closing phase             |
| --- | ------- | ----------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------- |
| I1  | PARTIAL | `crates/soglia-sandbox/src/bundle.rs:137-169`; `crates/soglia-sandbox/tests/runc.rs:167-185`                                                          | runc privileged test; T1-T10/H1-H4             | UID/GID, empty capabilities and `noNewPrivileges` are proved, but `bundle.rs:256` explicitly proves that no user namespace exists.                                             | Phase 3                   |
| I2  | PRESENT | `crates/soglia-sandbox/src/bundle.rs:106-120,158`; `crates/soglia-sandbox/src/bundle.rs:276-293`                                                      | bundle unit test; runc privileged test         | None for the current runc rootfs and bounded tmpfs model.                                                                                                                      | Maintained in every phase |
| I3  | ABSENT  | `crates/soglia-sandbox/src/bundle.rs:106-120`; `crates/soglia-sandbox/src/backend.rs:590-608`                                                         | None                                           | Only per-container tmpfs and bundle deletion exist; there is no fixed-size persistent volume, exclusive volume identity, lifecycle record or deletion proof.                   | Phase 3                   |
| I4  | PRESENT | `crates/soglia-enforcer/src/rules.rs:68-116`; `crates/soglia-enforcer/src/rules.rs:129-168`; `crates/soglia-proxy/src/policy/mod.rs:171-225`          | T2-T5, H1-H3; B2, B5 and B7                    | None for the qualified runc profiles; every later backend must re-prove the same boundary.                                                                                     | Maintained in Phases 2-6  |
| I5  | PARTIAL | `crates/soglia-sandbox/src/bundle.rs:16-69,162-180,185-205`; `crates/soglia-sandbox/src/bundle.rs:238-257`                                            | bundle unit tests; runc privileged test        | PID, network, IPC, UTS, mount and cgroup namespaces exist, but the user namespace is absent and seccomp is a default-allow deny-list rather than a least-privilege allow-list. | Phase 3                   |
| I6  | PARTIAL | `crates/soglia-core/src/config.rs:318-343`; `crates/soglia-sandbox/src/backend.rs:779-808`; `crates/soglia-sandbox/tests/runc.rs:196-212`             | H4; runc privileged test; B7 envelope          | CPU, memory, process and FD limits exist, but no cgroup I/O limit or aggregate resource reservation exists.                                                                    | Phase 3                   |
| I7  | PRESENT | `crates/soglia-supervisor/src/supervisor.rs:350-370`; `crates/soglia-sandbox/src/backend.rs:575-610`; `crates/soglia-enforcer/src/backend.rs:688-715` | T1, T6-T8; B3, B6, B7; uninstall qualification | None for the current one-call runc lifecycle; the warm pool must preserve single use and measured destruction.                                                                 | Requalified in Phase 4    |
| I8  | ABSENT  | `crates/soglia-core/src/config.rs:281-315`; `crates/soglia-sandbox/src/backend.rs:832-933`                                                            | None                                           | A mutable rootfs path is configured and the agent is created directly; no inert template, digest, signature, no-agent-executed proof or call-input boundary exists.            | Phase 3, then Phase 4     |

### Isolation conclusions

The strongest current properties are the read-only root, the network boundary and the verified one-shot lifecycle.
The largest gaps are the missing user namespace, default-allow seccomp, missing I/O control, missing private volume and missing immutable template supply chain.
Those gaps prevent the current implementation from claiming the complete I1-I8 platform contract despite the valid Phase 1 network qualification.

## Resource invariants

| ID  | Status  | Current evidence                                                                                                                                              | Current test or gate           | Precise gap                                                                                                                                                                         | Closing phase                                         |
| --- | ------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------- |
| R1  | PARTIAL | `crates/soglia-supervisor/src/supervisor.rs:355-369`; `spikes/cgroup-bpf/REPORT.md:1073-1113`                                                                 | T6-T8; B6 and B7               | Per-call residue and B7 row cleanup are proved, but no sustained-load gate proves return of every required measurement to baseline within 60 seconds.                               | Phase 4                                               |
| R2  | ABSENT  | `spikes/cgroup-bpf/REPORT.md:1204-1225`                                                                                                                       | None                           | The report explicitly requires a future churn soak; there is no 24-hour time series or slope test for kernel and process resources.                                                 | Phase 4                                               |
| R3  | PARTIAL | `crates/soglia-core/src/config.rs:61-104,169-190`; `crates/soglia-supervisor/src/supervisor.rs:180-186`; `crates/soglia-enforcer/src/cgroup_bpf.rs:1294-1306` | B4 and B7                      | Invocation, Resolve and BPF bounds exist, but accepted proxy tasks, several in-memory registries, configuration collections and journal retention have no declared defensive bound. | Phase 2, completed in Phases 3-4                      |
| R4  | PARTIAL | `crates/soglia-core/src/config.rs:318-343`; `crates/soglia-sandbox/src/backend.rs:779-797`                                                                    | H4; B7                         | Per-Execution cgroup limits are applied, but capacity is not reserved against host memory and disk before admission; disk has no quota or reservation model.                        | Phase 3                                               |
| R5  | PARTIAL | `crates/soglia-supervisor/src/supervisor.rs:307-329`; `crates/soglia-supervisor/src/helpers.rs:423-471`; `crates/soglia-sandbox/tests/runc.rs:196-212`        | T9; B4 and B7                  | Full queues and Resolve saturation refuse predictably, but memory exhaustion is still detected after the cgroup OOM event and disk/pool budgets are not modeled.                    | Phase 2 for queues; Phase 3 for memory and disk       |
| R6  | PARTIAL | `crates/soglia-sandbox/src/backend.rs:575-610`; `crates/soglia-enforcer/src/backend.rs:688-715`                                                               | T6-T8; B6, B7 and uninstall    | Bundle and network objects are removed and verified, but private volumes and ephemeral encryption keys do not exist yet and therefore have no immediate deletion proof.             | Phase 3, extended in Phase 6                          |
| R7  | PARTIAL | `crates/soglia-sandbox/src/backend.rs:38-43,873-889,985-998`; `src/main.rs:214-219`                                                                           | Agent relay unit behavior only | Agent output emission is capped at 64 KiB, but tracing writes to stderr and the repository declares no journal size, rotation, rate or retention budget.                            | Phase 4                                               |
| R8  | PARTIAL | `crates/soglia-supervisor/src/supervisor.rs:180-186`; `crates/soglia-sandbox/src/backend.rs:985-998`; `spikes/cgroup-bpf/REPORT.md:1101-1108`                 | B7                             | Execution concurrency bounds many live objects, but accepted connection tasks are unbounded and no long soak proves stable RSS, threads and FDs under admitted and refusal load.    | Phase 2 for connection bounds; Phase 4 for soak proof |

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

| Structure                      | Reference                                                                                           | Growth path                                                                                      | Required closure                                                          |
| ------------------------------ | --------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------- |
| Ingress connection tasks       | `crates/soglia-proxy/src/ingress.rs:81-119`                                                         | Every accepted TCP connection gets a new Tokio task before invocation admission.                 | Add a connection semaphore and typed saturation in Phase 2.               |
| Egress connection tasks        | `crates/soglia-proxy/src/egress.rs:145-163`                                                         | Every accepted proxy socket gets a new Tokio task before attribution completes.                  | Bound accepted and pending-attribution connections in Phase 2.            |
| IP attribution map             | `crates/soglia-proxy/src/attribution.rs:100-105,123-132`                                            | `HashMap<IpAddr, Entry>` has no local ceiling and relies on correct lifecycle admission.         | Enforce and assert a ceiling derived from `max_concurrency` in Phase 2.   |
| Candidate-A binding map        | `crates/soglia-proxy/src/attribution.rs:100-105,164-178`                                            | `HashMap<BindingKey, Entry>` has no local ceiling and relies on teardown.                        | Enforce the same declared ceiling and health-check it in Phase 2.         |
| Sandbox live registry          | `crates/soglia-sandbox/src/backend.rs:186-200,439-450`                                              | The in-memory map has no defensive capacity check of its own.                                    | Tie it explicitly to admission plus cleanup quarantine in Phase 3.        |
| nft backend live registry      | `crates/soglia-enforcer/src/backend.rs:328-368`                                                     | The in-memory map has no defensive capacity check of its own.                                    | Reject before insertion above the declared execution capacity in Phase 3. |
| cgroup-BPF live registry       | `crates/soglia-enforcer/src/cgroup_bpf.rs:116-129,350-378`                                          | The in-memory map is indirectly bounded by policy capacity but does not enforce a local ceiling. | Make the bound explicit and observable in Phase 2 or 3.                   |
| Agent configuration maps       | `crates/soglia-core/src/config.rs:55-58,281-315`                                                    | Agent count and each environment-map size have no item-count ceiling.                            | Add validated count and encoded-byte ceilings in Phase 3.                 |
| Destination policy collections | `crates/soglia-core/src/config.rs:129-142,194-232`; `crates/soglia-proxy/src/policy/mod.rs:120-159` | Allow rules, ports, internal ranges and resolved address lists have no declared item ceiling.    | Add validated policy and DNS-answer ceilings in Phase 2 or 5.             |
| Runtime stderr and journal     | `src/main.rs:214-219,292-298`                                                                       | Structured logs go to stderr with no repository-owned rotation or retention contract.            | Add rate, size and retention policy in Phase 4.                           |

The in-memory lifecycle registries are indirectly constrained by Supervisor admission today.
They remain listed because R3 requires each component to reject excess state locally rather than depend only on an upstream invariant.

No production cache was found.
Introducing image, template, connector, credential or snapshot caches requires a declared entry count, byte budget, expiry rule and saturation behavior before implementation.

## Tests serialized with `--test-threads=1`

The CI currently serializes every workspace unit test at `.github/workflows/ci.yml:43-46`.
The privileged acceptance runner separately serializes ignored tests for both backends at `dev/linux/acceptance.sh:17-23`.
Those two uses have different causes and should not be treated as one permanent constraint.

| Test or suite                                                                  | Shared state or contention                                                                                                                       | Current isolation                                                                                                           | Required isolation                                                                                                                                          |
| ------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `concurrent_missing_tuples_timeout_without_a_health_failure`                   | No mutable application state is shared, but its 40 ms wall-clock publication deadline competes for the OS scheduler and Tokio blocking pool.     | Global `--test-threads=1`; the test itself uses a private socketpair at `crates/soglia-supervisor/src/helpers.rs:978-1028`. | Use an injectable or paused clock plus explicit mock-resolver barriers, then restore parallel unit tests.                                                   |
| `pending_after_the_publication_deadline_times_out_without_poisoning`           | Private socketpair, real 20/60 ms sleeps and scheduler timing.                                                                                   | Global serialization; source at `crates/soglia-supervisor/src/helpers.rs:1030-1088`.                                        | Drive a deterministic clock and signal when the exchange starts.                                                                                            |
| `complete_after_the_publication_deadline_is_still_consumed`                    | Private socketpair, real 20/60 ms sleeps and scheduler timing.                                                                                   | Global serialization; source at `crates/soglia-supervisor/src/helpers.rs:1090-1132`.                                        | Replace sleeps with clock advancement and explicit response barriers.                                                                                       |
| `a_cancelled_caller_cannot_desynchronize_the_next_exchange` and watchdog tests | Private socketpair and real sleep/watchdog deadlines share only scheduler capacity.                                                              | Global serialization; source at `crates/soglia-supervisor/src/helpers.rs:1134-1192,1234-1264`.                              | Use deterministic coordination and keep each protocol test isolated in its own client/server pair.                                                          |
| Phase-0 T1-T10/H1-H4                                                           | Fixed ports, `/run/soglia-phase0`, one process singleton, fixed cgroup root, `soglia0`, `upstream0`, nftables and test services are host-global. | The module documents one-at-a-time execution at `tests/phase0.rs:4-19`; constants are at `tests/phase0.rs:38-48`.           | Keep one suite per disposable privileged VM/container, or parameterize every host resource and give each test a private runtime process and cgroup subtree. |
| `the_sandbox_isolates_classifies_and_cleans_up`                                | Delegated cgroup hierarchy, runc state, `/run/netns`, veth and nftables are kernel-global.                                                       | One ignored privileged test at `crates/soglia-sandbox/tests/runc.rs:107-120`.                                               | Run in its own disposable privileged container or VM with a unique delegated root.                                                                          |
| `netns_nft` privileged test                                                    | It owns fixed `soglia0`, `inet soglia_host`, netns and veth objects.                                                                             | The test declares itself sequential at `crates/soglia-enforcer/tests/netns_nft.rs:4-12`.                                    | Run in its own network namespace plus unique object names, or retain suite-level VM isolation.                                                              |

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

| Phase         | Required new evidence                                                                                                                              |
| ------------- | -------------------------------------------------------------------------------------------------------------------------------------------------- |
| Phase 2       | Independent bounds for ingress, egress and Resolve; exact saturation outcomes; stable connection-task and FD counts; no side effects for refusals. |
| Phase 3       | I1-I8 negative and positive matrix; OCI digest/signature provenance; private-volume isolation and deletion; I/O and aggregate resource budgets.    |
| Phase 4       | Pool claim and destroy latency distributions; crash matrix; 24-hour soak; resource-slope and 60-second-baseline verdicts.                          |
| Phase 5       | CA, Credential Anchor, PIC and Connector trust boundaries; request-level authorization; destination-mode downgrade tests.                          |
| Phase 6       | gVisor and Firecracker profile-specific isolation, TAP enforcement, VMM confinement, encrypted-disk key deletion and snapshot uniqueness.          |
| Cross-profile | The aggregate `spike:qualify` verifier, dual-backend regressions and clean-environment CI on one release commit.                                   |

## Audit verdict

The Phase 1 platform is a qualified one-shot runc execution path with strong network enforcement and verified teardown.
It is not yet the complete execution platform defined by I1-I8 and R1-R8.
The required order is Phase 2 bounds, Phase 3 isolation and reservation, then Phase 4 long-run proof; later profiles must reuse the invariants rather than weaken them.
