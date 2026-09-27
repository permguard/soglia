<!-- Copyright (c) 2022 Nitro Agility S.r.l. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Historical-to-reproducible migration map

The archive at `../cgroup-bpf-old/` is immutable reference evidence.
Copied BPF C and agent sources begin byte-identical to the archive; differences must be explicit in review.
Old shell runners are not runtime dependencies.

| Test | Historical implementation and evidence                      | New Rust authority                                                                                  | Incremental gate |
| ---- | ----------------------------------------------------------- | --------------------------------------------------------------------------------------------------- | ---------------- |
| S0   | S0 loader, delegation script, S0.3-S0.5 report/evidence     | Environment probe, actual systemd delegation, six links, ancestor exclusive/multi and cleanup      | First            |
| S1   | `s1_attribution.rs`, `run-s1.sh`, final port-fixed evidence | Placement, maps, tuple, accept and bounded Resolve as typed observations                            | After S0 PASS    |
| S1b  | Delayed variant in S1 harness                               | Delayed publication and missing-publication timeout without application/DNS/effect processing      | After S1 PASS    |
| S2   | `s2_concurrency.rs`, `run-s2.sh`                            | Concurrent Execution/socket identity matrix and mismatch/cross-attribution assertions              | After S1b PASS   |
| S3   | S1 harness modes and `run-s3.sh`                            | FIN/RST/kill/generation/tuple-reuse lifecycle                                                       | After S2 PASS    |
| S4   | `s4_direct_deny.rs`, `run-s4.sh`                            | Narrow nft relaxation, BPF deny causality and permissive control                                    | After S3 PASS    |
| S5   | `s5_hook_isolation.rs`, `run-s5.sh`                         | Six hook-specific variants, publication omission and fail-closed assertions                         | After S4 PASS    |
| S6   | `run-s6.sh` and enforcement table                           | Deterministic synthesis from stored structured S1-S5 observations                                   | After S5 PASS    |
| S7   | `s7_pinned_loader.rs`, `run-s7.sh`                          | Abrupt loader loss, retained pinned enforcement and causal unpin control                            | After S6 PASS    |
| S8   | `run-s8.sh` and current production helper supervision       | Kill real Enforcer child, observe autonomous cancellation/termination and restart-before-readiness | After S7 PASS    |
| S9   | foreign allow and `run-s9.sh`                               | Invoked ancestor ALLOW, child DENY and permissive child control                                     | After S8 PASS    |
| S10  | `s10_rewrite.rs`, foreign rewrite, `run-s10.sh`             | Real rewrite, normal nft denial and exact exposure success hard gate                                | After S9 PASS    |
| S11  | `run-s11.sh`                                                 | Representative full topology and exact zero-residue inventory                                       | After S10 PASS   |
| S12  | `s12_exhaustion.rs`, small-map variant                      | Proven-full maps, update failure, fail-closed Resolve and freed-entry control                       | After S11 PASS   |
| S13  | `S13-CONTRACT.md`, `run-s13-v2.sh`, state manager           | Trusted external ownership, compatibility, generation, crash boundaries and readiness ordering     | After S12 PASS   |
| S14  | `s14_scaling.rs`, `run-s14.sh`                              | N=1/4/16/32 correctness and untuned N=64 resource characterization                                  | Last             |

## Preserved source baseline

The following new files were initially copied byte-for-byte from the archive:

- `bpf/soglia_spike.c`;
- `bpf/foreign.c`;
- `bpf/netns_probe.c`;
- `bpf/gpl_probe.c`;
- `bpf/gpl_probe_kfunc.c`;
- `agent/src/main.rs`.

The orchestration is intentionally not copied: command execution, assertions, evidence, ownership, cleanup and verdicts move into `soglia-spike-runner`.

The S2 kernel/concurrency stimulus began as a byte-identical migration of historical
`harness/src/bin/s2_concurrency.rs` into `runner/src/bin/s2_helper.rs`. The parent
runner owns its topology, barriers, independent placement/attach snapshots,
typed metric verification, cleanup and verdict; subsequent helper differences
must remain explicit in review. System-tool invocations retained inside the
migrated stimulus execute through the runner's Rust `CommandExecutor`
abstraction into a dedicated evidence scope; they no longer escape recording.

The S5 hook-isolation stimulus likewise began as a byte-identical migration of
historical `harness/src/bin/s5_hook_isolation.rs` into
`runner/src/bin/s5_helper.rs` (SHA-256
`142cacaa155d95d30fc0bca5cb3d174a813969ba7181f2303d2470af625a377b`).
The parent runner owns the delegated cgroup and dual-stack network topology,
parses and independently asserts every phase's membership, attachment counts,
deny/delivery counters and fail-closed sockops behavior, then verifies and owns
final cleanup. Subsequent helper differences must remain explicit in review.
Its agent launcher and `bpftool` observations likewise use the shared
command-recording abstraction under the `s5/helper` evidence scope.

The S7 long-lived pinned loader began as a byte-identical migration of
historical `harness/src/bin/s7_pinned_loader.rs` into
`runner/src/bin/s7_loader.rs`. The parent runner owns topology, sends and
observes `SIGKILL`, compares kernel/link/pin identity, performs both direct-path
attempts, removes only the recorded `connect4` pin, and owns cleanup/verdict.

S8 deliberately preserves the proven historical `run-s8.sh` experiment's
three-Execution timing, real production Supervisor/Enforcer lifecycle, SIGKILL
event, no-RPC autonomous-detection oracle, bounded no-effect observation, and
restart sweep ordering. It is translated into the authoritative Rust test
instead of wrapping the shell runner. The test builds and invokes the current
production `soglia` binary from source and does not modify production behavior.

S9 reuses the already-validated S4 direct-deny and permissive-control stimulus,
but the Rust parent now loads and attaches only historical `foreign_allow` in
legacy MULTI mode at the fresh ancestor. It records exact foreign identity,
effective composition, the foreign ring-buffer chronology, child deny evidence,
the permissive child control, nft restoration and cleanup. It makes no relative
execution-order claim from bpftool listing order.

The S14 scaling loader began as a deliberate Aya-based migration of the
historical Candidate-C characterization. It preserves per-Execution object
loading and local `exec_ident`/`policy_local` semantics while the parent runner
owns every N=1/4/16/32/64 topology, membership proof, resource assertion,
bounded-limit classification and exact cleanup. This characterization does not
select Candidate C.
