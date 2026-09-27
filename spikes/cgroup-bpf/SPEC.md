<!-- Copyright (c) 2022 Nitro Agility S.r.l. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Reproducible cgroup-BPF spike specification

## Scope and trust model

The suite qualifies the Phase-1 cgroup-BPF design on an observed Linux kernel.
It does not select attribution Candidate A, B, C or D, implement the production `CgroupBpfBackend`, run B1-B7, or move proxy steering and final-destination enforcement into BPF.

The Rust guest runner is the sole authority for test order, observations, assertions, verdicts, evidence, ownership and cleanup.
The macOS layer owns only Lima lifecycle, provisioning, guest-side builds, runner invocation and exit-code propagation.
Agent output is an experimental stimulus and is never a trusted identity source.
IP and veth identity may be recorded as cross-checks but never authorize a proxy request.
nftables remains the final destination barrier; BPF supplies early deny, attribution and fail-closed hardening.

## Run modes

Authoritative mode is exactly `soglia-spike-runner run` without selection flags.
It requires every test to be implemented, a pristine VM contract, no previous authoritative marker and canonical S0 through S14 execution.
The marker is root-owned under `/var/lib/soglia-spike-runner/` and is published before the first security experiment.

Diagnostic mode includes `doctor`, `run --only <test>` and `run --from <test>`.
Diagnostic evidence always contains `authoritative: false` and can never constitute a complete replay.
Development proceeds incrementally: a test must pass diagnostically before implementation starts on its successor.
The reusable-development host wrapper rejects an unselected `run`; the
authoritative command shape is reserved to the fresh-VM wrapper.

## Classification

- `PASS`: the required invariant was causally proven.
- `FAIL`: an observation contradicted the required invariant.
- `UNPROVEN`: the observations could not causally establish the invariant.
- `UNSUPPORTED`: a required kernel or environment capability was unavailable.
- `INFRA_ERROR`: tooling, build, filesystem or provisioning prevented a valid security observation.
- `CLEANUP_FAIL`: test observations completed but owned residue could not be proven absent.
- `NOT_EXECUTED`: the test was after the fail-fast stop point or outside a diagnostic selection.

`UNSUPPORTED` is distinct from `FAIL`, but both stop an authoritative run and neither is success.

The stable process exit contract is `0` for requested complete PASS, `10` for FAIL, `11` for UNPROVEN, `12` for CLEANUP_FAIL, `13` for INFRA_ERROR, `14` for an internal runner bug and `15` for UNSUPPORTED.

## Test lifecycle

Every test follows this state machine:

```text
PREPARE
  -> VERIFY_PRECONDITIONS
  -> EXECUTE
  -> CAPTURE_OBSERVATIONS
  -> VERIFY_INVARIANTS
  -> CAPTURE_FINAL_EVIDENCE
  -> CLEANUP_OWNED_RESOURCES
  -> VERIFY_CLEANUP_INDEPENDENTLY
  -> NEXT_TEST
```

The first non-PASS result is immutable evidence.
The controller preserves it, performs scoped cleanup, records cleanup independently, marks later tests `NOT_EXECUTED` and exits non-zero.
Security observations are never retried automatically.
Only bounded SSH or package-repository readiness retries may occur before a security test starts, and each retry is evidence.

## Command evidence

Every external command passes through one `CommandExecutor`.
It records a monotonically increasing sequence, executable, argv, working directory, selected environment, wall-clock and monotonic start, duration, exit status or signal, timeout, stdout and stderr.
Machine-readable tool modes are used where available and parsed into Rust types or strongly typed test observations.
Human-readable strings such as `PASS` are not verdict inputs.

## Resource ownership and cleanup

The central `ResourceRegistry` records every process, process group, cgroup, namespace, interface, nft object, BPF program/link/map/pin, runc container, socket, temporary directory and S13 ownership record created by a run.
Each entry contains a run/test owner and concrete provenance.
Cleanup addresses only exact registered resources.
Unknown resources are never removed by prefix or wildcard and instead cause a fail-closed classification where relevant.

After every test, the runner observes kernel and filesystem state again and proves absence of owned processes, cgroups, runc state, netns, links, nft state, BPF objects, pins, attribution entries and ownership metadata.
A successful security assertion followed by unverifiable cleanup is `CLEANUP_FAIL`.

Signals and panics notify controller-level cleanup; complex cleanup never runs in a raw signal handler.
Evidence already persisted is retained.

## Evidence model

Each run writes incrementally under `evidence/replay/<run-id>/`.
The root contains `run.json`, `environment.json`, `source.json`, per-test directories, final cleanup/environment snapshots, `summary.json` and `summary.md`.
Each command has JSON metadata and separate raw stdout/stderr files.
Atomic publication prevents a partially written JSON document from replacing the last complete observation.

Source evidence includes repository commit and dirty state, relevant source hashes, Cargo lock hash, runner and agent hashes, every BPF object hash, environment fingerprint and Lima configuration hash.

## Delegation

Provisioning installs and enables prerequisites but does not establish S0 by assumption.
S0 itself asks systemd for a delegated transient unit, moves the service process into a leaf to satisfy the cgroup-v2 no-internal-process rule, enables required child controllers and verifies the actual unit properties, cgroup paths, ownership, modes, controller files and process placement.

## Canonical order and invariants

The order is S0, S1, S1b, S2, S3, S4, S5, S6, S7, S8, S9, S10, S11, S12, S13 and S14.
The invariant of each test is the one established in the historical final report and summarized in `MIGRATION.md`.
S6 derives its synthesis only from structured S1-S5 observations.
S8 tests the current production fix, not a reconstructed vulnerable version.
S10 is a hard gate for nft final-destination enforcement.
S13 uses the final spike-only ownership and compatibility contract, while preserving the original historical failure in the archive.
S14 characterizes Candidate C without selecting it or raising `RLIMIT_NOFILE`.

## Reproduction completion

One complete authoritative PASS is followed, without code changes, by the same bootstrap and run on a second newly created VM.
Only after both independent fresh-VM replays pass may a separate human review compare the historical spike and the two replays or consider A/B/C/D.
