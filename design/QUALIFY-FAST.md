<!-- Copyright (c) 2022 Nitro Agility S.r.l. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Fast aggregate qualification

## Status and scope

Status: `APPROVED`.

This design shortens `spike:qualify` without weakening any qualification property.
It changes the host orchestration only; gate scripts, verifier rules, evidence formats and production code are unchanged.

## Where the time goes today

Every gate creates a fresh Lima VM from the base cloud image and then, inside that VM:

1. installs the build and test packages with `apt-get`;
2. installs the pinned Rust toolchain and the musl target;
3. builds the spike runner, the spike agent and the production `soglia` binary in release mode;
4. builds `soglia` again with the gate's features where the gate requires it;
5. runs the gate.

Steps 1 to 4 repeat identically nine times and dominate the roughly fifty-minute run.
The nine gates also run strictly one after another.

## Design

### 1. A content-addressed base VM

A base VM is provisioned once from `lima.yaml` and `provision.sh` and then stopped.
Its identity is the SHA-256 of the rendered Lima configuration, `provision.sh`, the pinned toolchain version and the package list resolved by `apt-get`.
The identity is recorded in the base VM's metadata and in every gate's `environment.txt`.

Each gate starts from `limactl clone` of the stopped base VM.
A clone has its own disk, kernel boot and runtime state, so each gate still begins from a never-used guest with no Soglia state, no BPF objects, no cgroups and no network objects of a previous gate.
The base VM itself never runs a gate and never mounts evidence.

A base VM whose recorded identity differs from the current inputs is rebuilt, never reused.
A base VM that is running, missing its identity record or carrying any Soglia state is rejected before cloning.

### 2. One build for the whole run

A single build VM, cloned from the base, builds every binary the gates need exactly once, from the clean commit under qualification:
the spike runner and helpers, the musl spike agent, the production `soglia` binary for every feature set the gates use, and the config preflight validator.

The build writes a manifest with the commit, the empty working-tree diff fingerprint, `Cargo.lock` digest, toolchain version, target triple and the SHA-256 of every binary.
The binaries are copied into a read-only artifact directory outside the repository tree and are mounted read-only into each gate VM.
Each gate verifies every binary against the manifest before use and records the manifest digest in its evidence.

This is stricter than today: all gates provably exercise the same production binary, and the aggregate verifier checks that every gate records the same manifest digest.

### 3. Bounded parallel gates

Gates are scheduled in two classes:

| Class       | Gates                        | Reason                                                     |
| ----------- | ---------------------------- | ---------------------------------------------------------- |
| Parallel    | B1, B2, B4, B5, UNINSTALL    | Functional checks with no timing or load thresholds        |
| Exclusive   | B3, B6, B7, B8               | Races, watchdog windows, latency and load measurements     |

At most three parallel-class gates run at the same time, each on its own clone with the unchanged four CPUs and 8 GiB.
Exclusive-class gates run alone, with no other qualification VM running, so their timing and load evidence is not distorted.
Each gate's evidence records the concurrency class and the number of qualification VMs running during its window.

### 4. Fail-fast with complete evidence

The first non-PASS result stops scheduling.
Gates already running finish and keep their evidence, so a failure never destroys the diagnostic record of a concurrent gate.
The run reports every gate as `PASS`, `FAIL`, `INFRA_ERROR` or `NOT_EXECUTED`.
Every clone is deleted after its gate, and the run fails if any qualification VM other than the stopped base VM remains.

## Unchanged properties

- The clean-tree requirement, the production baseline check and the harness fingerprint stay as they are.
- Config preflight still runs before any VM starts.
- Every gate still runs on a guest that has never run another gate.
- Every gate still measures residue before harness teardown.
- The aggregate verifier still requires one run per gate, one production baseline and one harness fingerprint, and now also one build manifest.

## Qualification of the change

The fast orchestrator is accepted only after one fast run and the current sequential run on the same commit both return `PASS` with the same gate set, the same production baseline and the same per-case verdicts.
The fast run must also show zero lingering clones and identical binary digests across all gates.

## Expected effect

| Step                            | Today            | Fast                     |
| ------------------------------- | ---------------- | ------------------------ |
| Packages and toolchain per gate | Every gate       | Once per base            |
| Release builds                  | About 4 per gate | Once per run             |
| Gate scheduling                 | 9 sequential     | 3 parallel + 4 exclusive |
| Total wall time                 | About 50 minutes | About 15–20 minutes      |

## Approved decisions

1. Clone a provisioned base VM per gate instead of provisioning a fresh cloud image per gate.
2. Build once per run and verify binaries by manifest in every gate.
3. Run B1, B2, B4, B5 and UNINSTALL up to three at a time, and B3, B6, B7 and B8 alone.
