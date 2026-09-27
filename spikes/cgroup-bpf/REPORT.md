<!-- Copyright (c) 2022 Nitro Agility S.r.l. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Second-generation cgroup-BPF spike status

## Scope

This report covers the reproducible runner only. The historical spike and all of its evidence remain preserved at `../cgroup-bpf-old/`; its aggregate SHA-256 is `7150364722a56cab1c64809872d2fbf4a7747df7b36eb32925fcf30aa2e3ddbc`.

No new production behavior has been implemented, Candidate A/B/C/D has not been selected, and B1-B7 are out of scope.

## Development qualification

Incremental diagnostic development on the reusable `soglia-spike-dev` VM reached PASS in canonical order for S0, S1, S1b and S2 through S14. Earlier diagnostic failures and their evidence were retained rather than overwritten.

The complete integrated development replay `replay-1790517271938-71024` passed S0 through S14 and per-test cleanup. Subsequent pre-authoritative hardening adds:

- complete source, helper, production-binary and BPF-artifact hashing;
- tool-version and full artifact preflight evidence;
- independently recorded final environment and exact resource cleanup audits;
- command evidence for system-tool invocations inside the deliberately migrated S2 and S5 helpers;
- the explicit S13 ownership/recovery contract.

The final complete diagnostic replay `replay-1790518767981-110562` ran with
`authoritative: false` and passed all 16 tests, every per-test cleanup check, the
883-entry global resource audit, and the final environment recheck. Its source
manifest contains 84 hashes.

An earlier unselected invocation on the reused development VM was correctly
excluded from authoritative qualification: that VM was not fresh and the run
did not complete cleanly. The development wrapper now rejects the authoritative
command shape, preventing recurrence. Its evidence remains preserved.

## Authoritative replay status

Two independent, completely fresh VMs ran the same bootstrap and unchanged test
implementation in sequence. Replay #2 started only after replay #1 completed with
PASS.

| Replay | Fresh VM | Evidence | Result | Final cleanup |
| --- | --- | --- | --- | --- |
| #1 | `soglia-spike-replay-20260927T142235Z-16255-r1` | [`replay-1790519024728-5762`](evidence/replay/replay-1790519024728-5762/) | S0-S14 PASS | PASS |
| #2 | `soglia-spike-replay-20260927T142235Z-16255-r2` | [`replay-1790519492492-5783`](evidence/replay/replay-1790519492492-5783/) | S0-S14 PASS | PASS |

Both summaries record `authoritative: true`, all 16 test results and every
per-test cleanup as PASS. Each final cleanup audit checked 883 registered
resources, found zero live entries, and independently proved both run-owned
roots absent. Each VM's root-owned pristine marker names only its own replay
run ID.

The environment fingerprint matched across the two VMs: Ubuntu 24.04.4 LTS,
Linux 6.8.0-134-generic, aarch64, cgroup v2, bpffs and BTF present, effective
UID 0, and soft/hard `RLIMIT_NOFILE` 1024/1048576. The complete environment and
tool versions are in each replay's `environment.json` and
`final/environment-after.json`.

The two `source.json` records have the same repository commit
`b89c06be3228163887251bf04162abe8801fdebb`, the same truthfully recorded dirty
state, and exactly equal 84-entry source/artifact hash maps. Principal artifact
hashes are:

| Artifact | SHA-256 |
| --- | --- |
| runner | `7bfc06b5baf46a41108cbea8f48272324f5a09d604b9d868c3f763d7a4dd3ee5` |
| agent | `1062d1662bb39199f3e50ed1eb5ee91713c113c10be42e5a5a1c27a104c31bf2` |
| production `soglia` used by S8 | `1485d030c53b79269fe10de079dc4f4a55062217e5154008960231829dceaa83` |
| primary `soglia.o` | `31ae126f1e0d1b1baf4430402527673e7dfdca6f527228d9d9acf4fa037b1b31` |

The full list covers all built helpers and BPF variants and remains in both
source manifests. This report update was made after both replays; the manifests
therefore preserve the exact pre-update report hash
`d90a1359265dd09bd23971aa67e72b93af6bc6b0e880b0ec9ed5ab819bd91f9f`.
No executable source changed between or after the replay pair.

## Historical measurement drift

No material S14 resource-model drift was observed. Both replays reproduced
`programs=6N`, `links=6N`, `maps=8+2N`, `pins=8+6N`, and a 23-FD increase per
complete instance. N=1/4/16/32 passed with correct attribution and zero
cross-attribution. With the unchanged soft FD limit, N=64 again reached
`EMFILE` during object-map creation for instance index 44 after 44 complete
instances and 1016 open FDs. The particular map name at the exhaustion point
varied (`soglia_events` in replay #1 and `soglia_denies` in replay #2), as it
did historically with map-processing order; the limiting operation, boundary,
errno and cleanup result were unchanged.

That pair satisfied the gate for the runner revision used at the time. It is
retained as historical evidence, but the runner corrections below invalidate it
as the current required pair. Historical-vs-replay candidate review has not
been performed here: A/B/C/D remains unselected and B1-B7 remains unstarted.

## Replay-runner corrections after the first pair

The later authoritative replay
`replay-1790520827139-5753` remains a failed run. Its S1 cleanup reported
`CLEANUP_FAIL` even though every Soglia-owned unit, cgroup, namespace,
interface, nft object, pin and runtime path was absent. The before/after BPF
inventories showed that links and maps were identical and that only the 12
systemd-owned `sd_*` programs had been reloaded: IDs 162-173 became 184-195
while each program's name, type and tag and the complete `(name,type,tag)` set
were unchanged. This is the same external systemd churn characterized by the
historical spike, not test-owned residue.

Cleanup now identifies test-owned BPF programs, links and maps from the
`ResourceRegistry` entries recorded with creation provenance, additionally
rejects every residual `soglia_*` program and checks the run-owned pin root.
The full link and map inventories remain strict. Program-ID replacement is
accepted only for the narrow `sd_*` case where the complete stable systemd
program objects excluding ID are equal and every non-systemd program is equal.
The assessment and both systemd ID sets are written into `s1/cleanup.json`; an
accepted replacement is surfaced as `EXTERNAL_CHURN` in `s1/result.json` and
the run summary. Unknown, new or missing programs, a changed tag, any link or
map difference, and any registered owned object still present remain cleanup
failures.

The diagnostic replay `replay-1790523164709-7446` exercised the corrected path
on the reusable development VM. S1 and final cleanup passed while systemd again
replaced exactly 12 `sd_*` programs, IDs 100-111 with 122-133. The stable
systemd objects, non-systemd programs, links and maps were equal and the owned
object set was empty, so the evidence records `EXTERNAL_CHURN` rather than
test residue.

The silent authoritative run `replay-1790520483455-125400` stopped after its
completed preflight command 21 (`df -Pk /var/tmp/soglia-spike-2`) and before a
source command record or `source.json` was persisted. Its initiating external
event cannot be recovered: the old runner recorded neither a durable current
phase nor an interruption/error outcome at that boundary. The missing-state
defect was structural: pre-test errors could propagate out of `run` without a
finalizer, and no provisional state existed before fallible setup and source
collection.

Every new run now atomically creates `state.json` before fallible setup with a
non-terminal `INTERRUPTED` outcome. It checkpoints current phase and test,
command start/spawn failure/completion, and the complete owned-resource
registry. Normal completion records `COMPLETE`; propagated errors and panics
are finalized as terminal `INFRASTRUCTURE_FAILURE`/`INFRA_ERROR` with a summary
and final resource snapshot. SIGINT, SIGTERM and SIGHUP are registered, while
an uncatchable process or VM loss leaves the last durable state as
`INTERRUPTED` rather than producing a silent directory.

A controlled diagnostic failure, `replay-1790523202124-7964`, verifies this
path: it records terminal `INFRASTRUCTURE_FAILURE`, verdict `INFRA_ERROR`, phase
`SOURCE_COLLECTION`, command 22 (`git rev-parse HEAD`) as `SPAWN_FAILED`, an
empty owned-resource registry, `summary.json`, and `final/resources.json`.

The real-inventory classifier tests use the preserved 0078/0117 program,
0079/0118 link and 0080/0119 map JSON. They cover the accepted systemd churn
and rejection of an extra `soglia_*` program, extra cgroup link, changed tag,
unknown new program and missing non-owned program. Journal tests cover the
initial durable `INTERRUPTED` record and terminal infrastructure state with
phase, last command and resources. All eight tests pass on the Linux
development VM.

Because these are runner changes, no earlier PASS counts toward the replacement
pair, including `replay-1790520608391-5782`.

The replacement `task spike:replay` then completed without code changes between
the two runs:

| Replay | Fresh VM | Evidence | Result | Final cleanup |
| --- | --- | --- | --- | --- |
| #1 | `soglia-spike-replay-20260927T153509Z-69980-r1` | [`replay-1790523372183-5774`](evidence/replay/replay-1790523372183-5774/) | S0-S14 PASS | PASS |
| #2 | `soglia-spike-replay-20260927T153509Z-69980-r2` | [`replay-1790523817983-5789`](evidence/replay/replay-1790523817983-5789/) | S0-S14 PASS | PASS |

Both summaries are authoritative and contain 16 PASS results with PASS cleanup.
Both journals are terminal `COMPLETE`/`PASS`; each final audit independently
checked 1299 registry entries, found zero live entries and proved both run-owned
roots absent. S1 reproduced the reported 162-173 to 184-195 systemd replacement
on both VMs and recorded `EXTERNAL_CHURN`, equal non-systemd programs, strict
link/map equality and an empty owned-object set.

The two source manifests contain the same 93-entry hash map (canonical hash
`5d365f09b8ab9c3a909530a7458ee8f8519ae45f7086343eceb4593baad96288`)
and the same runner hash
`9203ee12fd7e72c8deca1ba93e22c271a27203a123cc1f0f715811e38ed15000`.
This post-run report update is not executable code; both manifests preserve its
pre-update hash `c8502f4e87a4269c2611473731d2a9a4617ded40f80a7eb079e6a4551faa222c`.

The replacement two-replay gate is satisfied. Candidate A/B/C/D remains
unselected; no candidate review was performed by this correction.
