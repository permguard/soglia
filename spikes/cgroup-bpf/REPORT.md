<!-- Copyright (c) 2022 Nitro Agility S.r.l. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Second-generation cgroup-BPF spike status

## Scope

This report covers the reproducible runner only. The historical spike and all of its evidence remain preserved at `../cgroup-bpf-historical/`; its aggregate SHA-256 is `7150364722a56cab1c64809872d2fbf4a7747df7b36eb32925fcf30aa2e3ddbc`.

No new production behavior has been implemented.
Candidate A was explicitly selected after the completed candidate review, and its production design and B1-B7 qualification gates are now documented in [PRODUCTION-DESIGN.md](PRODUCTION-DESIGN.md).

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

## Final comparative evidence review

Review date: 2026-09-27.

Final classification: `DRIFT` (non-material). The behavioral and security
invariants are `MATCH`; the explicitly bounded differences are classified
below. There is no `FAIL` or `UNPROVEN` result in the reviewed invariant set.

`REPRODUCIBILITY_CONFIRMED`

This review compares only the historical final S0-S14 evidence with the two
authoritative replays produced after the S14 cleanup correction. Intermediate
historical attempts, diagnostic runs, earlier replay pairs and the preserved
failed runs are not used as the historical baseline and do not count toward
the final pair.

### Reviewed replay pair

The host wrapper created two distinct VM names, rejected any pre-existing VM
with either name, provisioned and ran them sequentially, and printed `Two
independent fresh-VM replays completed.` The runner additionally accepted the
authoritative command only after atomically claiming an absent root-owned
pristine marker. The captured runs have distinct run IDs and each records
`requested_only: null`, `requested_from: null` and `authoritative: true`.

| Replay | Fresh VM | Evidence | Run result | Final audit |
| --- | --- | --- | --- | --- |
| #1 | `soglia-spike-replay-20260927T161150Z-98802-r1` | [`replay-1790525576624-5754`](evidence/authoritative/replay-1790525576624-5754/) | 16/16 PASS; terminal `COMPLETE/PASS` | PASS; 1,299 registry entries, zero live |
| #2 | `soglia-spike-replay-20260927T161150Z-98802-r2` | [`replay-1790525780260-5753`](evidence/authoritative/replay-1790525780260-5753/) | 16/16 PASS; terminal `COMPLETE/PASS` | PASS; 1,299 registry entries, zero live |

The final audits independently proved every registered resource and both
run-owned roots absent. The complete evidence-tree manifests contain 11,849
files with SHA-256
`b6d4b337f2e5f4615fad385e58f3202756f810c0b7ed7fac0aa8fb810ac9bbb8`
for replay #1 and 11,846 files with SHA-256
`e60ea6e03c2bd7c0898b060704e4a42d9ceba68797851ff9308addb0b032355b`
for replay #2. These are provenance hashes, not an expectation that dynamic
command evidence be byte-identical.

Both `source.json` files identify repository commit
`8272bb36d3229728089946427c674dd45be62da8`, contain 34,521 source/artifact
hash entries, and have an exactly equal canonical hash map. Its SHA-256 is
`828cfce90b0cc8be74340157cec9514c35f6dfd52d694db34c42d9c2a8de4e82`.
The runner hash is
`868102f8d8e71d0ec3ae8ae710b56d49a72501156d011931881b220a4f7213eb`;
the S14 implementation hash is
`581642acc884ef9fa669a2aafd0b42a207f29236d2b3d8373029efddf83e836d`.
Thus no executable or evidence input changed between replay #1 and replay #2.

### Historical baseline provenance

The historical baseline is exclusively the final evidence selected by the
historical report. For each row below, the manifest is the sorted sequence of
`SHA-256(file)  path`, with the path relative to `spikes/cgroup-bpf-historical/`; the
reported value is the SHA-256 of those manifest bytes.

| Test | Final historical evidence path | Files | Manifest SHA-256 |
| --- | --- | ---: | --- |
| S0 | [`evidence/s0`](../cgroup-bpf-historical/evidence/s0/) | 60 | `6f77c7a351f418f3744763fd39d5a49be0a6c559dd5b72d54d18609cce951c53` |
| S1 | [`evidence/s1/port-fixed`](../cgroup-bpf-historical/evidence/s1/port-fixed/) | 28 | `ec70717246cbddd7dcc9678c3d79d41397d5c9f0244303e6cdcedbfa7ef4c0f5` |
| S1b | [`evidence/s1b/race`](../cgroup-bpf-historical/evidence/s1b/race/) | 29 | `be6b7fc82356a1031c556fdf53d5359ea32f0c419e7124d22a4fa6202a27d3c8` |
| S2 | [`evidence/s2/run2`](../cgroup-bpf-historical/evidence/s2/run2/) | 32 | `1dbcdc8a5a338cf389059d6b6857b93ef5aa6b0951c6100ac48149adaf24ed2e` |
| S3 | [`evidence/s3`](../cgroup-bpf-historical/evidence/s3/) | 88 | `f535a3ed03eaf7e138ed533d8bcca542b6e415f2f70bcde57b0109c0f1f7c255` |
| S4 | [`evidence/s4/run2`](../cgroup-bpf-historical/evidence/s4/run2/) | 43 | `be8b7ea0abfe7f8e1f1a859610dfd16bdbe04e5d914acfb26d675a7f90b2e065` |
| S5 | [`evidence/s5/run3`](../cgroup-bpf-historical/evidence/s5/run3/) | 15 | `de54a808fb7f634a98ab80e0d1bcd0fbc71b034c12b57819a9eb2d08eee0186a` |
| S6 | [`evidence/s6`](../cgroup-bpf-historical/evidence/s6/) | 13 | `d92bb86574bb0bdeeb22ecdf93587292e6ed56250575a8975f1407be059864cf` |
| S7 | [`evidence/s7/run2`](../cgroup-bpf-historical/evidence/s7/run2/) | 39 | `af995971d8660faf538893167f6828f4c6096448eef7fe02bf046bb9e6eef149` |
| S8 | [`evidence/s8/after-fix-run6`](../cgroup-bpf-historical/evidence/s8/after-fix-run6/) | 91 | `41ac538e58f711b9fd9ba38eed2c8e86aacd99fece59114312ad65972f5f26f2` |
| S9 | [`evidence/s9/run4`](../cgroup-bpf-historical/evidence/s9/run4/) | 62 | `2be1f9120a34264a43065e61fc68bd2326b7c0ec1b29f419e8e6059195d7b7c6` |
| S10 | [`evidence/s10/run3`](../cgroup-bpf-historical/evidence/s10/run3/) | 73 | `8fb3684aafd84ba7a3f52a6ee34da2066b9e5532fc9423c43195265a6d6c039e` |
| S11 | [`evidence/s11/run1`](../cgroup-bpf-historical/evidence/s11/run1/) | 104 | `3d53036452daf1688c0edf8cb851ef68d9b7d8c7b225e7a96cd94bd67de1f633` |
| S12 | [`evidence/s12/run1`](../cgroup-bpf-historical/evidence/s12/run1/) | 47 | `541c2b9ae353bacd85c293dbad6c496218169a73a259a3366118ca791142854a` |
| S13 | [`evidence/s13/run2`](../cgroup-bpf-historical/evidence/s13/run2/) | 118 | `5eb2a0195d46a1b7202942c2a619cf572a522200b2cdb712e542c4561db317aa` |
| S14 | [`evidence/s14/run1`](../cgroup-bpf-historical/evidence/s14/run1/) | 316 | `054c3e4fa19060805625de12ef93cbca624eea7fe0d2457df6025fe59fe7f715` |

The union contains 1,158 unique files and has manifest SHA-256
`2d160644d87d7c4b08c59b2777309c60b18e6626c59c1617843aa78c75eb24c4`.
This selection excludes every historical intermediate or partial result.

During both final replays, the source manifest also captured a directory named
`spikes/cgroup-bpf/evidence_old/`. It was the archive of earlier
second-generation replay evidence, not the historical S0-S14 baseline above.
Each `source.json` records exactly 34,428 entries below that path. After
stripping the common prefix and sorting `relative-path<TAB>file-sha256`, both
recorded sets have manifest SHA-256
`d10944a6c4d24734d879999b6f0a9e9a397f36bfb5c16a0291fbd8455a4089d9`.
The identical path-and-content manifest proves its provenance and also proves
that it was unchanged between the two final replays. The path was subsequently
renamed back to `spikes/cgroup-bpf/evidence/`; it was not used as historical
input to this review.

### Environment fingerprints

| Fingerprint field | Historical final evidence | Replay #1 | Replay #2 | Classification |
| --- | --- | --- | --- | --- |
| OS / architecture | Ubuntu 24.04.4 LTS / aarch64 | same | same | `MATCH` |
| Kernel | `6.8.0-134-generic` | same | same | `MATCH` |
| BPF substrate | bpftool 7.4.0/libbpf 1.4; cgroup/BTF/bpffs proven by final tests | bpftool 7.4.0/libbpf 1.4; cgroup v2, BTF, bpffs true | same | `MATCH` |
| Clang / runc | clang 18.1.3; runc 1.3.4 | same | same | `MATCH` |
| FD limit relevant to S14 | soft 1,024 at the historical bound | 1,024 / 1,048,576 | 1,024 / 1,048,576 | `MATCH` |
| Additional historical fields | Lima 2.2.0, VZ, 4 CPU, 8 GiB, 40 GiB; Rust/Cargo 1.97.1; LLVM 18.1.3; Aya 0.14.0 | not recorded in authoritative `environment.json` | not recorded in authoritative `environment.json` | `DRIFT` (`FINGERPRINT_COVERAGE`) |
| Additional replay fields | not recorded in the historical fingerprint | uid 0; git 2.43.0; iproute2 6.1; nft 1.0.9; systemd 255 | identical | `DRIFT` (`FINGERPRINT_COVERAGE`) |

The overlap required by the tested kernel/BPF behavior matches. The coverage
asymmetry is recorded as drift rather than silently treating an unrecorded
field as equal; it does not contradict any raw measurement.

### S0-S14 comparison

| Test | Historical final invariant versus replay #1 and #2 | Classification |
| --- | --- | --- |
| S0 | delegation obtained and verified; six attaches and ancestor composition; owned cleanup | `MATCH` |
| S1 | live subject placement, six hook entries, tuple/cookie attribution, correct Resolve, fail-closed pre-resolution behavior | `MATCH` |
| S1b | 64 delayed publications resolve and one missing publication denies at the two-second bound without app/DNS/outbound/IP fallback | `MATCH` |
| S2 | 132 concurrent connections with unique attribution and zero mismatch/cross-attribution | `MATCH` |
| S3 | FIN, RST and kill lifecycle cases reject stale identity across inode/cookie/source-port reuse | `MATCH` |
| S4 | exact nft barrier relaxation exposes the control path while cgroup/connect4 prevents the BPF-denied direct path | `MATCH` |
| S5 | all six hooks are independently exercised; omission of sockops remains fail closed | `MATCH` |
| S6 | enforcement-layer synthesis remains evidence-derived and selects no candidate | `MATCH` |
| S7 | pinned links/maps preserve enforcement after loader SIGKILL; removing only connect4 exposes the controlled path | `MATCH` |
| S8 | autonomous Enforcer-loss detection, admission closure, agent/tunnel/runtime teardown, retained nft barrier and restart sweep-before-ready; no later RPC or post-loss effect | `MATCH` |
| S9 | foreign ancestor allow plus child deny, with permissive-child control and no unsupported ordering claim | `MATCH` |
| S10 | foreign rewrite composition is observed causally; normal and case-A paths do not establish, exact nft exposure admits only the rewritten case-B destination, and nft state is restored | `MATCH` |
| S11 | representative lifecycle removes all ten resource classes and restores the owned baseline | `MATCH` |
| S12 | capacity 8/8, overflow publication failure, unresolved deny with zero side effects, free-one recovery and correct control attribution | `MATCH` |
| S13 | trusted ownership record, exact compatible recovery, fail-closed incompatible/unknown handling, four crash boundaries, READY-last ordering and no stale authorization | `MATCH` |
| S14 | N=1/4/16/32 exact structural counts and correct sampled attribution; N=64 reaches the same 44-instance/1,016-FD `EMFILE` bound with complete cleanup | `DRIFT` (`EMFILE_ALLOCATION_SITE`) |

The critical S8, S10, S12 and S13 invariants are therefore `MATCH`. S14 is
deliberately classified `DRIFT`, not `FAIL`: all three evidence sets confirm
`programs=6N`, `links=6N`, `maps=8+2N`, `pins=8+6N`, the same successful
matrix points, the same bound at instance index 44 with 1,016 open FDs, and
complete cleanup. Only the map being created at exhaustion differs:
historically `soglia_cookie_a`, `soglia_counters` in replay #1 and
`soglia_events` in replay #2. This is the permitted allocation-site drift; the
structural model and security invariants are unchanged.

### Other bounded drift and cleanup attribution

| Observation | Classification | Effect |
| --- | --- | --- |
| S8 upper-bound timings: historical 109/119/125/130/131 ms versus 45/45/87/119/119 ms and 46/46/87/120/120 ms for detection/ingress/agents/tunnel/runtime | `DRIFT` (`TIMING_VARIATION`) | All required events remain bounded and ordered; no security invariant changes. |
| systemd `sd_*` program IDs are replaced during tests on both replay VMs | `DRIFT` (`EXTERNAL_CHURN`) | Stable `(name,type,tag)` multisets are equal; non-systemd programs, all links and maps are unchanged; every registered test-owned object is absent. |
| Dynamic kernel IDs, inodes, PIDs, timestamps and timing samples differ | `DRIFT` (`EPHEMERAL_IDENTITY`) | Expected fresh-run identity; comparisons use ownership, topology and semantic invariants rather than numeric reuse. |

No drift weakened an assertion. Links and maps retained strict inventory
comparison. Unknown or changed non-owned BPF objects would still have produced
cleanup failure; only the evidenced stable systemd replacement was classified
as external churn.

### Production and scope guard

The authorized S8 fail-closed lifecycle fix is part of the historical baseline
at commit `c5feded84de41c4845cbe7e4ceee82142380578b`. From that baseline through
current `HEAD`, the diff restricted to root `Cargo.toml`, `Cargo.lock`, `src/`,
`crates/` and `fixtures/` is empty. Both replay source records also contain zero
dirty entries in those production paths. The later changes are spike runner,
evidence migration and host orchestration only. Therefore the comparison finds
no new production modification after the authorized S8 baseline.

Candidate A/B/C/D remained unselected at the end of that reproducibility
review. That review did not start candidate review or B1-B7, and it made no
production change.

## Candidate review A/B/C/D

Review date: 2026-09-27.

Review status: `REVIEW_COMPLETE`. The evidence supports a non-binding technical
recommendation; final candidate selection remains an explicit subsequent human
decision.

### Evidence basis and limits

The authoritative basis is the final historical S0-S14 evidence selected in
the provenance table above plus both final authoritative replay roots:

- [`replay-1790525576624-5754`](evidence/authoritative/replay-1790525576624-5754/);
- [`replay-1790525780260-5753`](evidence/authoritative/replay-1790525780260-5753/).

Both replay summaries contain 16 PASS results and PASS cleanup, and their
candidate-relevant observations reproduce the historical final results. The
main raw historical references used below are:

| Evidence | Raw source |
| --- | --- |
| S1 trusted chain | [`s1/port-fixed/s1-harness.txt`](../cgroup-bpf-historical/evidence/s1/port-fixed/s1-harness.txt) |
| S1b delayed/missing publication | [`s1b/race/s1-harness.txt`](../cgroup-bpf-historical/evidence/s1b/race/s1-harness.txt) |
| S2 concurrency | [`s2/run2/s2-harness.txt`](../cgroup-bpf-historical/evidence/s2/run2/s2-harness.txt) |
| S3 lifecycle/reuse | [`s3/s3-summary.txt`](../cgroup-bpf-historical/evidence/s3/s3-summary.txt) |
| S6 enforcement boundaries | [`s6-enforcement-layer-table.md`](../cgroup-bpf-historical/evidence/s6/s6-enforcement-layer-table.md) |
| S7 loader loss | [`s7/run2/s7-summary.txt`](../cgroup-bpf-historical/evidence/s7/run2/s7-summary.txt) |
| S8 Enforcer loss | [`s8/after-fix-run6/s8-summary.txt`](../cgroup-bpf-historical/evidence/s8/after-fix-run6/s8-summary.txt) |
| S9/S10 foreign composition | [`s9/run4/s9-summary.txt`](../cgroup-bpf-historical/evidence/s9/run4/s9-summary.txt), [`s10/run3/s10-summary.txt`](../cgroup-bpf-historical/evidence/s10/run3/s10-summary.txt) |
| S11 lifecycle cleanup | [`s11/run1/s11-summary.txt`](../cgroup-bpf-historical/evidence/s11/run1/s11-summary.txt) |
| S12 exhaustion | [`s12/run1/s12-summary.txt`](../cgroup-bpf-historical/evidence/s12/run1/s12-summary.txt), [`s12-map-characterization.txt`](../cgroup-bpf-historical/evidence/s12/run1/s12-map-characterization.txt) |
| S13 ownership/recovery | [`S13-CONTRACT.md`](S13-CONTRACT.md), [`s13-v2-result.txt`](../cgroup-bpf-historical/evidence/s13/run2/s13-v2-result.txt) |
| S14 Candidate-C scaling | [`s14-scaling-matrix.txt`](../cgroup-bpf-historical/evidence/s14/run1/s14-scaling-matrix.txt), [`s14-resource-model.txt`](../cgroup-bpf-historical/evidence/s14/run1/s14-resource-model.txt), [`s14-result.txt`](../cgroup-bpf-historical/evidence/s14/run1/s14-result.txt) |

Failed and diagnostic runs are negative evidence, not authoritative PASS input:

- S1's [`SUBJECT_PLACEMENT_FAILURE`](../cgroup-bpf-historical/evidence/s1/diagnostic/s1-harness.txt)
  proves that runtime configuration is not placement evidence; the later
  [`ATTRIBUTION_LOGIC_FAILURE`](../cgroup-bpf-historical/evidence/s1/port-trace/s1-harness.txt)
  exposes how a common tuple-encoding defect can defeat every candidate.
- S8's preserved [`FAIL`](../cgroup-bpf-historical/evidence/s8/run4/s8-summary.txt)
  proves that candidate correctness cannot compensate for delayed Enforcer-loss
  detection. The authorized production fix and final regression are the
  baseline.
- S13's preserved [`FAIL`](../cgroup-bpf-historical/evidence/s13/run1/s13-result.txt)
  proves that pins, names and metadata without a trusted ownership/ABI/
  generation contract are unsafe. The final spike-only contract is evidence of
  the required behavior, not a production implementation.
- The failed/silent replay-runner attempts documented above are orchestration
  evidence: durable phase state and provenance-based owned-resource cleanup are
  mandatory. They do not distinguish A/B/C/D.

All conclusions are limited to Ubuntu 24.04.4, Linux
`6.8.0-134-generic`, aarch64 and the recorded Apache-2.0 programs. A successful
feature probe is not treated as runtime correctness evidence.

### Executive technical summary

The tested architecture remains `Execution -> forward proxy -> external API`.
cgroup-BPF supplies trusted attribution and early denial; nftables remains the
final destination barrier. The Enforcer is not a traffic hop, IP/veth identity
is only a cross-check, and missing or ambiguous attribution must deny.

A, B and C were carried simultaneously in the final tuple evidence and each
resolved to the current Execution in S1-S3. This proves their tested runtime
chains, but not three production backends. D only produced a netns cookie: the
trusted live `netns cookie -> Execution` owner mapping and its authorization
lifecycle were never exercised.

The main differentiators are therefore state ownership and operational shape:

- A uses an explicit, bounded and observable cookie-to-cgroup hash. Its update
  exhaustion was observed, and the surrounding missing-attribution path denied.
- B binds the same trusted cgroup identity to the socket through `sk_storage`,
  reducing explicit close cleanup but leaving allocation-pressure behavior and
  capacity less observable and not deterministically exhausted by S12.
- C removes the candidate-specific per-socket identity lookup by embedding one
  identity in each Execution's object instance, at the measured cost of `6N`
  programs, `6N` links, `8+2N` maps and `8+6N` pins. The present single-loader
  process reached `EMFILE` while loading instance 45 with 1,016 open FDs.
- D could reduce attribution to a namespace owner relation, but that security
  relation is currently `NOT PROVEN`; distinct cookies are insufficient.

### Candidate A dossier — socket cookie to cgroup identity

**Mechanism and trust source.** At admitted `connect4`, the program reads the
current cgroup ID and socket cookie and writes `cookie -> cgroup ID`. At
`ACTIVE_ESTABLISHED`, `sockops` reads the same socket cookie, looks up the
cgroup ID and publishes it with the accepted tuple. Resolve correlates that
tuple to the live Execution. Trust ultimately comes from the kernel's current
cgroup for a host-placed process; the cookie is the per-socket correlation key.

**Evidence maturity.**

- `PROVEN`: S1 published candidate-A cgroup 14646 from cookie 12347 and
  resolved the correct Execution; both final replays reproduced a nonzero
  cookie-to-current-cgroup record and correct Resolve.
- `PROVEN`: S2 observed 132 unique cookies over four concurrent Executions,
  zero attribution mismatch, zero cross-attribution and zero unexpected tuple
  collision. S3 covered FIN, RST, process kill and source-port reuse across
  fresh cgroup generations with zero stale/cross-generation attribution.
- `PROVEN`: S5 showed that omitting `sockops` leaves the connect-time cookie but
  no final tuple, identifying the required second half of the chain. S11
  removed cookie/tuple state and all other owned resources.
- `PARTIAL`: S12 filled the candidate-A cookie hash and tuple hash to 8/8; the
  extra cookie update returned `-7`, the tuple update also failed, and Resolve
  denied with no side effect. An isolated A-map-full case while tuple capacity
  remains available was not run.
- `NOT PROVEN`: production sizing/eviction policy, sustained hostile churn,
  cookie reuse outside the tested lifecycle, and production restart integration.

**State and lifecycle.** Candidate-specific state is one bounded hash entry per
live admitted socket. It also depends on the common tuple map, policy state,
six hooks and exact ownership metadata for any pins. `sockops` close deletes
only the tuple whose stored cookie matches the closing socket and then deletes
the cookie entry; Execution teardown removes remaining owned state. This was
safe in the S2/S3/S11 cases. Missed callbacks and crash residue still require
the S13 exact-record sweep/recreate rule; names or pin paths alone are not
ownership proof.

**Failure semantics.** Delayed/missing final tuple state denied in S1b, and
combined cookie/tuple exhaustion denied in S12. S7 proves pinned early-deny
enforcement survives loader loss, not that end-to-end proxy attribution remains
operable without its userspace owner. S8 Enforcer-loss cancellation and S13
incompatible/unknown-state refusal are surrounding lifecycle requirements, not
properties supplied by A itself.

**Kernel, licensing and composition.** A requires `connect4`, `sockops`, hash
map operations, `bpf_get_current_cgroup_id`, `bpf_get_socket_cookie` and the
state callback. These call sites loaded and executed under Apache-2.0 on the
tested kernel. S9/S10 prove the combined child program can coexist with an
ancestor foreign ALLOW/rewrite without bypassing child deny or nft's final
barrier; they do not prove every possible foreign program or attach topology.

**Cost and operations.** The normal spike bounds the candidate-A and common
tuple hashes at 4,096 entries; S12 used 8 to prove exhaustion. No independent
production A-only program/link/map/pin formula was measured. Relative to C, A
can use a shared program/map topology, but adds explicit per-socket map
insertion, deletion, sizing, diagnostics and stale-entry auditing. Its state is
directly enumerable, which improves observability.

**Residual risk.** The security-sensitive gaps are isolated A-only exhaustion,
production ownership/recovery, long-duration cookie churn, deployment-specific
map sizing and qualification outside the tested kernel/architecture.

### Candidate B dossier — socket-local BPF storage

**Mechanism and trust source.** At admitted `connect4`, the program obtains the
socket and creates socket-local BPF storage containing the kernel current
cgroup ID. `sockops` later reads that storage from the established socket and
publishes it with the tuple. Trust comes from the current cgroup at connect
time plus the kernel association of storage with that same socket.

**Evidence maturity.**

- `PROVEN`: S1-S3 published candidate B equal to the trusted current cgroup,
  resolved the correct Execution, produced zero cross-attribution over S2's 132
  sockets and no stale result in S3's FIN/RST/kill generations.
- `PROVEN`: the `sk_storage` helper path loaded and ran under Apache-2.0. S11
  returned attribution and BPF state to zero residue.
- `PARTIAL`: the same common tuple publication, bounded Resolve, foreign
  composition and lifecycle protections exercised B's value, but do not isolate
  B from A/C because all three travelled in one evidence record.
- `NOT PROVEN`: S12 observed zero `sk_storage` failures and documents no finite
  `max_entries` knob; deterministic allocation-pressure failure and a B-only
  missing-storage deny were not exercised.

**State and lifecycle.** Candidate-specific identity is a `BPF_MAP_TYPE_SK_STORAGE`
value associated with each socket; the map object and common tuple/policy state
still need ownership. The spike does not call `bpf_sk_storage_delete`; socket
lifetime owns that storage. This reduces explicit close deletion compared with
A, while making capacity, enumeration and pressure behavior less explicit.
S3/S11 support the tested lifecycle but do not prove all kernel allocation and
reclamation behavior.

**Failure semantics.** Source diagnostics treat failure to create/read storage
as absent B evidence. Production Resolve would have to reject that absence.
The common tuple-full path is proven fail closed; B-storage allocation failure
itself is not. Loader-, Enforcer- and incompatible-pin behavior is inherited
from S7/S8/S13 requirements in the same limited sense as A.

**Kernel, licensing and composition.** B additionally requires
`BPF_MAP_TYPE_SK_STORAGE`, a valid `ctx->sk` at connect time and
`bpf_sk_storage_get` in both hook contexts. Verifier acceptance and runtime use
were observed under Apache-2.0 only on the tested kernel. S9/S10 establish the
same combined-program coexistence as A, not a standalone production B design.

**Cost and operations.** There is one candidate-specific storage value per
socket plus the common tuple state, but no evidence-backed finite capacity or
standalone object formula. Explicit stale-entry deletion work is lower than A;
capacity planning, failure injection and operational inspection are harder.

**Residual risk.** Deterministic allocation-pressure behavior is the decisive
candidate-specific unknown, followed by observability, production ownership,
kernel-version semantics and sustained churn.

### Candidate C dossier — one configured object instance per Execution

**Mechanism and trust source.** The loader configures one object/program set
per Execution with `exec_ident` embedded in read-only data, activates its local
policy and attaches its six programs to that Execution's exact cgroup.
`sockops` publishes the configured identity directly. Trust comes from the
loader's binding of identity, object instance and cgroup attachment, so exact
ownership and generation validation are security-critical.

**Evidence maturity.**

- `PROVEN`: C resolved correctly in S1-S3, including four concurrent
  Executions and lifecycle/source-port reuse. S11 restored zero residue.
- `PROVEN`: S14 independently sampled membership and attribution at N=1, 4,
  16 and 32 with zero cross-attribution and exact resource counts.
- `PROVEN`: N=64 did not complete in the current loader shape. It completed 44
  instances and hit `EMFILE` during instance 45 with soft `RLIMIT_NOFILE=1024`,
  1,016 open FDs and a measured increase of 23 FDs per completed instance.
- `PARTIAL`: S13 proves a spike-only trusted ownership/ABI/generation contract
  can sweep/recreate compatible state and refuse incompatible/unknown state,
  but no production implementation exists.
- `NOT PROVEN`: optimized/sharded/short-lived loader designs, N>=45 in a
  production process, throughput, sustained churn and acceptable product
  setup/teardown latency.

**State and lifecycle.** The measured model is `6N` programs, `6N` links,
`8+2N` maps and `8+6N` pins: eight shared pinned maps, two private maps and six
link pins per Execution. Creation and teardown therefore scale with Execution
count. S3, S11, S13 and S14 prove the tested create/close/kill/recovery/cleanup
cases. Reusing prior authorization maps at readiness is explicitly forbidden by
the S13 negative and final evidence.

**Failure semantics.** C's configured identity has no candidate-specific
dynamic insertion-capacity failure, but the common tuple map can still fill and
must deny as in S12. Object loading can fail before admission, as S14 proves;
readiness must remain withheld and partial resources must be removed. Pinned
early denial survives loader death in S7, while S8 and S13 define the required
userspace-loss and restart behavior.

**Kernel, licensing and composition.** C uses the common six cgroup program
types and helpers plus loader relocation/configuration; the actual object loaded
and ran under Apache-2.0. S9/S10 are especially representative of C's direct
child attachment shape and show coexistence with the tested ancestor ALLOW and
rewrite. They do not establish arbitrary foreign ordering guarantees.

**Cost and operations.** C has the simplest candidate-specific publication
logic but the highest measured kernel-object, pin, attach/detach and loader-FD
burden. The FD boundary is a property of the current Aya/loader lifetime and
limit, not proof of intrinsic impossibility; no unmeasured optimization is
credited in this review. Per-Execution identity is visually direct, while a
large object inventory increases recovery and debugging work.

**Residual risk.** Production loader/process architecture, acceptable
concurrency and latency thresholds, multi-process coordination, production S13
state management and portability remain open. If one process must hold at
least 45 instances with the tested FD limit and lifetime, the current shape is
established non-viable for that requirement.

### Candidate D dossier — netns cookie with trusted owner mapping

**Mechanism and intended trust source.** `sockops` publishes the socket's netns
cookie. A privileged Enforcer that created and owns the network namespace would
have to establish and maintain a trusted live `netns cookie -> Execution`
mapping; Resolve would require that mapping before authorization. The intended
trust source is kernel namespace identity bound to trusted host-side ownership,
not the agent or its IP address.

**Evidence maturity.**

- `PROVEN`: `bpf_get_netns_cookie` loaded under Apache-2.0 in the tested
  `sockops` and `sock_create` programs; S1-S3 recorded cookies, and S3 observed
  distinct cookies for fresh namespace generations.
- `PARTIAL`: the experimental netns probe shows how a privileged process can
  learn a cookie from a socket it creates after entering an owned namespace.
  This is a mechanism observation, not an authorization chain.
- `NOT PROVEN`: no final test implemented or exercised the trusted live owner
  map, used it to Resolve, rejected stale/reused owner state, characterized
  map-full behavior or scaled the complete D chain. All final S1/S3 records
  explicitly mark D as recorded only.

**State and lifecycle.** A complete D design needs at least the common tuple
state plus an owner map and trusted create/remove/recovery records for every
owned namespace; the probe itself used a cookie-to-cookie observation map.
Exact production maps, bounds, pins and object counts are unknown. Namespace
creation, teardown, cookie reuse, delayed publication, Enforcer restart and
stale owner removal are security-critical and untested as an authorization
system.

**Failure semantics.** The surrounding proxy can deny a missing tuple, but it
has not been shown to deny every missing, stale or ambiguous D owner mapping.
S8 makes autonomous owner invalidation on Enforcer loss mandatory, and S13
makes unknown owner state non-authoritative, but neither validates D.

**Kernel, licensing and composition.** Helper load/runtime observation is
kernel-specific. S9/S10 show that the combined program can record a netns
cookie while composing with the tested foreign hooks; they do not prove D's
owner map or authorization. No resource/scaling conclusion for D is supported.

**Cost and operations.** D might use one owner relation per live namespace
rather than candidate-specific state per socket, but that is an unmeasured
design inference. It adds a cross-layer live-owner relationship whose atomic
creation, invalidation, recovery and observability have not been designed or
tested. Crediting it with lower cost or risk would therefore be speculative.

**Residual risk.** The complete trust chain, lifecycle/reuse safety, fail-closed
owner-map failure, resource bounds, foreign composition under authorization and
portability are all security-sensitive unknowns.

### Evidence-backed comparison matrix

`SUPPORTED`, `PARTIAL`, `BLOCKED` and `UNPROVEN` describe evidence maturity,
not scores or rankings.

| Criterion | A | B | C | D |
| --- | --- | --- | --- | --- |
| Trusted identity basis | Kernel current cgroup at connect; cookie correlates socket (`SUPPORTED`, S1) | Kernel current cgroup stored on the socket (`SUPPORTED`, S1) | Trusted loader binds configured identity to exact child cgroup (`SUPPORTED`, S1/S14) | Kernel netns cookie plus intended owner map; owner binding `UNPROVEN` |
| Complete attribution chain | Correct cookie -> cgroup -> tuple -> Resolve (`SUPPORTED`, S1-S3) | Correct storage -> cgroup -> tuple -> Resolve (`SUPPORTED`, S1-S3) | Correct embedded identity -> tuple -> Resolve (`SUPPORTED`, S1-S3/S14) | Cookie recorded only; owner-map Resolve `BLOCKED` |
| Concurrent safety | 132 sockets/four Executions, zero cross-attribution (`SUPPORTED`, S2) | Same carried B evidence (`SUPPORTED`, S2) | Same plus sampled N=32 (`SUPPORTED`, S2/S14) | Full chain `UNPROVEN` |
| Stale/reuse safety | FIN/RST/kill/source-port reuse passed; long churn `PARTIAL` (S3) | Same; kernel storage reclamation beyond cases `PARTIAL` | Same plus generation contract; production recovery `PARTIAL` (S3/S13) | Owner teardown/reuse `UNPROVEN` |
| Candidate-specific kernel state | Bounded cookie hash, one entry/live socket | `sk_storage`, one value/socket; capacity opaque | Per-Execution object plus two private maps | Owner map required; exact design unknown |
| Per-Execution kernel objects | No evidence-backed A-only formula; shared topology possible | No evidence-backed B-only formula; shared topology possible | Exactly six programs, six links, two private maps and six link pins | `UNPROVEN` |
| Map dependency | Cookie hash plus common tuple/policy | Socket storage plus common tuple/policy | Common tuple/policy; identity is configured, not dynamically inserted | Common tuple plus unimplemented owner map |
| Pin/recovery complexity | Shared maps/links still need S13 contract (`PARTIAL`) | Same, including storage-map ownership (`PARTIAL`) | Highest measured inventory; S13 contract essential (`PARTIAL`) | Owner-state contract not designed (`UNPROVEN`) |
| Missing/delayed state | Common Resolve denies; A-only absence not isolated (`PARTIAL`, S1b/S12) | Common Resolve denies; storage-allocation failure not exercised (`PARTIAL`) | Common Resolve denies; load failure prevents admission if readiness is correct (`PARTIAL`) | Owner-map absence/ambiguity not exercised (`UNPROVEN`) |
| Map-full exposure | Cookie and tuple update failure observed together; denied (S12) | Deterministic `sk_storage` exhaustion unavailable/not observed | No candidate-identity insertion; common tuple full observed | Owner-map capacity unknown |
| Loader-loss exposure | Pinned early deny survives; full attribution continuity not tested (S7) | Same | Same, with more per-Execution pinned objects | Full chain not present |
| Enforcer-loss exposure | Candidate-independent pre-fix FAIL then bounded regression PASS (S8) | Same | Same | Especially affects owner-map liveness; not candidate-tested |
| Kernel/API assumptions | Cookie and cgroup helpers, HASH, connect4/sockops callbacks | Adds `sk_storage` and socket availability in both contexts | Per-object configuration, six direct attachments, pinning | Adds netns-cookie semantics and trusted namespace-owner publication |
| Apache-2.0 compatibility | Required actual path loaded/executed | Required actual path loaded/executed | Required actual path loaded/executed | Helper loaded/executed; complete D path absent |
| Foreign-BPF coexistence | Combined child program passed tested ancestor ALLOW/rewrite (`PARTIAL`, S9/S10) | Same | Direct child shape most closely matches test (`SUPPORTED` for tested cases only) | Cookie observation only; authorization `UNPROVEN` |
| Operational scaling | Per-socket map state; no standalone scale formula | Per-socket storage; capacity not characterized | Exact formulas; N=32 passed, current N=64 bounded at 44 | `UNPROVEN` |
| Observability | High: enumerable cookie map and counters | Lower: socket-local allocation/capacity less explicit | High identity clarity; high inventory volume | Owner relation could be explicit, but no implementation |
| Implementation complexity | Moderate BPF/map logic; moderate lifecycle burden | Compact data path; kernel-specific failure/inspection complexity | Simple attribution logic; high loader/lifecycle complexity | Incomplete security design; highest uncertainty |
| Portability risk | Medium; cookie/callback semantics need matrix qualification | Medium-high; `sk_storage` semantics and pressure need qualification | Medium-high; loader/verifier/resource behavior and limits vary | High; cookie/owner semantics and full chain unqualified |
| Remaining security-critical unknown | A-only exhaustion, sizing, long churn, production recovery | Allocation failure, capacity, observability, production recovery | Production scale/process model and state manager | Trusted owner map, authorization, lifecycle, failure and scale |

### Evidence-readiness classification

| Candidate | Classification | Exact reason |
| --- | --- | --- |
| A | `SUFFICIENTLY CHARACTERIZED FOR HUMAN DECISION` | Complete tested chain, concurrency/lifecycle evidence, explicit state and observed bounded-map failure. This is not production qualification; A-only exhaustion and production recovery remain requirements. |
| B | `REQUIRES SPECIFIC ADDITIONAL EVIDENCE` | A deterministic `sk_storage` allocation-pressure failure with tuple capacity available must show that missing B evidence denies and leaves no stale authorization. |
| C | `SUFFICIENTLY CHARACTERIZED FOR HUMAN DECISION` | Correctness and exact operational cost are known through N=32, and the present 45th-instance FD failure is characterized. The human must decide whether that object/FD/lifecycle model fits the product envelope. |
| D | `REQUIRES SPECIFIC ADDITIONAL EVIDENCE` | The trusted live netns-cookie owner map, authorization lookup, teardown/reuse safety, missing/ambiguous-owner denial and resource bounds were never exercised. |

No candidate is classified intrinsically non-viable. The current C loader shape
is, however, established non-viable for a requirement of at least 45
simultaneously retained instances under soft `RLIMIT_NOFILE=1024`; that does not
prove Candidate C itself cannot be implemented differently.

### Technical recommendation, not final selection

The evidence-backed technical recommendation is **Candidate A as the starting
direction for a production design**, subject to explicit human selection and
the candidate-independent requirements below.

The basis is narrow and factual: A has a complete exercised trust chain,
concurrency and lifecycle evidence; its candidate-specific state is explicit,
bounded and observable; its update failure was observed; and it avoids C's
measured per-Execution multiplication of programs, links, pins and long-lived
loader FDs. B does not yet have deterministic allocation-pressure evidence, and
D lacks its core trusted owner mapping. C remains a viable, sufficiently
characterized alternative when direct per-Execution identity is worth its
known operational cost.

This recommendation does not select A, authorize implementation, eliminate C,
or claim that A is production-qualified. If the human decision requires B's
socket-lifetime ownership benefits or D's namespace-owner model, the exact
missing evidence above is material and must be obtained before choosing them.

### Candidate-independent production requirements

The completed evidence makes the following requirements independent of the
candidate selected:

1. Place and independently verify the actual live agent PID in the exact
   attached Execution cgroup before releasing traffic.
2. Validate all six direct/effective hooks and ancestor composition; keep BPF
   as attribution/early deny rather than routing or proxy steering.
3. Keep Resolve bounded and deny before application reads, DNS, outbound
   effects or IP-derived authorization fallback.
4. Keep nftables as the final destination barrier and preserve namespace/
   topology confinement as a separate layer.
5. Treat tuple representation and byte order as an explicit ABI with regression
   evidence; the S1 diagnostic showed one port extraction defect breaks every
   candidate.
6. Make map update/allocation failure observable and fail closed; never repair
   missing attribution from IP/veth identity.
7. Detect Enforcer loss autonomously and cancel admission, agents, HTTP work,
   DNS, outbound connections and tunnels before restart readiness.
8. Persist exact root-owned ownership/schema/ABI/build/generation records;
   validate kernel IDs and contracts, recreate compatible state empty, refuse
   incompatible/unknown state and never delete by pathname prefix.
9. Publish readiness only after recovery and verify zero residue across
   processes, cgroups, runtime state, netns/veth/nft, BPF objects, pins,
   attribution maps and ownership records.
10. Budget programs, links, maps, pins, memlock/JIT and userspace FDs against
    the supported concurrent-Execution envelope.
11. Preserve Apache-2.0-compatible facilities. The two evaluated routes to
    `CGRP_STORAGE` through task-BTF/cgroup-pointer access were GPL-restricted on
    the tested kernel and are not available design assumptions.

### Remaining unproven items

- Production `CgroupBpfBackend` remains a refusing skeleton; its initialize,
  prepare, freeze, destroy, recovery and readiness behavior is unimplemented.
- B1-B7, full regression across both backends, T1-T9, H1-H4 and the T10 no-eBPF
  build remain outside S0-S14.
- No production upgrade/migration, multi-loader coordination, sustained hostile
  churn, throughput or tail-latency envelope was qualified.
- Candidate A's isolated supporting-map failure, B's storage allocation
  failure, C beyond the measured current-process bound and D's complete owner
  chain remain as described above.
- Kernel, distro, configuration and architecture portability beyond the tested
  Ubuntu/Linux 6.8 aarch64 environment is unproven.
- S7 proves persistence of pinned kernel enforcement after loader death, not
  uninterrupted end-to-end attribution service without a healthy userspace
  owner.
- S13 proves a spike-only recovery contract, not the production contract's
  implementation or upgrade policy.

### Questions reserved for the human decision

1. Is Candidate A's explicit bounded per-socket map and cleanup obligation
   preferable to B's kernel-owned storage with currently uncharacterized
   allocation pressure?
2. Does the product require the direct per-Execution identity isolation of C
   strongly enough to accept its measured `6N` program/link and pin lifecycle,
   and what simultaneous-Execution/FD envelope is mandatory?
3. Is Candidate D still strategically important enough to justify obtaining
   its missing trusted-owner evidence before selection, or should it remain a
   deferred design?
4. What supported kernel/distro/architecture matrix and resource ceilings must
   the chosen candidate satisfy before B1-B7 and production qualification?
5. Does the human reviewer accept the technical recommendation toward A, choose
   another sufficiently characterized candidate, or require one of the exact
   missing evidence items first?

The candidate review itself made no final A/B/C/D selection, changed no architecture or production code, and stopped pending a separate explicit decision.

## Post-review candidate decision

On 2026-09-27, after approving the evidence-backed review above, the human reviewer explicitly selected **Candidate A** as the attribution mechanism for the first production `CgroupBpfBackend`.
The production architecture, lifecycle, ownership/recovery rules, failure semantics and B1-B7 qualification gates are specified in [PRODUCTION-DESIGN.md](PRODUCTION-DESIGN.md).

This recorded a design decision only at that review checkpoint. Implementation
was subsequently authorized under the normative production design; the existing
`NetnsNftBackend` default remains unchanged.

## Production qualification status

The current authoritative B1 qualification is
[`b1-20260928T211104Z-8595`](evidence/authoritative/b1-20260928T211104Z-8595/).
It qualifies the Candidate-A production implementation at production commit
`bc55e76725c251a5ae3b89360b014563dd8249df`; its complete source fingerprint is
`668562dd4a40570157eb92859efbb07f72eec508` with an empty working-tree diff.
The run records `authoritative: true`, B1 `PASS`, all thirteen qualified
properties true and cleanup `PASS`. Its BPF inventory result is
`EXTERNAL_CHURN`: only systemd-owned `sd_*` program IDs changed while the full
set of program name/type/tag tuples, all non-systemd programs, links and maps
were restored and every Soglia-owned resource was absent. All 144 entries in
`SHA256SUMS` verify.

The earlier authoritative B1 runs are retained but superseded:

- [`b1-20260927T214134Z-7374`](evidence/authoritative/b1-20260927T214134Z-7374/)
  predates the production cleanup `ENOENT` correction;
- [`b1-20260927T235134Z-8460`](evidence/authoritative/b1-20260927T235134Z-8460/)
  includes that correction but predates the typed, correlated one-shot Resolve
  protocol;
- [`b1-20260928T113442Z-8393`](evidence/authoritative/b1-20260928T113442Z-8393/)
  qualifies the typed Resolve implementation before the durable-record policy
  validation correction in `bc55e76`.

None of the superseded runs counts as the current B1 qualification.
Simulation of a kernel missing a required feature remains `NOT_PERFORMED`:
the qualification did not modify the production BPF object, so support remains
limited to the exact recorded platform fingerprint.

The current authoritative B2 qualification is
[`b2-20260928T211528Z-8553`](evidence/authoritative/b2-20260928T211528Z-8553/).
It qualifies production commit
`bc55e76725c251a5ae3b89360b014563dd8249df` with the B2 harness and complete
source fingerprint `668562dd4a40570157eb92859efbb07f72eec508`; the recorded
working-tree diff is empty. The run records `authoritative: true`, B2 `PASS`
and all eleven cases `PASS`. In addition to the positive chain and the typed
placement and Resolve refusals, it independently qualifies `wrong_destination`,
the source-port-only `tuple_byte_order` case, and `host_origin_refused`. Its
`concurrent_timeout` case originates four simultaneous connections inside one
Execution and observes four bounded `Timeout` results without a health failure,
application read, DNS or outbound effect. Cleanup is `PASS`; programs are
`EXTERNAL_CHURN` solely because systemd replaced equivalent `sd_*` programs,
while links and maps are `MATCH` and no Soglia-owned object remains. All 356
entries in `SHA256SUMS` verify.

Capacity exhaustion and helper-loss cancellation remain `NOT_PERFORMED` in B2
because they belong respectively to B4 and B6.

The earlier authoritative B2 runs are retained but superseded:

- [`b2-20260928T060551Z-8414`](evidence/authoritative/b2-20260928T060551Z-8414/)
  predates typed Resolve and its `tuple_byte_order` case swapped both source and
  destination ports, so it exercised the proxy-destination guard rather than
  the source-port byte-order invariant;
- [`b2-20260928T153155Z-8510`](evidence/authoritative/b2-20260928T153155Z-8510/)
  qualifies the typed B2 chain before the durable-record policy validation
  correction in `bc55e76`.

Neither superseded run counts as the current B2 qualification.

The current and first authoritative B3 qualification is
[`b3-20260928T213249Z-8581`](evidence/authoritative/b3-20260928T213249Z-8581/).
It qualifies production commit
`bc55e76725c251a5ae3b89360b014563dd8249df` with source fingerprint
`668562dd4a40570157eb92859efbb07f72eec508` and an empty working-tree diff.
The run records `authoritative: true`, B3 `PASS`, all thirteen cases `PASS`,
all sixteen ordinary binding-mismatch cells `PASS`, all three durable-record
mismatch cells `PASS`, and all 202 freeze/Resolve race iterations `PASS` with
no post-freeze effects. In particular, changing only the durable record's
execution nonce now refuses startup as `UNKNOWN per-Execution ownership record`
without changing a kernel object. Lifecycle cleanup, source-port reuse, old
close cookie protection, generation advance, CONNECT tunnel revocation and
counter accounting all pass. Cleanup is `PASS`; programs are
`EXTERNAL_CHURN` only for equivalent systemd-owned replacements, links and maps
are `MATCH`, and all 1914 `SHA256SUMS` entries verify.

Actual cgroup-ID reuse is `NOT_PERFORMED`: the recorded kernel exposes a 64-bit
kernfs identity carrying generation information and did not reuse a destroyed
identity during the bounded lifecycle. The required stale-nonce and generation
classes were nevertheless exercised deterministically by the mismatch matrix.

The current and first authoritative B4 qualification is
[`b4-20260929T084513Z-8677`](evidence/authoritative/b4-20260929T084513Z-8677/).
It qualifies production commit
`bc55e76725c251a5ae3b89360b014563dd8249df` with harness/source fingerprint
`aff9c3645a6751968c94c596215e027614900614` and an empty working-tree diff.
The run records `authoritative: true`, B4 `PASS` and all ten capacity and
publication cases `PASS`. In particular, the isolated cookie-full case accepts
exactly four live sockets and denies the fifth synchronously without a proxy
accept, while the event-ring case observes 256 client denials, a matching
`C_CONNECT4_DENY` delta of 256 and nonzero dropped-event accounting. The
post-refusal control for `admission_limit` and the post-saturation control for
`resolve_queue_full` both resolve to the correct Execution. Cleanup is `PASS`;
programs are `EXTERNAL_CHURN` only for equivalent systemd replacements, links
and maps are `MATCH`, all six production program tags are recorded, and all 89
entries in `SHA256SUMS` verify.

Diagnostic run `b4-diagnostic-20260929T080354Z-198174` remains a
`CLEANUP_FAIL`. It observed one added `sd_devices`/`cgroup_device` program later
located live on `fwupd.service`, but the run had not captured the attachment
path and therefore lacked the evidence required to call it external. Harness
commit `aff9c36` resolves that evidence gap without weakening cleanup: B1-B4
now share a classifier that accepts `EXTERNAL_ADDITION` or `EXTERNAL_REMOVAL`
only when every changed program has a tag distinct from all six observed
production tags, no Soglia pin or link reference, and direct attachments solely
outside the Soglia cgroup subtree recorded from `bpftool cgroup tree`.
Unattached programs, programs inside the Soglia subtree, production-tag
matches and incomplete evidence remain cleanup failures. Five focused tests
cover the accepted external addition/removal and the required negative cases.

The current and first authoritative B5 qualification is
[`b5-20260929T140856Z-8731`](evidence/authoritative/b5-20260929T140856Z-8731/).
It qualifies production commit
`bc55e76725c251a5ae3b89360b014563dd8249df` with harness commit
`caa9293093281b137d549a487f55d207d63e92b7` and an empty working-tree diff.
The run records `authoritative: true`, B5 `PASS` and all eleven cases `PASS`.
Cleanup is `PASS`; programs are `EXTERNAL_CHURN` only for equivalent
systemd-owned replacements, links and maps are `MATCH`, and all 152 entries in
`SHA256SUMS` verify.

The dedicated proxy-steering boundary evidence performs a static
production-source audit of `candidate_a.c`: the only accesses to
`ctx->user_ip4`, `ctx->user_ip6` or `ctx->user_port` are the expected reads of
`user_port` and `user_ip4`, there is no `bpf_bind` call, and the production
source SHA-256 matches the qualified baseline. At runtime the agent-requested,
configured and proxy-observed destinations are all `10.200.255.1:15001`.
Proxy steering therefore remains outside BPF.

The foreign-ancestor rewrite case records no program-order claim. In the
observed topology the production child `connect4` admits the original proxy
destination, the ancestor then rewrites it to `10.201.0.2:16001`, and the
Execution namespace nft output policy is the final post-rewrite barrier. The
counter-only nft observer records two rewritten packets, the target listener
accepts none, and both the Execution and host rulesets are restored exactly.

Runtime execution of `connect6`, `sendmsg4` and `sendmsg6` remains
`NOT_PERFORMED`: production `sock_create` admits only IPv4/TCP sockets and a
socket's cgroup is fixed at creation, making those later hooks unreachable by
construction. The optional direct TCP Fast Open extension is also
`NOT_PERFORMED` and is not required for B5 PASS.

The current and first authoritative B6 qualification is
[`b6-20260930T081205Z-8744`](evidence/authoritative/b6-20260930T081205Z-8744/).
It qualifies production commit
`a8a0e9cef0f675f6b6415a34d14d21a339d85ec8` with harness/document fingerprint
`e1cad0bfb0ee83c7975bcf4adbfc5ab963e1a933` and an empty working-tree diff.
The run records `authoritative: true`, B6 `PASS` and all 38 case verdicts
`PASS`. Cleanup is `PASS`; programs are `EXTERNAL_CHURN` only for equivalent
systemd-owned replacements, links and maps are `MATCH`, and all 917 entries in
`SHA256SUMS` verify.

B6 covers admission-before-readiness, all four host-wide S13 boundaries, all
nine per-Execution S13 boundaries, interrupted recovery, Enforcer, Supervisor,
Sandbox and Resolve-channel loss, four typed `Incompatible` refusals, nine
typed `Unknown` refusals, repeated refusal under `Restart=on-failure`, and the
four negative `TargetReleased` controls: a live attached link, a mixed link
set, a non-empty replacement target and a target outside the current unit.
Each negative refuses without publishing readiness or mutating unknown state.

In `sandbox_sigkill`, the durable cgroup handle matches the independent probe
and returns `ESTALE` after systemd releases the old target. A write through the
retained old `cgroup.procs` descriptor fails with `ENODEV`, while
`clone3(CLONE_INTO_CGROUP)` fails with `ENOENT`; neither admits a process. The
harness corroborates that the old ID is absent from the live hierarchy. All
six recorded links are detached exactly and verified, the backend advances
from generation 1 to generation 2 with empty authorization maps, and READY is
published last. The 512 MiB page-cache workload was observed to delay target
release and is recorded as an availability contributor; page-cache state is
not a `TargetReleased` classification predicate.

Three production corrections entered while B6 was developed: `4d1e40f` makes
Execution admission wait for startup readiness; `c80cd4e` carries stable typed
refusal classes through the helper protocol and Supervisor exit; and the
`TargetReleased` work culminating in `a8a0e9c` records an exact durable cgroup
handle plus a unique cgroup-mount identity, proves an offline target directly
through the kernel, detaches only exact recorded links and recovers through a
new empty generation. The authoritative run qualifies their combined state,
not any intermediate commit.

B1 through B5 remain qualified on production commit `bc55e76`, while B6 is
qualified on the later production commit `a8a0e9c`. B7 remains
`NOT_EXECUTED`. Because the production baseline changed during B6, Phase 1
still requires a final authoritative B1-B7 qualification sequence on one
unchanged production commit; the earlier per-gate evidence remains valid for
the exact commits it records but does not replace that unified final run.

Historical note: the first authoritative B2 run
[`b2-20260928T060551Z-8414`](evidence/authoritative/b2-20260928T060551Z-8414/)
must not be cited as qualification of the source-port byte-order invariant.

## Final unified B1-B7 production qualification

**Status: COMPLETE PASS on one unchanged production baseline.**  The final
authoritative sequence qualifies Candidate A and the production
`CgroupBpfBackend` at production commit
`db6e1ac21a957b5fd8de96f5e3a719db1d897723`.  Every gate records
`production_source_baseline.matches: true`, an empty working-tree diff, a fresh
authoritative VM and cleanup `PASS`.  The seven promoted runs are:

| Gate | Authoritative run | Source fingerprint | Checksums | Cleanup inventory |
| ---- | ----------------- | ------------------ | --------- | ----------------- |
| B1 | [`b1-20260930T150949Z-8734`](evidence/authoritative/b1-20260930T150949Z-8734/) | `4824d1bbb1c567a11ca2c338212cb76cefea805c` | 151/151 | programs `EXTERNAL_CHURN`; links/maps `MATCH` |
| B2 | [`b2-20260930T163724Z-8764`](evidence/authoritative/b2-20260930T163724Z-8764/) | `4824d1bbb1c567a11ca2c338212cb76cefea805c` | 362/362 | programs `EXTERNAL_CHURN`; links/maps `MATCH` |
| B3 | [`b3-20260930T164122Z-8761`](evidence/authoritative/b3-20260930T164122Z-8761/) | `4824d1bbb1c567a11ca2c338212cb76cefea805c` | 1920/1920 | programs `EXTERNAL_CHURN`; links/maps `MATCH` |
| B4 | [`b4-20260930T164653Z-8823`](evidence/authoritative/b4-20260930T164653Z-8823/) | `4824d1bbb1c567a11ca2c338212cb76cefea805c` | 89/89 | programs `EXTERNAL_CHURN`; links/maps `MATCH` |
| B5 | [`b5-20260930T165141Z-8741`](evidence/authoritative/b5-20260930T165141Z-8741/) | `4824d1bbb1c567a11ca2c338212cb76cefea805c` | 152/152 | programs `EXTERNAL_CHURN`; links/maps `MATCH` |
| B6 | [`b6-20260930T165432Z-8758`](evidence/authoritative/b6-20260930T165432Z-8758/) | `4824d1bbb1c567a11ca2c338212cb76cefea805c` | 917/917 | programs `EXTERNAL_CHURN`; links/maps `MATCH` |
| B7 | [`b7-20260930T220538Z-8812`](evidence/authoritative/b7-20260930T220538Z-8812/) | `57a072154dd538c02efe0bf9ac62a170a294a030` | 186/186 | programs `EXTERNAL_CHURN`; links/maps `MATCH` |

All 3,777 recorded checksum entries verify.  The B7 fingerprint differs from
the B1-B6 harness fingerprint only after the reviewed B7 harness corrections
and report-only commits; its production tree still matches `db6e1ac` exactly.
The systemd-owned program replacement accepted as `EXTERNAL_CHURN` preserves
the complete non-owned name/type/tag set and leaves no Soglia-owned program,
link, map, pin or runtime resource behind.

The unified sequence closes the normative qualification matrix:

- **B1** qualifies the six-link production attach topology, true effective
  inventory, real delegation, READY-last ordering, typed startup refusals,
  synchronous rollback and crash recovery.
- **B2** proves exact subject placement and Candidate-A attribution, including
  typed negative outcomes, bounded concurrent timeouts, no pre-Resolve read,
  no IP fallback and no DNS or outbound side effect.
- **B3** proves whole-`BindingKey` isolation, lifecycle and generation
  boundaries, stale-close protection, tunnel revocation and the freeze/Resolve
  race.  Actual cgroup-ID reuse remains `NOT_PERFORMED` because the recorded
  kernel did not reuse a destroyed 64-bit identity; deterministic stale-nonce
  and stale-generation cases are covered.
- **B4** proves fail-closed admission, policy, cookie, tuple, Resolve-queue and
  event-ring capacity behavior with recovery controls after every injected
  saturation or duplicate.
- **B5** proves the enforcement composition: BPF early deny, nftables as the
  final post-rewrite destination barrier, namespace confinement, supported
  foreign-ancestor coexistence and proxy steering outside BPF.  The unreachable
  `connect6`/`sendmsg4`/`sendmsg6` paths and optional direct TCP Fast Open case
  remain explicitly `NOT_PERFORMED` as recorded in the run.
- **B6** proves readiness, typed S13 refusal and preservation, process/helper
  loss, interrupted recovery and exact `TargetReleased` recovery for an offline
  systemd target, including the negative controls.
- **B7** proves the declared M0-M3 resource envelope, constant shared topology
  of six programs, six links, seven maps and thirteen pins, production
  observability, both integrity-drift transitions and cleanup.  The supported
  claims remain bounded to 512 simultaneously live sockets and 32 simultaneous
  new admissions under the recorded production `RLIMIT_NOFILE=1024`; maps were
  configured to 4,096 tracked sockets but 4,096 live sockets were not claimed.

In the authoritative B7 out-of-envelope burst, 256 simultaneous requests
produce 115 successful connections and 141 typed `QueueFull` refusals.  Packet
capture records exactly 115 raw SYNs and 115 distinct source/destination
4-tuples, with zero retransmissions, zero outbound attempts or accepts for the
141 refused connections and zero DNS packets.  The immediate post-burst control
resolves successfully without retry.  Thus the burst characterizes the bounded
fail-closed refusal path; it is not promoted into the supported envelope.

B7 records the three cleanup boundaries independently.  With the runtime still
active, every workload's closed Executions have zero policy, cookie, tuple and
deny entries and no owned cgroup, netns, veth, runtime bundle or ownership
record.  After service stop and before harness deletion, each row retains
exactly its registered persistent generation and no unregistered object.  Only
then does the harness remove exact registered paths, without wildcard cleanup;
every row, both drift cases and the final global inventory report `PASS`.
The foreign-direct-link and owned-link-detach drift cases stop admission and
effect-producing work in 932 ms and 937 ms respectively, within the recorded
one-second health interval plus deterministic tolerance, with no silent
in-process repair.

This COMPLETE PASS closes B1-B7 qualification for the exact recorded platform
and production baseline.  It does **not** by itself change the default backend,
replace the T1-T9/H1-H4 and no-eBPF regressions, qualify an installation or
uninstallation path, or authorize a release.  Those remain separate Phase 1
steps.  The availability and kernel-pressure follow-ups are intentionally
unchanged in [Deferred work: independent Resolve queue depth](#deferred-work-independent-resolve-queue-depth)
and [Deferred work: warm pool of never-used Executions](#deferred-work-warm-pool-of-never-used-executions),
including the warm-pool and churn risks documented there.

## Deferred work: independent Resolve queue depth

Status: decided on 2026-09-30 during the B7 review; the Phase 1 choice is recorded here, the follow-up is not implemented.

### What was observed

In B7 diagnostic run `b7-diagnostic-20260930T204331Z-1087755`, M0, M1 and M2 recorded zero `queue_refusal` outcomes in the production `cgroup_bpf.resolve_health` events.
M3, with `max_concurrency: 32`, recorded 1,015 `queue_refusal` outcomes in eight waves of about 140, including the 256-connection burst in which 120 connections succeeded and 136 were refused.
Every other failure class stayed at zero: no timeout, `Unavailable`, identity mismatch, not-found or integrity failure.

### Why it happens

The Supervisor bounds pending Candidate-A Resolve requests with a queue whose depth equals `runtime.max_concurrency`.
New proxy connections that arrive at the same moment beyond that depth are refused with the typed `QueueFull` outcome, before any DNS lookup or outbound connection.
The refusal is fail-closed: nothing leaves the Execution, and each refusal is counted as `queue_refusal`.

### Phase 1 decision: option A

Production is not changed for Phase 1.
The declared B7 envelope states the simultaneity that the qualification proves without refusals, and states that bursts of new connections beyond the Resolve queue depth are refused fail-closed.
B7 requires zero refusals inside the declared envelope and keeps the 256-connection burst as a characterization of the refusal path, not as a supported capacity.

The consequences are availability-only:

- an agent, or several Executions together, that opens more new proxy connections at the same instant than `max_concurrency` sees the excess connections fail;
- connections that keep their tunnel open are not affected, because Resolve runs once per new proxy connection, not per HTTP request;
- the workloads most exposed are aggressive fan-out patterns such as parallel downloads, crawlers and headless browsers, which can mitigate by bounding their own parallelism or retrying with a short backoff;
- the only way to deepen the queue today is to raise `max_concurrency`, which also raises the number of Executions admitted at once.

### Follow-up: option B, a parallel Resolve path

Decided on 2026-09-30: option B is implemented as a complete parallel Resolve path, not as a larger queue in front of the current single exchange.
It starts after Phase 1 is closed, as decided on 2026-09-30: B7 on option A authoritative and promoted, the single `spike:qualify` command with automatic evidence verification, the uninstall command, `cgroup-bpf` as the default backend with an explicit `netns-nft` fallback, the T1-T9/H1-H4 regressions on both backends, the final qualification of the release commit and the documentation. Optimizations such as this one and the warm pool follow that release.

How the path works today, in `crates/soglia-supervisor/src/helpers.rs`: every new proxy connection takes a permit from a semaphore sized `max_concurrency` with a non-blocking `try_acquire`, and no free permit means an immediate `QueueFull`.
Permit holders then exchange with the Enforcer one at a time over a single channel guarded by the IPC gate, retrying every 2 ms while the tuple is not yet published, up to `resolve_timeout_ms`.
Each exchange is fast, most under 250 µs, so the limit is how requests enter and wait, not raw Resolve speed.

The target design has three parts:

1. **Bounded, configurable admission in the Supervisor.** The pending-Resolve depth becomes its own validated setting, for example `cgroup_bpf.max_pending_resolves`, independent of `runtime.max_concurrency`, with a ceiling derived from the file-descriptor budget. Admission beyond the ceiling still refuses immediately with the typed `QueueFull`.
2. **A pipelined channel.** Several requests are in flight on the channel at once, each correlated by its `request_id`. A protocol error, an unknown or duplicate `request_id`, or any unexpected response poisons the channel and triggers the existing one-way fail-closed transition.
3. **A worker pool in the Enforcer.** K resolver threads serve requests in parallel with read-only access to the BPF maps, outside the backend lock that serializes Execution lifecycle changes. Every answer keeps the generation and identity checks, and a worker failure is an integrity failure, not a degraded mode.

The security properties do not change: kernel-derived attribution, fail-closed on any anomaly, no stale authorization, and no DNS or outbound effect before a Resolve succeeds.

The pool reuses Soglia's own trusted threads, not agent code: every call still runs in a fresh Execution that is never reused.
Resolve workers therefore carry no state from one request to the next, with no attribution cache, no per-Execution data and no credentials; each answer is derived again from the kernel-owned maps and the current generation.

Work items:

1. Design review: the parallel protocol, the worker count and its bound, the admission ceiling and the saturation behavior, written into `PRODUCTION-DESIGN.md` before any code.
2. Budget file descriptors: every pending connection holds a descriptor, and the production unit does not set `LimitNOFILE`, so the soft limit is 1,024. Either set `LimitNOFILE` in `dev/systemd/soglia.service` or derive the ceiling from `RLIMIT_NOFILE`, and refuse a configuration that cannot fit.
3. Implement the three parts with unit tests for correlation, poisoning, concurrent generation checks and saturation.
4. Expose the queue depth, its high-water mark, in-flight requests and per-worker outcomes in `cgroup_bpf.resolve_health`.
5. Extend B7 with a burst row that declares a burst size and requires zero refusals up to it, plus a saturation row that proves typed `QueueFull` beyond the ceiling with no effect.
6. Requalify: this is a production change, so it starts a new production baseline and requires the complete authoritative B1-B7 sequence on it, run through a single `spike:qualify` command with automatic evidence verification.
7. Document the setting and its limits in `README.md` and in the site's "Run Soglia" page.

## Deferred work: warm pool of never-used Executions

Status: proposed on 2026-09-30; not designed in detail and not implemented. It is a throughput and latency lever for higher call volumes, planned after Phase 1 closes and after the parallel Resolve path.

At high volume the cost of a call is dominated by creating its Execution (namespaces, cgroup, veth, nftables, runc container), not by Resolve.
A warm pool keeps N Executions prepared in advance and never used: each one serves exactly one call and is then destroyed, as with pre-started microVMs in serverless platforms.
Nothing is ever reused, so the one-Execution-per-call model is unchanged.

The Supervisor already has the admission queue this builds on, in `crates/soglia-supervisor/src/supervisor.rs`: a `running` semaphore sized `max_concurrency` and a `waiting` semaphore sized `max_queue`; a call starts when a running permit is free, otherwise waits in a bounded queue, and is refused when the queue is full.

The existing Execution lifecycle, whose boundaries B6 qualifies one by one, splits naturally:

- ahead of time, into the pool: prepare network and cgroup with the policy frozen, then `runc create` the container paused; no agent code has run and the zone holds no authority;
- on arrival of a call: generate the execution nonce, bind the `BindingKey`, activate the policy and `runc start` the agent; the call's authority enters only now;
- at the end: destroy the zone, and only after its cleanup is verified prepare a fresh one with a new cgroup and a new nonce.

Rules to fix in the design:

1. A zone is used once and never returned to the pool.
2. At claim time the zone is revalidated: never started, cgroup holding only the paused init, nftables intact, current BPF generation. Any mismatch destroys the zone instead of using it.
3. Zones expire after a bounded idle time and are recreated; after an Enforcer restart every old zone is destroyed.
4. Rootfs, command and environment differ per agent, so the pool and its size N are per agent.

Sizing, by Little's law (items waiting = arrival rate × waiting time):

- **N, warm zones:** enough to cover recreation time, about calls per second × time to prepare one zone, plus headroom for bursts; for example 20 calls/s × 0.15 s ≈ 3 zones.
- **`max_queue`, waiting calls:** at most (caller timeout ÷ mean call duration) × `max_concurrency`; for example 30 s ÷ 2 s × 4 = 60. Beyond that, an immediate refusal is better than a wait that will time out.
- **Budget:** every waiting call holds an ingress connection and its request body, so the queue needs `max_queue` × `max_request_bytes` of memory and `max_queue` file descriptors, within the same `LimitNOFILE` budget as the parallel Resolve path.
- **Capacity:** warm zones + running Executions + zones being cleaned ≤ `policy_capacity`, because a warm zone already holds a frozen policy entry.

Qualification: the change touches the Execution lifecycle, so it requires the complete B1-B7 sequence on its production baseline, with B3, B6 and B7 extended for claim-time revalidation, crash boundaries inside the pool and pool sizing, plus the T1-T9/H1-H4 regressions.

### Kernel pressure under Execution churn

Creating and destroying zones at high rate stresses the kernel in ways the qualification has not yet measured; B7 measured thousands of connection cycles, not a long run of Execution lifecycles.

- **Dying cgroups.** Page cache read by an Execution is charged to its memory cgroup, which then stays in memory after removal until the pages are reclaimed. The B6 review VM already held 66 dying cgroups for 28 live ones. Mitigations: pre-read each agent rootfs from a permanent cgroup, such as the runtime's own, so Execution cgroups hold no page cache of their own and die at once; watch `nr_dying_descendants` and stop admission above a threshold rather than let the host degrade.
- **Network namespace teardown is asynchronous.** The kernel dismantles namespaces in a system worker, so creation faster than teardown builds a backlog. Mitigation: bound the creation rate; the warm pool spreads creations over time instead of concentrating them in bursts.
- **veth operations take the global `rtnl_lock`.** Parallel link creation and removal serialize and slow other host networking. Mitigation: bound parallel link operations and use netlink directly instead of one `ip` process per operation.
- **nftables** changes are transactions; cheap at normal rates, still to be measured.
- **Ephemeral ports on the proxy's upstream side.** Every HTTPS tunnel opens its own upstream connection that cannot be pooled, because TLS runs end to end between the agent and the service, and each closed connection holds a local port in TIME_WAIT for 60 s. For example, 50 Executions/s × 10 connections to the same API is 500 connections/s × 60 s = 30,000 ports, above the default range of about 28,000 per destination, after which new connections fail. Mitigations: widen `net.ipv4.ip_local_port_range`, enable `net.ipv4.tcp_tw_reuse=1` for outbound connections, and if needed give the proxy several source addresses.
- **Process zombies** are a low risk: each agent runs in its own PID namespace, which the kernel tears down with the Execution, and the Sandbox reaps the runc processes; B6 proved no agent process survives loss. The soak still counts zombies over time.

Not a concern by design: the six shared BPF programs and links stay constant as Executions come and go (qualified by B7), map-entry updates are cheap, and 64-bit cgroup IDs are never reused.

Required before pushing volume: an Execution churn soak of tens of thousands of lifecycles that tracks, over time, `nr_dying_descendants`, kernel memory, namespace-teardown backlog, zombie processes, TIME_WAIT sockets and free ephemeral ports per destination, and creation latency; a rising creation latency is the signature of accumulation.
The soak raises the rate until one of these starts to grow; that rate becomes the declared sustainable rate, and admission-stop valves on the same signals keep the host from degrading beyond it.

## Deferred work: VM-isolation profile with Firecracker

Status: proposed on 2026-10-01; not scheduled in the current phases. The architecture already allows it through the pluggable `SandboxBackend` (`soglia-architecture.md` §22.3).

A Firecracker profile would add hardware-virtualization isolation for agents that are very poorly trusted, or for customers who require a VM boundary: each Execution would run in its own microVM with its own guest kernel, so a guest-kernel exploit stays inside the VM.
It is an additional profile beside the container profile, not a replacement: the container profile on `runc` with the `CgroupBpfBackend` remains the default.

### What is reused as it is

- The `CgroupBpfBackend` and its B1-B7 qualification, for the container profile.
- The egress proxy, destination policy, DNS resolution and address validation, which do not depend on the sandbox.
- The Supervisor: one Execution per call, admission queue, readiness, fail-closed helper loss and typed refusal classes.
- The durable-state and recovery model of S13, applied to the new backend's objects, and the rule that unknown state is refused and preserved.
- The qualification method: B1-B7-style gates, checksummed and fingerprinted evidence, residue measured before any harness teardown, and `spike:qualify` once it exists.
- cgroup-BPF as defense in depth: the host-side Firecracker process still runs in a cgroup, and the shared programs can keep it from opening host sockets of its own.

### What must be built for it

- A `SandboxBackend` for microVMs: the jailer, microVM start and teardown, the rootfs as a block device, and agent communication over vsock or the network.
- An `EnforcementBackend` at the TAP boundary. Inside a microVM the agent's sockets live in the guest kernel and are invisible to host cgroup hooks, so socket-cookie attribution does not apply; the trusted identity is the microVM and its TAP device, one per microVM, closer to the `netns-nft` design, with the Soglia proxy as the only exit.
- Its own qualification gates, analogous to B1-B7, for that backend.

### Caution: snapshots and the warm pool

Firecracker's fast start uses snapshots, and restoring several microVMs from one snapshot copies one memory state into all of them: the same random-generator state and the same memory layout, as with a forked zygote.
Firecracker's own documentation flags this.
A warm pool on this profile must reseed entropy in every clone, or use microVMs prepared fresh rather than cloned from a shared snapshot, so that no two calls share generator state.
