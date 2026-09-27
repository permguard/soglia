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
| #1 | `soglia-spike-replay-20260927T161150Z-98802-r1` | [`replay-1790525576624-5754`](evidence/replay/replay-1790525576624-5754/) | 16/16 PASS; terminal `COMPLETE/PASS` | PASS; 1,299 registry entries, zero live |
| #2 | `soglia-spike-replay-20260927T161150Z-98802-r2` | [`replay-1790525780260-5753`](evidence/replay/replay-1790525780260-5753/) | 16/16 PASS; terminal `COMPLETE/PASS` | PASS; 1,299 registry entries, zero live |

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
`SHA-256(file)  path`, with the path relative to `spikes/cgroup-bpf-old/`; the
reported value is the SHA-256 of those manifest bytes.

| Test | Final historical evidence path | Files | Manifest SHA-256 |
| --- | --- | ---: | --- |
| S0 | [`evidence/s0`](../cgroup-bpf-old/evidence/s0/) | 60 | `6f77c7a351f418f3744763fd39d5a49be0a6c559dd5b72d54d18609cce951c53` |
| S1 | [`evidence/s1/port-fixed`](../cgroup-bpf-old/evidence/s1/port-fixed/) | 28 | `ec70717246cbddd7dcc9678c3d79d41397d5c9f0244303e6cdcedbfa7ef4c0f5` |
| S1b | [`evidence/s1b/race`](../cgroup-bpf-old/evidence/s1b/race/) | 29 | `be6b7fc82356a1031c556fdf53d5359ea32f0c419e7124d22a4fa6202a27d3c8` |
| S2 | [`evidence/s2/run2`](../cgroup-bpf-old/evidence/s2/run2/) | 32 | `1dbcdc8a5a338cf389059d6b6857b93ef5aa6b0951c6100ac48149adaf24ed2e` |
| S3 | [`evidence/s3`](../cgroup-bpf-old/evidence/s3/) | 88 | `f535a3ed03eaf7e138ed533d8bcca542b6e415f2f70bcde57b0109c0f1f7c255` |
| S4 | [`evidence/s4/run2`](../cgroup-bpf-old/evidence/s4/run2/) | 43 | `be8b7ea0abfe7f8e1f1a859610dfd16bdbe04e5d914acfb26d675a7f90b2e065` |
| S5 | [`evidence/s5/run3`](../cgroup-bpf-old/evidence/s5/run3/) | 15 | `de54a808fb7f634a98ab80e0d1bcd0fbc71b034c12b57819a9eb2d08eee0186a` |
| S6 | [`evidence/s6`](../cgroup-bpf-old/evidence/s6/) | 13 | `d92bb86574bb0bdeeb22ecdf93587292e6ed56250575a8975f1407be059864cf` |
| S7 | [`evidence/s7/run2`](../cgroup-bpf-old/evidence/s7/run2/) | 39 | `af995971d8660faf538893167f6828f4c6096448eef7fe02bf046bb9e6eef149` |
| S8 | [`evidence/s8/after-fix-run6`](../cgroup-bpf-old/evidence/s8/after-fix-run6/) | 91 | `41ac538e58f711b9fd9ba38eed2c8e86aacd99fece59114312ad65972f5f26f2` |
| S9 | [`evidence/s9/run4`](../cgroup-bpf-old/evidence/s9/run4/) | 62 | `2be1f9120a34264a43065e61fc68bd2326b7c0ec1b29f419e8e6059195d7b7c6` |
| S10 | [`evidence/s10/run3`](../cgroup-bpf-old/evidence/s10/run3/) | 73 | `8fb3684aafd84ba7a3f52a6ee34da2066b9e5532fc9423c43195265a6d6c039e` |
| S11 | [`evidence/s11/run1`](../cgroup-bpf-old/evidence/s11/run1/) | 104 | `3d53036452daf1688c0edf8cb851ef68d9b7d8c7b225e7a96cd94bd67de1f633` |
| S12 | [`evidence/s12/run1`](../cgroup-bpf-old/evidence/s12/run1/) | 47 | `541c2b9ae353bacd85c293dbad6c496218169a73a259a3366118ca791142854a` |
| S13 | [`evidence/s13/run2`](../cgroup-bpf-old/evidence/s13/run2/) | 118 | `5eb2a0195d46a1b7202942c2a619cf572a522200b2cdb712e542c4561db317aa` |
| S14 | [`evidence/s14/run1`](../cgroup-bpf-old/evidence/s14/run1/) | 316 | `054c3e4fa19060805625de12ef93cbca624eea7fe0d2457df6025fe59fe7f715` |

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

Candidate A/B/C/D remains unselected. This review does not start candidate
review or B1-B7, and it makes no production change.
