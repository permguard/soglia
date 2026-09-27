<!-- Copyright (c) 2022 Nitro Agility S.r.l. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# S6 actual enforcement-layer table

This table reports only behavior exercised by S1–S5 on Linux 6.8.0-134.
“Primary” means the layer whose isolated removal or relaxation exposed the tested behavior.
“Defense-in-depth” means a separately demonstrated second barrier.
“Not established” prevents intended architecture from being presented as runtime fact.

| Property | Primary observed enforcement | Other observed constraint / defense | Negative or isolation evidence | Raw evidence |
| --- | --- | --- | --- | --- |
| Live process belongs to the current Execution | trusted launcher/runtime placement into the delegated cgroup | owned netns entry is separately checked by inode | the first S1 diagnostic previously found wrong subject placement; all passing runs compare the live PID, `/proc/<pid>/cgroup`, `cgroup.procs` and netns inode | [S1 membership](../s1/port-fixed/s1-membership.txt), [S2 mappings](../s2/run2/s2-membership.txt) |
| IPv6 stream socket creation is rejected early | cgroup-BPF `sock_create` | later `connect6` is an independent second gate | default denied creation with one BPF deny; relaxing only IPv6 creation made the identical `socket()` succeed | [S5 run](../s5/run3/s5-harness.txt) |
| Datagram socket creation is rejected early | cgroup-BPF `sock_create` | `sendmsg4/6` remain independent later gates when creation is relaxed | S5 datagram-relaxed variants reached the send hooks; default socket-family/type policy is characterized separately by S0/S5 | [S5 run](../s5/run3/s5-harness.txt) |
| Direct IPv4 TCP to a non-proxy destination is rejected early | cgroup-BPF `connect4` | namespace nft output policy is the final destination barrier | with the one nft exception present, `connect4` produced exactly one deny and no accept; omitting only `connect4` with an exposed path established to the listener | [S4 summary](../s4/run2/s4-summary.txt), [S4 nft states](../s4/run2/s4-nft-during.txt), [S5 run](../s5/run3/s5-harness.txt) |
| IPv6 TCP connect is rejected | cgroup-BPF `connect6` | `sock_create` normally rejects before connect; S5 relaxed it to expose `connect6` | `connect6` present denied with no accept; omitting only `connect6` established to the IPv6 listener | [S5 run](../s5/run3/s5-harness.txt) |
| IPv4 UDP emission is rejected | cgroup-BPF `sendmsg4` | `sock_create` normally rejects datagram creation; namespace nft remains a later packet barrier | with creation relaxed, `sendmsg4` present denied/no delivery; omitting only it delivered `probe` | [S5 run](../s5/run3/s5-harness.txt) |
| IPv6 UDP emission is rejected | cgroup-BPF `sendmsg6` | `sock_create` normally rejects datagram creation; namespace nft remains a later packet barrier | with creation relaxed, `sendmsg6` present denied/no delivery; omitting only it delivered `probe` | [S5 run](../s5/run3/s5-harness.txt) |
| Only the proxy destination is reachable in the normal Execution policy | namespace nft output chain is the final packet/destination barrier | `connect4` is an earlier deny for IPv4; namespace route and host-forward drop constrain topology | S4 BPF-permissive control still could not reach the direct target under normal nft, while proxy connected; adding one exact nft exception exposed the direct path when BPF was also relaxed | [S4 before/during/after nft](../s4/run2/s4-nft-before.txt), [S4 run](../s4/run2/s4-harness.txt) |
| Candidate A/B state is captured for an admitted IPv4 proxy connect | cgroup-BPF `connect4` | `sockops` later consumes it for tuple evidence | S5 omission of `sockops` retained one connect4 cookie but produced no final tuple | [S5 run](../s5/run3/s5-harness.txt) |
| Established socket becomes resolvable by accepted tuple | cgroup-BPF `sockops` publishes the tuple/evidence map | proxy performs the trusted lookup and validates current Execution identity | omitting only `sockops` left the TCP established at the proxy but tuple count stayed zero for 2 s | [S1 chain](../s1/port-fixed/s1-harness.txt), [S5 run](../s5/run3/s5-harness.txt) |
| Missing or delayed tuple attribution does not authorize | proxy bounded Resolve logic | BPF maps provide data but do not make the proxy authorization decision | delayed publication resolved only after promotion; deliberate missing publication timed out and closed with zero application read, DNS, outbound effect or IP fallback | [S1b run](../s1b/race/s1-harness.txt), [S5 run](../s5/run3/s5-harness.txt) |
| Concurrent live sockets are not cross-attributed | BPF per-socket/per-instance evidence plus proxy tuple correlation | source IP is only an independent cross-check | 132 overlapping sockets across four Executions produced zero cross-attribution; missing final state timed out instead of using IP | [S2 run](../s2/run2/s2-harness.txt) |
| Closed socket attribution is removed | cgroup-BPF `sockops` state callback deletes its tuple and candidate-A cookie | test-owned map teardown removes all remaining state at Execution teardown | FIN/RST generations reused source port without stale authorization; omitting `sockops` left a cookie until map cleanup, demonstrating its cleanup contribution | [S3 summary](../s3/s3-summary.txt), [S5 run](../s5/run3/s5-harness.txt) |
| Process death / Execution teardown does not leave test-owned authorization state | Execution lifecycle cleanup in the harness/supervising runner | socket close callbacks can remove per-socket state before teardown | SIGKILL produced the expected nonzero child result; runner cleanup removed maps, links, cgroup and topology before the next generation | [S3 process-kill](../s3/process-kill/s1-harness.txt), [S3 cleanup](../s3/s3-cleanup.txt) |
| Loader death while links are pinned | not established by S1–S5 | none claimed | reserved for S7 | — |
| Enforcer/helper death behavior | not established by S1–S5 | source observations are not runtime enforcement evidence | reserved for S8 | — |
| Foreign ancestor coexistence and execution order | attach compatibility only was established by S0.4 | actual behavior/order is not inferred from bpftool list order | reserved for S9/S10 | [S0.4 evidence](../s0/s04-exclusive.txt) |

## S6 classification

The table distinguishes actual primary enforcement, observed defense-in-depth, topology constraints and untested later properties without assigning an attribution candidate or changing the architecture.

`S6_RESULT=PASS`
