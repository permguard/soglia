<!-- Copyright (c) 2022 Nitro Agility S.r.l. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# S6 actual enforcement-layer table

This table is generated only from structured observations in this same replay. It selects no attribution candidate.

| Property | Primary observed enforcement | Other observed constraint / defense | Negative or isolation evidence | Sources |
| --- | --- | --- | --- | --- |
| Live process belongs to the current Execution | trusted launcher/runtime placement into the delegated cgroup | owned netns entry checked independently by inode | live PID, /proc cgroup, cgroup.procs and netns inode agree | s1, s2 |
| IPv6 stream socket creation is rejected early | cgroup-BPF sock_create | connect6 remains an independent later gate | relaxing only IPv6 stream creation makes socket creation succeed | s5 |
| Direct IPv4 TCP is rejected early | cgroup-BPF connect4 | namespace nft output policy remains the final destination barrier | exact nft relaxation still denies with BPF; omitting only connect4 exposes the listener | s4, s5 |
| IPv6 TCP connect is rejected | cgroup-BPF connect6 | sock_create is the earlier independent gate | with creation relaxed, omitting only connect6 exposes the IPv6 listener | s5 |
| IPv4 UDP emission is rejected | cgroup-BPF sendmsg4 | sock_create and namespace nft are separate gates | with datagram creation relaxed, omitting only sendmsg4 delivers the datagram | s5 |
| IPv6 UDP emission is rejected | cgroup-BPF sendmsg6 | sock_create and namespace nft are separate gates | with datagram creation relaxed, omitting only sendmsg6 delivers the datagram | s5 |
| Only the proxy destination is reachable normally | namespace nft output chain | connect4 is earlier IPv4 defense; route/forward policy constrains topology | BPF-permissive normal control is blocked until one exact nft exception is added | s4 |
| Candidate A/B state is captured for admitted IPv4 proxy connect | cgroup-BPF connect4 | sockops later consumes it | sockops omission retains one cookie but publishes no final tuple | s5 |
| Accepted tuple becomes resolvable | cgroup-BPF sockops publishes; proxy correlates | IP remains a cross-check only | omitting only sockops leaves established TCP without tuple publication | s1, s5 |
| Missing/delayed attribution does not authorize | proxy bounded Resolve | BPF maps provide evidence but do not authorize | missing publication times out without read, DNS, effect or IP fallback | s1b, s5 |
| Concurrent sockets are not cross-attributed | per-socket/per-instance evidence plus proxy tuple correlation | source IP is not authorization | 132 sockets across four Executions produce zero cross-attribution | s2 |
| Old lifecycle state does not authorize a new generation | sockops close cleanup plus runner-owned Execution teardown | map teardown removes remaining test state | FIN/RST reuse and SIGKILL generations show zero cross-generation attribution/residue | s3, s5 |

Later properties remain explicitly unestablished: loader loss (S7), helper death (S8), and foreign ancestor execution/order (S9/S10).
