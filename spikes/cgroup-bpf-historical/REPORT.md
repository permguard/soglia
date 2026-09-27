<!-- Copyright (c) 2022 Nitro Agility S.r.l. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Phase-1 cgroup-BPF spike — final qualification report

> **STATUS: S0–S14 COMPLETE — HUMAN CANDIDATE REVIEW REQUIRED**
>
> - S0 / environment and preliminary build/licensing investigation: **EXECUTED**
> - S0 itself: **PASS** — S0.1, S0.2, S0.3, S0.4 and S0.5 all **PASS** (section 10); S0 makes no security claim
> - S1: **PASS** — final classification **S1_CHAIN_PROVEN** after the minimum spike-only port extraction fix
> - S1b: **PASS** — delayed publication and bounded fail-closed timeout proven
> - S2: **PASS** — zero cross-attribution across four concurrent Executions and 132 sockets
> - S3: **PASS** — lifecycle, FIN/RST, process kill and cross-generation port reuse proven fail-closed
> - S4: **PASS** — direct IPv4 remained unable to establish under a one-rule nft relaxation, attributed to cgroup-BPF by counters/event and a path-exposure control
> - S5: **PASS** — each of the six attached hooks was isolated with a deny/publication observation and a single-hook relaxation or omission control
> - S6: **PASS** — actual primary enforcement, defense-in-depth, topology constraints and untested layers are separated in an evidence-backed table
> - S7: **PASS** — pinned link/program/map identity and BPF denial survived abrupt loader loss; removing only the connect4 pin detached that gate
> - S8: **PASS AFTER PRODUCTION FIX** — the original run4 FAIL is preserved; after-fix-run6 proves autonomous Enforcer-loss detection and bounded fail-closed cancellation
> - S9: **PASS** — an invoked foreign ancestor ALLOW did not neutralize the child Soglia DENY; the same path established with the child permissive control
> - S10: **PASS** — an experimentally proven ancestor rewrite remained subject to nft's final-destination barrier; the exact nft exposure control reached the rewritten listener
> - S11: **PASS** — a representative complete lifecycle created every applicable owned resource class, resolved one proxy connection, then restored the owned baseline with zero residue
> - S12: **PASS** — proven-full tuple/cookie maps rejected one additional update; missing attribution timed out fail-closed and succeeded after one known entry was freed
> - S13: **PASS AFTER SPIKE-ONLY CONTRACT** — the original FAIL is preserved; run2 proves trusted ownership binding, exact sweep/recreate, incompatible/unknown fail-closed behavior and crash-safe readiness ordering
> - S14: **PASS** — Candidate C characterized at N=1/4/16/32; N=64 bounded at 44 complete instances by the loader's soft-FD limit, with exact `EMFILE` evidence and complete cleanup
> - B1–B7: **no evidence, NOT PASSED**
> - Spike harness: S0 loaders plus experimental S1/S1b, S2, S3, S4, S5, S7, S8, S9, S10, S11, S12, S13 and S14 runners; S6 is a read-only synthesis
> - Production `CgroupBpfBackend`: **NOT IMPLEMENTED**
> - Final attribution candidate (A/B/C/D): **NOT SELECTED**
> - S8: **EXPERIMENTALLY VERIFIED PASS AFTER FIX**, with the authoritative pre-fix FAIL preserved (section 9 and S8 detail in section 10)
> - No Phase-1 production design has been selected.

This report preserves every failed and diagnostic S1, S8, S9, S10, S11, S12, S13 and S14 attempt as well as their authoritative runs, and leaves the spike in a clean state.
Each PASS is limited to the property, topology and tested kernel stated below; S13's original FAIL remains historical evidence beside its authorized spike-contract rerun, and S14's raw N=64 limit exit remains beside the diagnostic that identified `EMFILE`.

Every statement below is tagged with what it is:

| Tag                    | Meaning                                                                    |
| ---------------------- | -------------------------------------------------------------------------- |
| **PROVEN ON KERNEL**   | Observed on the tested kernel `6.8.0-134-generic`, with the evidence given |
| **SOURCE OBSERVATION** | Read in source code; not verified by execution                             |
| **NOT TESTED**         | Expected or planned; no evidence yet                                       |

## 1. Environment

| Item                               | Value                                                                                          |
| ---------------------------------- | ---------------------------------------------------------------------------------------------- |
| Host                               | Apple M4 Max, macOS                                                                            |
| Lima                               | `limactl version 2.2.0` (Homebrew)                                                             |
| VM name                            | `soglia-spike`                                                                                 |
| VM config                          | [lima.yaml](lima.yaml): `vz`, aarch64, 4 CPUs, 8 GiB, 40 GiB disk                              |
| Image                              | `ubuntu-24.04-server-cloudimg-arm64.img`, release `20260705`                                   |
| Distribution                       | Ubuntu 24.04.4 LTS                                                                             |
| Architecture                       | aarch64                                                                                        |
| Kernel                             | `Linux 6.8.0-134-generic #134-Ubuntu SMP PREEMPT_DYNAMIC Fri Jun 26 18:28:11 UTC 2026 aarch64` |
| systemd                            | 255 (255.4-1ubuntu8.16)                                                                        |
| cgroup v2                          | `/sys/fs/cgroup` is `cgroup2fs`, mounted `rw,nsdelegate,memory_recursiveprot`                  |
| Root controllers                   | `cpuset cpu io memory hugetlb pids rdma misc`                                                  |
| bpffs                              | `bpf on /sys/fs/bpf type bpf (rw,nosuid,nodev,noexec,relatime,mode=700)`                       |
| BTF                                | `/sys/kernel/btf/vmlinux` present                                                              |
| `kernel.unprivileged_bpf_disabled` | `2`                                                                                            |

The repository is mounted writable at `/soglia` in the VM.
Build output lives on the VM's own disk under `/var/tmp/spike/`.

**BPF program types reported available** by `sudo bpftool feature probe kernel` (**PROVEN ON KERNEL**, as a probe result):

- `cgroup_sock`
- `cgroup_sock_addr`
- `cgroup_sockopt`
- `sock_ops`

**BPF map types reported available** by the same probe:

- `hash`
- `array`
- `lru_hash`
- `array_of_maps`
- `hash_of_maps`
- `cgroup_storage`
- `sk_storage`
- `ringbuf`
- `cgrp_storage`

The same probe lists, among others, `bpf_get_socket_cookie`, `bpf_get_current_cgroup_id`, `bpf_sk_storage_get`, `bpf_get_netns_cookie`, the ring-buffer helpers and `bpf_cgrp_storage_get` as supported for `cgroup_sock_addr`, `cgroup_sock` and `sock_ops`.
`bpf_sock_ops_cb_flags_set` is listed for `sock_ops`.
A bpftool probe listing says a helper exists for a program type; it says nothing about the licence a program needs to call it.
Licence behaviour is established only by the loads in section 5.

The full `bpftool feature probe kernel` output and the BPF lines of `/boot/config-$(uname -r)` are now saved in [evidence/s0/](evidence/s0/) (S0.1, section 10).

S0 later completed all of these prerequisites; section 10 and [evidence/s0/](evidence/s0/) are authoritative.

## 2. Installed toolchain and packages

| Component                     | Version                                                                                                                                                                                                                                                    |
| ----------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| clang                         | Ubuntu clang 18.1.3 (package `1:18.0-59~exp2`)                                                                                                                                                                                                             |
| llvm                          | 18.1.3 (package `1:18.0-59~exp2`)                                                                                                                                                                                                                          |
| bpftool                       | v7.4.0, using libbpf v1.4: `/usr/sbin/bpftool` is a wrapper from `linux-tools-common` that runs `/usr/lib/linux-tools-6.8.0-134/bpftool` (package `linux-tools-6.8.0-134-generic`); the libbpf 1.4 it reports is its own, distinct from `libbpf-dev` 1.3.0 |
| runc                          | 1.3.4-0ubuntu1~24.04.1                                                                                                                                                                                                                                     |
| Rust                          | rustc 1.97.1 (8bab26f4f 2026-07-14), cargo 1.97.1, via rustup, profile `minimal`                                                                                                                                                                           |
| Rust target                   | `aarch64-unknown-linux-musl`                                                                                                                                                                                                                               |
| libbpf-dev                    | 1:1.3.0-2build2                                                                                                                                                                                                                                            |
| linux-libc-dev                | 6.8.0-142.142                                                                                                                                                                                                                                              |
| libc6-dev                     | 2.39-0ubuntu8.7                                                                                                                                                                                                                                            |
| linux-tools-common            | 6.8.0-142.142                                                                                                                                                                                                                                              |
| linux-tools-6.8.0-134-generic | 6.8.0-134.134                                                                                                                                                                                                                                              |
| iproute2                      | 6.1.0-1ubuntu6.4                                                                                                                                                                                                                                           |
| nftables                      | 1.0.9-1ubuntu0.1                                                                                                                                                                                                                                           |
| jq                            | 1.7.1-3ubuntu0.24.04.2                                                                                                                                                                                                                                     |
| build-essential               | 12.10ubuntu1                                                                                                                                                                                                                                               |
| musl-tools                    | 1.2.4-2                                                                                                                                                                                                                                                    |
| Aya (Rust crate)              | 0.14.0 (MIT OR Apache-2.0), in the spike's `Cargo.lock`; used by the experimental loaders and S1/S1b harness                                                                                                                                               |

`linux-libc-dev` (6.8.0-142) is newer than the running kernel (6.8.0-134).
Both are the same 6.8 UAPI series; the objects were verified against the running kernel, not the header package.
`musl-tools` was added beyond the approved list because the spike agent is built as a static musl binary.

## 3. Header provenance

| Header                                        | Package          | Version         | License observed in the installed file                                                   |
| --------------------------------------------- | ---------------- | --------------- | ---------------------------------------------------------------------------------------- |
| `/usr/include/linux/bpf.h`                    | `linux-libc-dev` | 6.8.0-142.142   | `SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note`                               |
| `/usr/include/linux/types.h`                  | `linux-libc-dev` | 6.8.0-142.142   | `SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note`                               |
| `/usr/include/linux/in.h`                     | `linux-libc-dev` | 6.8.0-142.142   | `SPDX-License-Identifier: GPL-2.0+ WITH Linux-syscall-note`                              |
| `/usr/include/bpf/bpf_helpers.h`              | `libbpf-dev`     | 1:1.3.0-2build2 | `SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)`                                    |
| `/usr/include/bpf/bpf_helper_defs.h`          | `libbpf-dev`     | 1:1.3.0-2build2 | No SPDX line; header comment: "This is auto-generated file. See bpf_doc.py for details." |
| `/usr/include/bpf/bpf_endian.h`               | `libbpf-dev`     | 1:1.3.0-2build2 | `SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)`                                    |
| `/usr/include/aarch64-linux-gnu/sys/socket.h` | `libc6-dev`      | 2.39-0ubuntu8.7 | No SPDX line; GNU Lesser General Public License, version 2.1 or later                    |

`bpf_helper_defs.h` is included by `bpf_helpers.h`; it carries no licence line of its own, and its licensing follows libbpf's.
`<sys/socket.h>` supplies `AF_INET`, `AF_INET6`, `SOCK_STREAM` and `SOCK_DGRAM`.
The UAPI headers do not define them, but glibc's header compiles with `clang -target bpf` once the multiarch include path `-I/usr/include/aarch64-linux-gnu` is given.

The kfunc licence probe (`gpl_probe_kfunc.c`, section 5) also includes a `vmlinux.h`.
It is generated by `bpftool btf dump file /sys/kernel/btf/vmlinux format c` into the build output directory.
It is never committed, and it is used by that probe only.

Explicitly:

- no BPF helper declarations were hand-written;
- no third-party headers were vendored into the repository;
- no local ABI constants were required.

## 4. BPF build

**Sources** (all first-party, `Apache-2.0`, EXPERIMENTAL):

| File                                           | What it is                                                                                                                                                                                       |
| ---------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| [bpf/soglia_spike.c](bpf/soglia_spike.c)       | The evaluated hook set (`sock_create`, `connect4`, `connect6`, `sendmsg4`, `sendmsg6`, `sockops`), the evidence fields of candidates A–D, and the maps; test-only variants via `SPIKE_*` defines |
| [bpf/netns_probe.c](bpf/netns_probe.c)         | Candidate-D reference: socket cookie → netns cookie, for the harness's own cgroup                                                                                                                |
| [bpf/foreign.c](bpf/foreign.c)                 | Stand-in foreign ancestor programs for S9/S10 (`allow`, `rewrite`)                                                                                                                               |
| [bpf/gpl_probe.c](bpf/gpl_probe.c)             | Licence probe: `bpf_get_current_task_btf`                                                                                                                                                        |
| [bpf/gpl_probe_kfunc.c](bpf/gpl_probe_kfunc.c) | Licence probe: kfunc `bpf_cgroup_from_id` with `bpf_cgrp_storage_get`                                                                                                                            |

**Program license string** in every object: `char LICENSE[] SEC("license") = "Apache-2.0";`

**Build command:**

```sh
limactl shell --workdir /soglia soglia-spike -- spikes/cgroup-bpf/build.sh /var/tmp/spike/bpf
```

[build.sh](build.sh) compiles with:

```sh
clang -target bpf -O2 -g -Wall -Werror -I/usr/include/$(gcc -dumpmachine) -c <source> -o <object>
```

**Generated objects** in `/var/tmp/spike/bpf/` (sha256):

| Object                       | Variant                                       | sha256                                                             |
| ---------------------------- | --------------------------------------------- | ------------------------------------------------------------------ |
| `soglia.o`                   | production-shaped (no `SPIKE_*`)              | `2b1b76e1f8561071a6a129169683879c2874c7bcd874aa7853adafbead51fceb` |
| `soglia-relax-inet6.o`       | `SPIKE_RELAX_INET6_STREAM`                    | `fa02df53ca73521f15cc1c6fd9f96d8123ee6077efd65badb0ed0fd152f650c3` |
| `soglia-relax-dgram.o`       | `SPIKE_RELAX_DGRAM`                           | `6e2dd7e1b5b491dc0ade5e2d653d08272270a7158bf98f963dc2292a7f0d2c9f` |
| `soglia-relax-all.o`         | both relaxations                              | `3346da87d6a3b4341ef3ba95378f32924d5806c6e186c24175c69d35c1dcfd67` |
| `soglia-relax-inet6-diag.o`  | IPv6 creation relaxation plus diagnostics     | `b3472f9b76bd284987377e6cd576331d0b170e5ffdfe43bfc3091c29611aa254` |
| `soglia-relax-dgram-diag.o`  | datagram creation relaxation plus diagnostics | `c4783c6d9dde9e18826b33682d7f57ea753a64a77a041bf1253e840961dcd194` |
| `soglia-delay.o`             | `SPIKE_DELAY_PUBLISH`                         | `187f0079acc2e1946812b51c1a0b96c56043038a517c81ec2167abe1d5f81ffe` |
| `soglia-delay-diag.o`        | delay plus `SPIKE_DIAGNOSTIC`                 | `1aacd88387975b9ef2f392169ff3cf70e27c4f461aa6c0d056c3c203f72640d4` |
| `soglia-small.o`             | `SPIKE_TUPLE_MAX=8`                           | `b4dc95d4bcd3e3b660a8c7f0f68c4c42941ae84498170318ce8777026476a871` |
| `soglia-trace.o`             | `SPIKE_TRACE`                                 | `41921b0c0615f70c7056ba3ce69ebe8a714c788d4b5a5dbdcef266c293d33a53` |
| `soglia-diag.o`              | `SPIKE_DIAGNOSTIC`                            | `82fc10841f90f70f73068a3a819702d5ec1ee300c8845e8c72d48d3e84fbdac8` |
| `soglia-direct-control.o`    | S4-only direct-path negative control          | `191383d0588dd764914f981e4c3ed0f31fdbc2b5b7274156e52e2c3718878a35` |
| `netns-probe.o`              | —                                             | `96c5675a15c88683d1bbf08f4810e9d04fcc6c0385186cc3cf72bc4c1dd6d8f4` |
| `foreign.o`                  | —                                             | `5d8afe054da170c813b232ac7bd00de45da1483687c05dc328904c1eadf2395e` |
| `gpl-probe-task-btf.o`       | `PROBE=1`                                     | `001f0c728c25e99e85826b86a1560666d33b43eb67e47228fed7dc45ae11f798` |
| `gpl-probe-cgroup-from-id.o` | kfunc probe, against generated `vmlinux.h`    | `cfe30345ab66b349e21eee2d93289607573b82e6829267221779c431d00d712c` |

The hashes identify these builds; they are not expected to be reproducible bit for bit on another toolchain.

**Warnings and errors:** none; the build runs with `-Werror`.

One build issue was found and resolved during the investigation.
A hand-written forward declaration of the kfunc `bpf_cgroup_from_id` was refused by libbpf before loading: `extern (func ksym) 'bpf_cgroup_from_id': func_proto [22] incompatible with vmlinux [143917]`.
The kfunc probe was therefore moved to `gpl_probe_kfunc.c`, compiled against the generated `vmlinux.h`.

A successful compile or load is not evidence of runtime correctness.
None of these programs has been attached to a cgroup, and none has processed a socket.

## 5. Licensing and helper evidence

All loads used `sudo bpftool prog loadall <object> /sys/fs/bpf/verify-<name>`, which loads every program of an object through the kernel verifier without attaching any.
Every program carried `SEC("license") = "Apache-2.0"`.
The temporary pins were removed after each load.
`loadall` also pinned the objects' `LIBBPF_PIN_BY_NAME` maps under `/sys/fs/bpf/`; they were removed, and `/sys/fs/bpf/` is empty at the time of writing.

| Object                       | Programs                                                                                                           | Verdict                                                                         | Status               |
| ---------------------------- | ------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------- | -------------------- |
| `soglia.o`                   | `soglia_sock_create`, `soglia_connect4`, `soglia_connect6`, `soglia_sendmsg4`, `soglia_sendmsg6`, `soglia_sockops` | Loaded                                                                          | **PROVEN ON KERNEL** |
| `netns-probe.o`              | `soglia_netns_probe` (`cgroup/sock_create`)                                                                        | Loaded                                                                          | **PROVEN ON KERNEL** |
| `foreign.o`                  | `foreign_allow`, `foreign_rewrite` (`cgroup/connect4`)                                                             | Loaded                                                                          | **PROVEN ON KERNEL** |
| `gpl-probe-task-btf.o`       | `probe_task_btf` (`cgroup/connect4`)                                                                               | Rejected: `cannot call GPL-restricted function from non-GPL compatible program` | **PROVEN ON KERNEL** |
| `gpl-probe-cgroup-from-id.o` | `probe_cgroup_from_id` (`cgroup/connect4`)                                                                         | Rejected: `cannot call kernel function from non-GPL compatible program`         | **PROVEN ON KERNEL** |

The variant objects (`soglia-relax-*`, `soglia-delay`, `soglia-small`, `soglia-trace`) compiled but were **not** load-tested.

**Helper set actually used by `soglia.o`**, taken from `llvm-objdump -d soglia.o` (helper call IDs) and matched against `/usr/include/bpf/bpf_helper_defs.h`:

| ID  | Helper                      | Called from (per source)                                   | Accepted under `Apache-2.0` |
| --: | --------------------------- | ---------------------------------------------------------- | --------------------------- |
| 1   | `bpf_map_lookup_elem`       | all programs                                               | yes (object loaded)         |
| 2   | `bpf_map_update_elem`       | all programs                                               | yes (object loaded)         |
| 3   | `bpf_map_delete_elem`       | `soglia_sockops`                                           | yes (object loaded)         |
| 5   | `bpf_ktime_get_ns`          | event emission, `soglia_sockops`                           | yes (object loaded)         |
| 46  | `bpf_get_socket_cookie`     | `soglia_connect4/6`, `soglia_sendmsg4/6`, `soglia_sockops` | yes (object loaded)         |
| 59  | `bpf_sock_ops_cb_flags_set` | `soglia_sockops`                                           | yes (object loaded)         |
| 80  | `bpf_get_current_cgroup_id` | `sock_create`, `connect4/6`, `sendmsg4/6`, `sockops`       | yes (object loaded)         |
| 107 | `bpf_sk_storage_get`        | `soglia_connect4`, `soglia_sockops`                        | yes (object loaded)         |
| 122 | `bpf_get_netns_cookie`      | `soglia_sockops`                                           | yes (object loaded)         |
| 130 | `bpf_ringbuf_output`        | event emission                                             | yes (object loaded)         |

Because the whole object loaded under a non-GPL licence, the verifier accepted every call site listed above in the program type it appears in, on this kernel (**PROVEN ON KERNEL**).
`bpf_sk_storage_delete` is not used.
`bpf_get_netns_cookie` is also used by `netns-probe.o`, which runs as `cgroup/sock_create`, and that object loaded too.

**NOT TESTED:**

- the `gpl_only` flag of each helper in the kernel source; only verifier behaviour was recorded;
- verifier acceptance on other kernel versions;
- whether any helper behaves as the spike needs at runtime.

## 6. CGRP_STORAGE finding

The evaluated `CGRP_STORAGE` path was not viable on the tested kernel under the approved non-GPL program-licence constraints.
`bpf_cgrp_storage_get` needs a `struct cgroup *` argument.
Both routes to such a pointer from a `cgroup/connect4` program were refused by the verifier under `Apache-2.0`:

1. helper route: `bpf_get_current_task_btf` → `cannot call GPL-restricted function from non-GPL compatible program`;
2. kfunc route: `bpf_cgroup_from_id` → `cannot call kernel function from non-GPL compatible program`.

This does not establish that `CGRP_STORAGE` is impossible in general.
It establishes only that these two routes, from this program type, on this kernel, need a GPL-compatible program licence.
Changing the licence is not approved and was not attempted.

HASH-based cgroup state, a `BPF_MAP_TYPE_HASH` keyed by cgroup id, remains available as a candidate.
Its programs are in `soglia.o`, which loaded under `Apache-2.0`.
Its runtime behaviour is **NOT TESTED**.

## 7. Candidate D

Established facts (**PROVEN ON KERNEL**):

- `bpf_get_netns_cookie` is available to the tested `sock_ops` program (`soglia_sockops` in `soglia.o`) and to the tested `cgroup/sock_create` program (`netns-probe.o`);
- both loaded under the approved non-GPL licence `Apache-2.0`.

Candidate D is **not validated**.
S1–S3 recorded its netns cookie, including distinct cookies across the S3 netns lifecycle, but did not exercise the trusted owner mapping required to validate candidate D, so the following remain unproved:

- the trusted live owner mapping from netns cookie to Execution;
- stale-state behaviour when candidate D is actually used to authorize;
- owner-map lifecycle safety across destroyed and recreated netns;
- authorization-independent comparison of BPF identity with the observed IP/veth identity;
- lifecycle safety for delayed state across teardown and reuse.

Candidates A, B and C are not selected.
The final S1 run exercised all three from the correctly placed agent: candidate A and B published cgroup id 14646 and candidate C published identity 1001001; the corrected tuple key matched the accepted socket and Resolve returned the current Execution.
No candidate has been eliminated, except the `CGRP_STORAGE` state option of section 6.

## 8. Workspace and repository changes

Root product workspace, the only change outside `spikes/` (`git diff --stat -- Cargo.toml`: `1 file changed, 3 insertions(+)`):

```diff
 [workspace]
 resolver = "3"
 members = ["crates/*", "fixtures/*"]
+# Experiments with their own workspaces and lock files. Nothing under `spikes/` is part of the
+# product, and nothing here may depend on it.
+exclude = ["spikes"]
```

Spike tree, untracked in git (`?? spikes/`):

```text
spikes/cgroup-bpf/Cargo.toml         spike workspace: members harness, agent; unsafe_code = "forbid"
spikes/cgroup-bpf/Cargo.lock         its own lock file
spikes/cgroup-bpf/lima.yaml          VM config
spikes/cgroup-bpf/build.sh           BPF build
spikes/cgroup-bpf/bpf/*.c            BPF sources (section 4)
spikes/cgroup-bpf/agent/             spike agent, std + rustix
spikes/cgroup-bpf/harness/           S0 loaders plus the experimental S1 attribution harness
spikes/cgroup-bpf/run-s1.sh          disposable S1 cgroup/netns/veth/nft topology and evidence runner
spikes/cgroup-bpf/run-s2.sh          disposable multi-Execution S2 topology and evidence runner
spikes/cgroup-bpf/run-s3.sh          FIN/RST/process-kill lifecycle sequence using fresh topologies
spikes/cgroup-bpf/REPORT.md          this report
```

| Item            | Status                                                                                                                                                                                                                                             |
| --------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Agent           | Builds: `cargo build --release -p soglia-spike-agent --target aarch64-unknown-linux-musl`; S1 and S1b ran it in the experimental namespace topology                                                                                                |
| Harness         | S0 loaders remain; `harness/src/bin/s1_attribution.rs` (sha256 `ed95b18f…ed33`) implements S1/S1b attach, host-first placement, bounded Resolve, delayed publication and classification; `run-s1.sh` owns disposable topology and evidence capture |
| Production code | Modified only for the authorized S8 lifecycle/fail-closed fix; no cgroup-BPF backend or Phase-1 attribution candidate was selected                                                                                                                 |

`harness/src/main.rs` carries the project licence header; since S0.3 it is the S0.3 loader (sha256 `ebe95619…af13`), not a placeholder.

Hygiene at handoff:

| Check                               | Result                                                                                    |
| ----------------------------------- | ----------------------------------------------------------------------------------------- |
| `git diff --check`                  | Clean                                                                                     |
| `task check:headers`                | `ok: every tracked source file carries the licence header` (it checks tracked files only) |
| Header check on untracked `spikes/` | Every file carries the header, except `Cargo.lock`, which the header check always skips   |
| Trailing whitespace in `spikes/`    | None                                                                                      |

## 9. S8 source observation, production fix and regression result

Status: **PASS AFTER PRODUCTION FIX — EXPERIMENTALLY VERIFIED**.

Before the fix, reading the Phase-0 runtime showed:

- **Helper loss appears to be detected only after a later helper operation fails.** `Supervisor::on_helper_error` (`crates/soglia-supervisor/src/supervisor.rs`) sets the fatal signal only when a helper call returns `HelperError::Channel`. No watch on an idle helper channel was found.
- **Existing tunnels appear able to stay alive during a normal stop.** In `src/main.rs`, `serve` sends `stop`. In `crates/soglia-proxy/src/egress.rs`, `EgressProxy::serve` returns from its accept loop on that signal. Connection tasks already spawned end only when their connection ends or their attribution is revoked. Revocation happens in a per-Execution teardown, which in turn needs a working enforcer call.

The source observation was tested on the running Phase-0 runtime. It was accurate: killing the
actual Enforcer child did not notify the Supervisor while no helper RPC was in progress. During that
undetected interval an existing CONNECT tunnel remained usable, DNS completed, and a new outbound
connection was established by an already-admitted Execution. A later admission's Enforcer RPC
observed `EPIPE`, stopped admissions and closed the ingress listener. The complete measurement and
classification remain preserved as [evidence/s8/run4/](evidence/s8/run4/).

The production fix gives each helper a direct child-exit watcher and routes lifecycle exit and
permanent IPC loss through one idempotent Supervisor transition.
That transition closes admission, broadcasts runtime cancellation, closes active ingress and egress
connections including CONNECT tunnels and pending DNS/connect/HTTP futures, and closes sandboxd's
channel so its trusted EOF path kills every live Execution.
Startup still completes both helper hello/sweep operations before `startup.ready`, and a helper that
exits between hello and readiness is now detected by the already-running watcher.

The post-fix regression at [evidence/s8/after-fix-run6/](evidence/s8/after-fix-run6/) sent `SIGKILL`
to the actual Enforcer without issuing a later RPC.
The lifecycle transition was journaled after 8 ms, polling observed it within 109 ms,
ingress was observed closed within 119 ms, agents were gone within 125 ms, the existing tunnel was
closed within 130 ms, and the failed runtime exited within 131 ms.
No post-loss application pulse, DNS/new outbound connection, or fourth admission occurred during a
7,039 ms observation window.
Restart swept all recorded resources before `startup.ready`, and final cleanup passed.

## 10. Test matrix

| Id  | Test                                 | Status                                                                                                                   |
| --- | ------------------------------------ | ------------------------------------------------------------------------------------------------------------------------ |
| S0  | Environment                          | **PASS**: S0.1, S0.2, S0.3, S0.4, S0.5 all PASS (see "S0 in detail" below); no security claim                            |
| S1  | End-to-end attribution               | **PASS**: final classification **S1_CHAIN_PROVEN**; cleanup PASS                                                         |
| S1b | Delayed attribution / race tolerance | **PASS**: 64 delayed resolves plus one timeout deny; cleanup PASS                                                        |
| S2  | Concurrency                          | **PASS**: 132 concurrent sockets, zero cross-attribution; cleanup PASS                                                   |
| S3  | Stale state / port or object reuse   | **PASS**: FIN/RST/kill and source-port reuse across three fresh generations; cleanup PASS                                |
| S4  | IPv4 BPF deny                        | **PASS**: one-rule nft relaxation, BPF deny attribution and path-exposure control proven                                 |
| S5  | Individual hook isolation            | **PASS**: all six hooks isolated with single-hook relaxation/omission controls                                           |
| S6  | Actual enforcement-layer table       | **PASS**: S1–S5 observations assigned to actual layers; untested S7+ properties left explicit                            |
| S7  | Pinned link lifetime                 | **PASS**: loader SIGKILL preserved IDs/pins/enforcement; connect4 unpin control exposed path                             |
| S8  | Enforcer death                       | **PASS AFTER FIX**: lifecycle detection autonomous; ingress/effects/Executions cancelled; restart sweep and cleanup PASS |
| S9  | Ancestor allow program               | **PASS**: invoked foreign ancestor ALLOW did not neutralize child DENY; permissive child control established             |
| S10 | Ancestor destination rewrite         | **PASS**: proven rewrite blocked by normal nft final barrier; exact nft exposure control reached rewritten listener      |
| S11 | Complete cleanup                     | **PASS**: representative lifecycle, ordered trusted teardown and ten-class zero-residue proof                            |
| S12 | Map exhaustion                       | **PASS**: tuple/cookie capacity and update failure proven; bounded deny and one-entry causal control passed              |
| S13 | Pinned state version / restart       | **PASS AFTER SPIKE CONTRACT**: original FAIL preserved; A–D, readiness and crash recovery pass                           |
| S14 | Candidate-C operational cost         | **PASS**: N=1/4/16/32 characterized; N=64 bounded by `RLIMIT_NOFILE` after 44 instances; attribution and cleanup PASS    |

S1, S1b, S2, S3, S4, S5, S7, S9, S10, S11 and S12 are the runtime security experiments marked PASS.
S6 is a PASS for its evidence-backed synthesis deliverable and introduces no new runtime security claim.
S8 is a runtime security experiment marked PASS after the authorized production fix and regression rerun.
S9, the S10 hard gate, S11 and S12 are PASS on the tested kernel; S13 passed only after the authorized spike-only ownership/compatibility contract. S14 characterized Candidate C without selecting it and preserved the bounded N=64 loader-FD limit.
The S0 checks S0.1–S0.5 make no security claim: they prove that the hooks attach and detach and how attachments compose, not that anything is enforced.
B1–B7 have no evidence and are **NOT PASSED**.

### S0 in detail

| Step | What it establishes                                                          | Status                                                                | Evidence                                                                                         |
| ---- | ---------------------------------------------------------------------------- | --------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------ |
| S0.1 | Environment, kernel config, sysctls, feature probe, versions                 | **PASS**                                                              | `env.txt`, `cgroup.txt`, `kconfig-bpf.txt`, `sysctl.txt`, `probe.txt`, `versions.txt`            |
| S0.2 | A real systemd-delegated cgroup subtree                                      | **PASS**                                                              | `delegation.txt`                                                                                 |
| S0.3 | Real link-based attach of each of the six hooks, and verified removal        | **PASS** (all six hooks)                                              | `attach.txt`, `attach-after-*.json/.txt`, `attach-removed-*.json/.txt`, plus the preflight files |
| S0.4 | Attach flags of a link attach; ancestor constraints; multi-program behaviour | **PASS** (coexistence characterised, cleanup and non-mutation proven) | `s04-*` files, `vm-logs/`                                                                        |
| S0.5 | S0 leaves no residue                                                         | **PASS**                                                              | `s05-cleanup.txt`, `s05-final-prog.json`, `s05-final-link.json`                                  |

All paths are relative to [evidence/s0/](evidence/s0/).
Every file starts with the command that produced it.
The two `cd: /Users/...` lines at the top of some outputs come from `limactl shell` trying to enter the macOS working directory inside the VM; the requested command runs after them.

#### S0.1 — environment: PASS

Checked against the saved files (**PROVEN ON KERNEL**):

- `env.txt`: Lima 2.2.0; `Linux 6.8.0-134-generic` aarch64; Ubuntu 24.04.4 LTS.
- `cgroup.txt`: `/sys/fs/cgroup` is `cgroup2fs`, mounted `nsdelegate,memory_recursiveprot`; root controllers `cpuset cpu io memory hugetlb pids rdma misc`; root `subtree_control` `cpuset cpu io memory pids`; bpffs mounted on `/sys/fs/bpf` with `mode=700`.
- `kconfig-bpf.txt`: `CONFIG_BPF_SYSCALL=y`, `CONFIG_CGROUP_BPF=y`, `CONFIG_DEBUG_INFO_BTF=y`, `CONFIG_BPF_JIT=y`, `CONFIG_BPF_JIT_ALWAYS_ON=y`, `CONFIG_BPF_UNPRIV_DEFAULT_OFF=y`, `CONFIG_NET_SOCK_MSG=y`, `CONFIG_BPF_LSM=y`.
- `sysctl.txt`: `kernel.unprivileged_bpf_disabled = 2` (consistent with `CONFIG_BPF_UNPRIV_DEFAULT_OFF=y`), `net.core.bpf_jit_enable = 1`, `net.core.bpf_jit_harden = 0`.
- `probe.txt`: program types `cgroup_sock`, `cgroup_sock_addr`, `sock_ops` and map types `hash`, `sk_storage`, `cgrp_storage`, `ringbuf` available.
- `versions.txt`: the versions of section 2, including the bpftool provenance.

`CONFIG_BPF_LSM=y` is recorded as an observation only; BPF-LSM stays outside Phase 1.

#### S0.2 — delegated subtree: PASS

From `delegation.txt` (**PROVEN ON KERNEL**):

- unit `soglia-spike-s0.service`, created with `systemd-run --unit=soglia-spike-s0 --property=Delegate=yes /tmp/soglia-s0-delegation.sh`;
- `Delegate=yes`, `DelegateControllers=cpu cpuset io memory pids`, `ControlGroup=/system.slice/soglia-spike-s0.service`;
- the service process started in the delegated root, and was moved to the leaf `runtime/`; the root's `cgroup.procs` then became empty;
- `+memory +pids` written to the root's `cgroup.subtree_control` without error; it then read `memory pids`;
- ownership `root:root`, directory mode `755`, control files `644`.

#### S0.3 — preflight facts (as collected before the attach)

Established from `attach-preflight.txt`, `attach-baseline-*.json` and `attach-foreign-baseline.txt` (**PROVEN ON KERNEL** for the state described, at the time of collection):

| Fact                         | Value                                                                                                                                                                                         |
| ---------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Delegated unit               | `soglia-spike-s0.service`, `active/running`, `MainPID 1536` (the script, ending in `sleep infinity`)                                                                                          |
| Delegated root               | `/sys/fs/cgroup/system.slice/soglia-spike-s0.service`, inode 5016, `subtree_control` `memory pids`, no processes                                                                              |
| Leaf of the unit's processes | `runtime/`, inode 5076                                                                                                                                                                        |
| Parent of Executions         | `executions/`, inode 5118, `subtree_control` `memory pids`                                                                                                                                    |
| Target cgroup                | `executions/s0-probe`, **inode 5160** (the expected `cgroup_id`), empty, `populated 0`                                                                                                        |
| BPF object                   | `/var/tmp/spike/bpf/soglia.o` in the VM only (not on the host), 46832 bytes, sha256 `05e426df7fbb09ef7bd4c3b50ac6ba5ed73b67c37b1b284871dd1a80124b3638`, equal to section 4                    |
| bpffs                        | `/sys/fs/bpf` empty                                                                                                                                                                           |
| Programs before S0.3         | 14, none of Soglia: `hid_tail_call` (tracing), `lima_ticker` (tracepoint), systemd `sd_devices`, `sd_fw_egress`, `sd_fw_ingress`                                                              |
| Links before S0.3            | 2, both foreign: id 1 `tracing`, id 2 `perf_event`                                                                                                                                            |
| Programs on `s0-probe`       | none attached, none effective                                                                                                                                                                 |
| Foreign cgroup programs      | systemd's `sd_devices` (`cgroup_device`) and `sd_fw_ingress`/`sd_fw_egress` (`cgroup_inet_ingress`/`egress`), flags `multi`, on sibling units only; no ancestor of `s0-probe` has any program |

`bpftool cgroup show <cgroup> -j` prints nothing at all, not `[]`, for a cgroup with no attachment.
`attach-baseline-cgroup.json` and `attach-baseline-cgroup-effective.json` are therefore empty files, and an empty file is the expected "nothing attached" form in later comparisons.

No real ancestor exercises cgroup-BPF composition over the Execution cgroups on this VM.
S9 and S10 therefore need the synthetic foreign program (`foreign.o`), as the plan foresees.

State re-verified before this update: the unit is still `active`, `runtime/` still holds PID 1536 (`bash /tmp/soglia-s0-delegation.sh`) and PID 1556 (`sleep infinity`), `s0-probe` is empty with inode 5160, nothing is effective on it, `/sys/fs/bpf` is empty, and the program and link sets equal the saved baseline.

#### S0.3 — validation checklist for the attach evidence

The attach is performed by the spike harness through Aya, as a `bpf_link`.
**SOURCE OBSERVATION:** in `aya-0.14.0/src/programs/cgroup_sock.rs`, `cgroup_sock_addr.rs` and `sock_ops.rs`, `attach` calls `bpf_link_create` when `KernelVersion::at_least(5, 7, 0)`, and otherwise falls back to a legacy `ProgAttachLink::attach` without any error.
The fallback is silent, so check 5 below, a `cgroup` link in `bpftool link show`, is what proves a link was created; the API returning success does not.
`bpftool cgroup attach` is not used for S0.3: it performs a legacy `BPF_PROG_ATTACH`, which creates no link.

Expected files in `evidence/s0/`:

1. `attach.txt`
2. `attach-after-cgroup.json`
3. `attach-after-link.json`
4. `attach-after-pins.txt`
5. `attach-removed-cgroup.json`
6. `attach-removed-link.json`
7. `attach-removed-bpffs.txt`

`attach.txt`, `attach-prog-before.json` and `attach-link-before.json` already exist (written at 06:35, before the preflight).
They hold a preparation record only: the unit's properties, the `runtime/` processes, inode 5160, an empty `s0-probe`, and the bpffs listing.
The two JSON files are identical to `attach-baseline-prog.json` and `attach-baseline-link.json`.
`attach.txt` contains no attach result yet, so it does not satisfy checks 1–3; the attach run must add its results to it, keeping the preparation record above them.

Raw outputs under `evidence/` keep trailing whitespace exactly as the tools printed it; `evidence/.gitattributes` disables git's whitespace check there, so the evidence need not be altered to be committed.

Checks applied to them:

| #   | Check                                                                                                                                                                                                                                                                                                |
| --- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1   | `attach.txt` names the command, Aya 0.14.0 (as in `Cargo.lock`), the sha256 of `harness/src/main.rs` (equal to the file in the repository), and the runtime sha256 of `soglia.o` equal to `05e426df…3638`                                                                                            |
| 2   | `attach.txt` states the globals: `proxy_ip4` 10.200.255.1 in network byte order (`__u32` in `.rodata`), `proxy_port` 15001 (`__u32`, host order), `exec_ident` 0 (`__u64`); map pin root `/sys/fs/bpf/soglia-spike/global/`; the six link pin paths                                                  |
| 3   | `attach.txt` lists, for each hook, the Aya program type, the numeric flags passed, and the result or exact error                                                                                                                                                                                     |
| 4   | `attach-after-cgroup.json` holds exactly six entries on `s0-probe`, with the attach types of the table below, and names `soglia_*` (the kernel truncates program names to 15 characters: `soglia_sock_cre` is expected)                                                                              |
| 5   | `attach-after-link.json` holds six links of type `cgroup` besides the two baseline links; each has `cgroup_id` 5160, the expected `attach_type`, and a `prog_id` present in check 4                                                                                                                  |
| 6   | `attach-after-pins.txt` shows six pins under `/sys/fs/bpf/soglia-spike/exec/s0-probe/`, and the eight by-name maps under `/sys/fs/bpf/soglia-spike/global/` (`soglia_policy`, `soglia_tuples`, `soglia_cookie_a`, `soglia_sk_b`, `soglia_events`, `soglia_counters`, `soglia_denies`, `soglia_meta`) |
| 7   | `attach-removed-cgroup.json` is empty, as the baseline                                                                                                                                                                                                                                               |
| 8   | `attach-removed-link.json` equals the baseline: links 1 and 2 only                                                                                                                                                                                                                                   |
| 9   | `attach-removed-bpffs.txt` shows `/sys/fs/bpf` empty, or `/sys/fs/bpf/soglia-spike` absent or empty                                                                                                                                                                                                  |
| 10  | Live cross-check at review time: the program set equals the baseline, and `s0-probe` is still empty                                                                                                                                                                                                  |

| Program              | Aya type         | Expected `attach_type` (libbpf naming, as bpftool prints it) |
| -------------------- | ---------------- | ------------------------------------------------------------ |
| `soglia_sock_create` | `CgroupSock`     | `cgroup_inet_sock_create`                                    |
| `soglia_connect4`    | `CgroupSockAddr` | `cgroup_inet4_connect`                                       |
| `soglia_connect6`    | `CgroupSockAddr` | `cgroup_inet6_connect`                                       |
| `soglia_sendmsg4`    | `CgroupSockAddr` | `cgroup_udp4_sendmsg`                                        |
| `soglia_sendmsg6`    | `CgroupSockAddr` | `cgroup_udp6_sendmsg`                                        |
| `soglia_sockops`     | `SockOps`        | `cgroup_sock_ops`                                            |

The exact strings are confirmed from the evidence, not assumed; a different spelling of the same attach type is not a failure.

Verdict per hook: **PASS** when checks 1–10 hold for it; **FAIL** when the attach is rejected; **UNPROVEN** when the attach succeeded but the link identity, type, `cgroup_id` or the verified removal cannot be established.
The `attach_flags` bpftool reports for these link attaches are recorded as an observation for S0.4, not as a kernel guarantee.
Any FAIL or UNPROVEN stops S0 before S0.4.

#### S0.3 — result: PASS

Reviewed independently from the raw files, with the chronology anchored in the VM's own journal rather than in the files' host modification times.

**Chronology** (VM clock, CEST; **PROVEN ON KERNEL** from `journalctl -u soglia-spike-s0.service`, `journalctl _COMM=sudo`, and file modification times inside the VM):

| Time            | Event                                                                                                                                                                |
| --------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 07:13:11.7      | harness binary `/var/tmp/spike/target/release/soglia-spike-harness` built                                                                                            |
| 07:13:25        | pre-attach check: `/sys/fs/bpf` empty, nothing attached to `s0-probe`                                                                                                |
| 07:13:41.59     | harness started (`sudo sh -c 'exec …/soglia-spike-harness …'`)                                                                                                       |
| 07:13:47.77–.79 | attached-state snapshots: `bpftool cgroup show s0-probe -j`, `bpftool link show -j`, `ls -la` of both pin directories                                                |
| 07:13:57.97     | stop file created; harness cleanup begins                                                                                                                            |
| 07:13:58.04     | harness log ends with `state=CLEANUP_COMPLETE`                                                                                                                       |
| 07:13:58.10–.12 | removed-state snapshots: `bpftool cgroup show s0-probe -j`, `bpftool link show -j`, `ls -la /sys/fs/bpf`, `test -e /sys/fs/bpf/soglia-spike`, `bpftool prog show -j` |
| 07:15:13.04     | first stop/start of `soglia-spike-s0.service`                                                                                                                        |
| 07:15:53.25     | second stop/start of `soglia-spike-s0.service`                                                                                                                       |

No `bpftool cgroup show` of the target ran between 07:13:58 and 07:15:13.
Every S0.3 snapshot therefore predates both restarts and was taken against the original `executions/s0-probe`, inode 5160.
The files' host modification times (07:14:44–07:15:03) record when the evidence was written into the repository, not when it was captured.

**Attached state** (`attach-after-cgroup.json`, `attach-after-link.json`, `attach-after-pins.txt`):

| Program              | prog id | `attach_type` (cgroup and link) | `attach_flags` | Link id | Link type | `cgroup_id` | Link pin                    |
| -------------------- | ------: | ------------------------------- | -------------- | ------: | --------- | ----------: | --------------------------- |
| `soglia_sock_create` | 683     | `cgroup_inet_sock_create`       | `multi`        | 3       | `cgroup`  | 5160        | `exec/s0-probe/sock_create` |
| `soglia_connect4`    | 684     | `cgroup_inet4_connect`          | `multi`        | 4       | `cgroup`  | 5160        | `exec/s0-probe/connect4`    |
| `soglia_connect6`    | 685     | `cgroup_inet6_connect`          | `multi`        | 5       | `cgroup`  | 5160        | `exec/s0-probe/connect6`    |
| `soglia_sendmsg4`    | 686     | `cgroup_udp4_sendmsg`           | `multi`        | 6       | `cgroup`  | 5160        | `exec/s0-probe/sendmsg4`    |
| `soglia_sendmsg6`    | 687     | `cgroup_udp6_sendmsg`           | `multi`        | 7       | `cgroup`  | 5160        | `exec/s0-probe/sendmsg6`    |
| `soglia_sockops`     | 688     | `cgroup_sock_ops`               | `multi`        | 8       | `cgroup`  | 5160        | `exec/s0-probe/sock_ops`    |

- Exactly six entries on `s0-probe`; each `prog_id` of links 3–8 is one of the six program ids, one to one.
- The baseline links 1 (`tracing`) and 2 (`perf_event`) were present and unchanged throughout.
- The eight by-name maps were pinned under `/sys/fs/bpf/soglia-spike/global/`: `soglia_cookie_a`, `soglia_counters`, `soglia_denies`, `soglia_events`, `soglia_meta`, `soglia_policy`, `soglia_sk_b`, `soglia_tuples`.
- Nothing was pinned at the bpffs root.

**Run record** (`attach.txt` and the harness log):

- runtime sha256 of `soglia.o` `05e426df…3638`, equal to section 4;
- harness `harness/src/main.rs` sha256 `ebe95619d402e91fb795eeed95807a515ffba237d54e35a1555d6718bd81af13`, equal to the file in the repository;
- Aya 0.14.0;
- globals `proxy_ip4` 10.200.255.1 as bytes `[0a, c8, ff, 01]`, `proxy_port` 15001, `exec_ident` 0;
- every hook attached with `CgroupAttachMode::Single`, numeric flags 0, result `SUCCESS`;
- no failure line in the harness log.

**Removed state** (`attach-removed-cgroup.json`, `attach-removed-link.json`, `attach-removed-bpffs.txt`):

- `bpftool cgroup show s0-probe -j` printed nothing, the same form as `attach-baseline-cgroup.json`;
- `bpftool link show -j` is identical to `attach-baseline-link.json`: links 1 and 2 only;
- `/sys/fs/bpf` empty and `/sys/fs/bpf/soglia-spike` absent.

At review time, after both restarts: no program named `soglia*` is loaded, no link of type `cgroup` exists, and `/sys/fs/bpf` is empty.

**Verdict:**

| Hook                 | Verdict  |
| -------------------- | -------- |
| `soglia_sock_create` | **PASS** |
| `soglia_connect4`    | **PASS** |
| `soglia_connect6`    | **PASS** |
| `soglia_sendmsg4`    | **PASS** |
| `soglia_sendmsg6`    | **PASS** |
| `soglia_sockops`     | **PASS** |

For each hook: a real `cgroup` link exists, the attach type is correct, `prog_id` is consistent between cgroup and link, `cgroup_id` is 5160, the link pin was observed, and removal is verified by bpftool and bpffs state, not by API return codes.

**Observations**, recorded without being generalised:

- **Flags.** A link attach made through Aya with `CgroupAttachMode::Single`, numeric flags 0, is reported by bpftool with `attach_flags` `multi`, on kernel 6.8.0-134. This is the input to S0.4a; it is not yet a documented guarantee.
- **Program names.** bpftool reported the full program names, such as `soglia_sock_create`, not the 15-character kernel name the checklist anticipated. This is not a failure.
- **Pin-to-link mapping.** `ls -la` proves each link pin existed; which link id each pin held was not recorded (`bpftool link show pinned <path>`). The six links and six pins match in number and name, and all six links were gone after unpinning.
- **Binary provenance.** The harness binary was built at 07:13:11 by `cargo build`, and the run's `cargo build` found it up to date. The binary itself was not hashed.
- **`attach.txt`** documents one restart (07:15:13, MainPID 17949, root inode 8952). The journal shows a second one at 07:15:53. The unit now has MainPID 22563, delegated-root inode 12456, and only `runtime/` below it.

**Inode 5160 is historical evidence only.** The cgroup it named was destroyed by the restarts and is not the current target of anything.

**S0.4 needs a new preflight** before any S0.4 setup:

1. verify, or recreate, the delegated hierarchy (`runtime/`, `executions/` with `+memory +pids`);
2. create and verify a fresh empty `executions/s0-probe`;
3. record its new inode (the new expected `cgroup_id`);
4. collect a fresh baseline of programs, links, the target's attached and effective programs, and bpffs.

Inode 5160 must not be reused for S0.4.

#### S0.4 — fresh preflight (attach observations not executed)

Collected in `s04-preflight.txt` and `s04-baseline-*.json` (**PROVEN ON KERNEL** for the state described, at 07:20 CEST):

| Fact                   | Value                                                                                                                                                                                   |
| ---------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Unit                   | `soglia-spike-s0.service` `active`, MainPID 22563, `NRestarts=0`, `Delegate=yes`, `DelegateControllers=cpu cpuset io memory pids`                                                       |
| Delegated root         | `/sys/fs/cgroup/system.slice/soglia-spike-s0.service`, inode 12456, `subtree_control` `memory pids`, no processes; `runtime/` holds PID 22563 (the script) and 22595 (`sleep infinity`) |
| Created                | `executions/` (inode 13326, `subtree_control` `memory pids`) and `executions/s0-probe`                                                                                                  |
| **S0.4 target**        | `executions/s0-probe`, **inode 13368** (`S0_4_TARGET_INODE`, the expected `cgroup_id`), empty, `populated 0`                                                                            |
| Programs on the target | none attached, none effective; no program on `/`, `system.slice`, the unit, or `executions/`                                                                                            |
| Links                  | 1 (`tracing`) and 2 (`perf_event`) only                                                                                                                                                 |
| Programs               | 15, none of Soglia; systemd's programs now have ids 1066–1084 and include `fwupd.service`                                                                                               |
| bpffs                  | `/sys/fs/bpf` empty                                                                                                                                                                     |

The systemd program ids differ from the S0.3 baseline: systemd reloaded them.
S0.4d must therefore compare with the `s04-baseline-*` files, not with the S0.3 baseline.
Unrelated systemd programs may appear or disappear during S0.4 as units start and stop; non-mutation is judged on the objects the test creates and on the foreign program.

**`foreign.o`** (`s04-foreign-object.txt`, static inspection, not loaded):

| Item       | Value                                                                                                         |
| ---------- | ------------------------------------------------------------------------------------------------------------- |
| Source     | `spikes/cgroup-bpf/bpf/foreign.c`, sha256 `4bd437eb05daf5790cc81ab65e5317cdb17883008a5d23b66297c5d3382d3a67`  |
| Object     | `/var/tmp/spike/bpf/foreign.o`, sha256 `5d8afe05…395e` (equal to section 4), built by `build.sh`              |
| Licence    | section `license` = `Apache-2.0`                                                                              |
| Programs   | `foreign_allow` and `foreign_rewrite`, both in section `cgroup/connect4` (attach type `cgroup_inet4_connect`) |
| Map        | `foreign_trace` (ring buffer), not pinned by name                                                             |
| Globals    | `proxy_ip4`, `proxy_port`, `rewrite_ip4`, `rewrite_port`, all `const volatile __u32`, default 0               |
| Id and tag | exist only once loaded; to be recorded at load time in S0.4b                                                  |

`foreign_allow` returns 1 on every call and only writes to its own ring buffer, so it is suitable for both the exclusive (S0.4b) and the multi (S0.4c) ancestor observation.
Two limitations apply when S0.4 runs:

1. Loading the object loads both programs; only `foreign_allow` may be attached. `foreign_rewrite` belongs to S10 and, with its default constants, would rewrite connects to `0.0.0.0:0`.
2. The foreign program's pins must live outside `/sys/fs/bpf/soglia-spike/`, so that Soglia and foreign objects stay distinguishable, and S0.4d must verify their removal too.

#### S0.4 — result: PASS

Reviewed independently from the raw files, with the chronology anchored in the VM journal.

**Validity of the target.** The unit journal has no entry after the 07:15:53 restart, and MainPID stayed 22563.
`executions/` kept inode 13326 and `s0-probe` inode 13368 through the whole run, and at review time.
The 07:20 preflight was therefore valid for every S0.4 run.

**Chronology** (VM clock, CEST, from `journalctl _COMM=sudo`):

| Time        | Event                                                                                                                                    |
| ----------- | ---------------------------------------------------------------------------------------------------------------------------------------- |
| 07:27:52    | run baseline (`s04-run-baseline-*`)                                                                                                      |
| 07:30:12.99 | exclusive run 1, non-authoritative (harness `af6891c2…`): `loadall`, legacy attach, child attempt, detach, unpin, `rmdir` by 07:30:13.19 |
| 07:30:50.04 | **exclusive run 2, authoritative** (harness `a225cb91…`): same sequence, cleaned by 07:30:50.24                                          |
| 07:31:39.49 | multi run 1, non-authoritative: child link created; snapshot script stopped early; cleaned by 07:31:39.77                                |
| 07:32:13.08 | **multi run 2, authoritative**: same sequence, cleaned by 07:32:13.34                                                                    |
| 07:32:55    | final snapshots (`s04-final-*`)                                                                                                          |

The non-authoritative runs left no residue in the authoritative ones.
During the authoritative exclusive run, the links were the baseline links only and the effective list held only that run's `foreign_allow`.
During the authoritative multi run, the only non-baseline link was that run's Soglia link.
Every `bpftool cgroup attach` in the journal names `foreign_allow`; **`foreign_rewrite` was loaded and pinned by `loadall`, and never attached.**

**Harness.** `harness/src/bin/s04_connect4.rs`, sha256 `a225cb91803d56ea7a79ba05d461c5e5167f6dc6b93a1844f9c53229d353c051`, equal to the file in the repository.
Its binary `/var/tmp/spike/target/release/s04_connect4` has sha256 `3396766f711a11a4cee1820202783dd42bf3f37473355304c6856df4e028adfb`, verified in the VM.
It attaches only `soglia_connect4`, through Aya, `CgroupAttachMode::Single`, numeric flags 0.
The four raw harness logs are preserved in `evidence/s0/vm-logs/`.

**S0.4a — observation.**
Child link attaches made with `Single` / flags 0 are reported by bpftool with `attach_flags` `multi`: in S0.3 for all six hooks, and in S0.4c for `soglia_connect4`.
This holds on kernel 6.8.0-134, with Aya 0.14.0; it is not generalised.

**S0.4b — exclusive ancestor** (`s04-exclusive.txt`, `s04-exclusive-ancestor.json`, `s04-exclusive-child.json`, `s04-exclusive-effective.json`, `s04-exclusive-link.json`):

| Item              | Evidence                                                                                                                                       |
| ----------------- | ---------------------------------------------------------------------------------------------------------------------------------------------- |
| Foreign program   | `foreign_allow`, id 1105, tag `824ab03dccc4ea22`, type `cgroup_sock_addr`, `gpl_compatible: false`, object sha256 `5d8afe05…`                  |
| Ancestor attach   | `bpftool cgroup attach <executions> cgroup_inet4_connect pinned …/foreign_allow`, no flag, i.e. legacy exclusive, flags 0                      |
| Ancestor state    | one entry, id 1105, `attach_type` `cgroup_inet4_connect`, `attach_flags` `""`                                                                  |
| Child attempt     | `soglia_connect4` only, Aya `CgroupSockAddr`, `Single`, flags 0                                                                                |
| Child result      | **rejected**: `SyscallError { call: "bpf_link_create", io_error: Os { code: 1, kind: PermissionDenied, message: "Operation not permitted" } }` |
| Child state after | direct: nothing; effective: only 1105 (`foreign_allow`); links: 1 and 2 only                                                                   |
| Foreign id/tag    | 1105 / `824ab03dccc4ea22` before and after the child attempt, other metadata identical                                                         |

Observation (**PROVEN ON KERNEL 6.8.0-134**): with a legacy exclusive `cgroup_inet4_connect` program on `executions/`, a link-based attach of the same attach type on its child `s0-probe` is refused with `EPERM`, and leaves no partial attachment.
The non-authoritative run 1 reached the same rejection; its log shows only Aya's outer message (`bpf_link_create failed`), which is why run 2 printed the nested errno.

**S0.4c — multi ancestor** (`s04-multi.txt`, `s04-multi-ancestor.json`, `s04-multi-child.json`, `s04-multi-effective.json`, `s04-multi-link.json`):

| Item                  | Evidence                                                                                                                |
| --------------------- | ----------------------------------------------------------------------------------------------------------------------- |
| Foreign program       | `foreign_allow`, id 1133 (a new load), tag `824ab03dccc4ea22`                                                           |
| Ancestor attach       | `bpftool cgroup attach <executions> cgroup_inet4_connect pinned …/foreign_allow multi`, i.e. legacy `BPF_F_ALLOW_MULTI` |
| Ancestor state        | one entry, id 1133, `cgroup_inet4_connect`, `attach_flags` `multi`                                                      |
| Child attempt         | `soglia_connect4` only, Aya `Single`, flags 0: **succeeded**                                                            |
| Child link            | id 12, type `cgroup`, `prog_id` 1140, `cgroup_id` 13368, `attach_type` `cgroup_inet4_connect`                           |
| Child direct state    | one entry, id 1140, `soglia_connect4`, `attach_flags` `multi`                                                           |
| Child effective state | `[1140 soglia_connect4, 1133 foreign_allow]`, in that order                                                             |
| Foreign id/tag        | 1133 / `824ab03dccc4ea22` before and after, other metadata identical                                                    |

Observation (**PROVEN ON KERNEL 6.8.0-134**): with a legacy multi ancestor program, the child link attach succeeds and both programs are effective on the child.
bpftool lists the child's program before the ancestor's.
That is the listing order of the effective array; **the order in which the kernel runs the two programs was not measured here**.
S9 later records foreign invocation chronology but deliberately makes no relative foreign/child execution-order claim; no conclusion is drawn from list order.

**Non-mutation of the foreign program.**
Within each authoritative run, id and tag are identical before and after the child attempt.
Between runs the id changes (1091, 1105, 1133) because each run loads the object again; the tag `824ab03dccc4ea22` is the same for every load.

**S0.4d — cleanup and non-mutation** (`s04-final-*`, compared with `s04-run-baseline-*`):

- `executions/`: no direct attachment; `s0-probe`: no direct and no effective attachment;
- links: identical to the run baseline (1 and 2 only), no `cgroup` link;
- programs: the same 14 ids, names and tags as the run baseline; no `soglia*` or `foreign*` program;
- `/sys/fs/bpf` empty, including `soglia-spike/` and both `soglia-foreign-s04-*` directories;
- `s0-probe` still empty, inodes unchanged.

**External host churn**, classified separately: `s04-baseline-prog.json` (07:20) lists 15 programs, the run baseline (07:27) 14.
The difference is id 1084 `sd_devices`, systemd's program for `fwupd.service`, which stopped on its own before the test.
No program changed between the run baseline and the final state.

**Minor deviations**, none of which affects the verdict:

- file names: `s04-exclusive-link.json` and `s04-multi-link.json` (singular) and `s04-final-child.json`, instead of the requested `-links` and `-cgroup` names;
- `s04-final-bpffs.txt` ends with a summary written by the executor after the raw `ls`/`find` output;
- in the non-authoritative multi run, `bpftool link show pinned` printed the link JSON but returned non-zero.

**Verdict:**

| Part  | Result                                                                              |
| ----- | ----------------------------------------------------------------------------------- |
| S0.4a | Observation recorded: link attach with flags 0 reported as `multi`                  |
| S0.4b | Characterised: exclusive ancestor → child link attach `EPERM`, no partial state     |
| S0.4c | Characterised: multi ancestor → child link attach succeeds, both programs effective |
| S0.4d | **PASS**                                                                            |
| S0.4  | **PASS**                                                                            |

**Consequence for a future start-up probe** (a requirement candidate, not yet normative):
a link-based Execution attach of a given attach type fails with `EPERM` when an ancestor holds a legacy exclusive program of that type.
The probe must therefore detect ancestor attachments, and must fail closed with that reason rather than treat the `EPERM` as a transient error.

#### S0.5 — result: PASS

From `s05-cleanup.txt` (07:36:56 CEST), `s05-final-prog.json` and `s05-final-link.json`:

- before: `executions/` (13326) and `s0-probe` (13368) empty, with no direct or effective attachment;
- `rmdir executions/s0-probe` and `rmdir executions` succeeded, and both paths are verified absent;
- below the delegated root only `runtime/` remains (PIDs 22563 and 22595); root inode 12456, `subtree_control` `memory pids`;
- `bpftool cgroup tree` of the delegated root lists no program;
- `/sys/fs/bpf` empty; no `soglia*` or `foreign*` program loaded; no `cgroup` link; links 1 and 2 only.

The unit `soglia-spike-s0.service` is left running as the parent for the next preflight.
The harness logs remain in the VM's `/var/tmp`; copies are in `evidence/s0/vm-logs/`.

#### S0.4 — criteria and required evidence (as planned before execution)

S0.4 establishes only what the start-up capability probe of a future backend must require, so that no kernel feature becomes normative without evidence.
Its results are observations on kernel 6.8.0-134, except for cleanup and non-mutation, which are PASS/FAIL.

| Part  | Question                                                                                                                                                                            | Evidence required                                                                                                                                                                                   |
| ----- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| S0.4a | Which `attach_flags` does bpftool report for a link attach made with flags 0? Is an explicit `BPF_F_ALLOW_MULTI` needed?                                                            | Observed in S0.3: `multi` for all six hooks, with flags 0; whether an explicit flag changes anything is still open                                                                                  |
| S0.4b | With a foreign `cgroup_inet4_connect` program attached to `executions/` in exclusive mode (legacy attach, no flags), does a link attach of `soglia_connect4` on `s0-probe` succeed? | `foreign.o` loaded and attached with bpftool; `bpftool cgroup show executions/ -j` before and after; the harness's attach result and exact error; the foreign program's id and tag before and after |
| S0.4c | Same, with the foreign program attached with `multi`: does the child link attach succeed, and what does `bpftool cgroup show s0-probe effective -j` list?                           | as S0.4b, plus the effective list on `s0-probe`                                                                                                                                                     |
| S0.4d | Cleanup and non-mutation: are the foreign program, its attachment and the Soglia links all removed as intended, with the foreign object untouched while it existed?                 | `bpftool prog show -j` and `link show -j` after, compared with the baseline; foreign id and tag unchanged between before and after                                                                  |

S0.4d is **PASS** when the final state equals the baseline and the foreign program's id and tag never changed; **FAIL** otherwise.
S0.4a–c are recorded as observations.
They become the capability-probe requirements of the backend only after review.

#### S0.5 — criteria (as planned before execution)

After S0.4: `ls -A /sys/fs/bpf` is empty; `bpftool cgroup tree` shows no program under the delegated root; `executions/s0-probe` is removed and verified absent; the program and link sets equal the baseline.

### S1 — trusted attribution chain: PASS

**Hypothesis.**
For a connection from one fresh Execution to the experimental proxy, the proxy can derive the same current Execution from kernel subject, socket and published tuple evidence before reading application bytes.
The peer IP/veth identity is recorded only as an independent cross-check and is never an authorization fallback.

**Topology.**
Each attempt started from a clean S0.5-equivalent baseline and created a fresh `executions/s1-e1` cgroup, `soglia-s1-e1` network namespace, `sgh-s1e1` veth pair, `soglia-proxy0` dummy address `10.200.255.1`, and nftables deny-by-default namespace and host tables.
The Execution address was `10.201.0.1`; the proxy listened at `10.200.255.1:15001`.
The fresh Execution cgroup inodes were 13572, 13716 and 13800 in the three attempts; no historical S0 inode was reused.

The S1 harness loaded one `soglia.o` instance with candidate-C identity 1001001, activated its per-instance policy, and attached all six programs directly to the fresh Execution cgroup.
The during-run bpftool snapshots show real cgroup links and all six programs in the target's effective list in every attempt.

**Observed result.**
All three agent connections reached proxy accept, with peers `10.201.0.1:42238`, `10.201.0.1:47234`, and `10.201.0.1:38824`.
The harness then performed bounded tuple lookup for two seconds without reading application bytes, creating an outbound effect, or authorizing from the peer IP.
Every lookup timed out and denied.

The third attempt added raw map diagnostics before teardown:

- `soglia_tuples` was empty;
- `soglia_cookie_a` was empty;
- all nine `soglia_counters` values were zero;
- `soglia_denies` was empty.

This rules out a mere proxy-side tuple-key mismatch for that attempt: no observed connect4 or sockops state was published at all.
At that point the evidence did not establish why the accepted agent socket had not traversed the attached programs, because live process membership had not been captured.
The narrowly authorized diagnostic below resolved that ambiguity as a subject-placement defect.

Candidate mechanisms A, B and C were configured but produced no runtime attribution evidence.
Candidate D recorded no tuple and was not otherwise exercised.
The observed peer IP matched the veth assignment, but it was not used to authorize and cannot repair the missing BPF chain.

**Cleanup.**
Every attempt removed the test cgroups, namespace, veth, dummy link, nftables table, BPF pins, programs and cgroup links.
The final checks show only `runtime/` below the delegated root, empty bpffs, zero Soglia/foreign programs, zero cgroup links and no owned netns/veth/nft resource.

**Evidence.**
The original third run and `s1-final-live.txt` are in [evidence/s1/](evidence/s1/); the two earlier attempts are preserved under `attempt1/` and `attempt2/`.
The narrow subject-placement diagnostic is under `diagnostic/`.
For each run, the preflight, topology, during-state, harness, provenance/status and cleanup files preserve the before, during, failure and after states.

#### S1 diagnostic rerun — SUBJECT_PLACEMENT_FAILURE

The diagnostic used a fresh `executions/s1-e1` cgroup with inode 13968 under a fresh `executions/` inode 13926.
It loaded the spike-only `soglia-diag.o`, whose source adds unconditional entry and milestone counters for `sock_create`, `connect4` and `sockops` without changing production code or attribution decisions.
bpftool observed all six programs directly and effectively attached to the fresh cgroup, with program ids 1185–1190.

The agent was changed to announce its real PID and wait at a filesystem barrier before creating the test socket.
The launcher also enabled `set -e`, so failure to move the process could no longer be silently ignored.
No agent reached the barrier.
The trusted launcher exited before `exec` with:

```text
s1-child: line 2: /sys/fs/cgroup/system.slice/soglia-spike-s0.service/executions/s1-e1/cgroup.procs: No such file or directory
```

The launch sequence attempted the `cgroup.procs` write from inside the context established by `ip netns exec`.
That context did not expose the host cgroup path, so the process could not be moved to the attached Execution cgroup.
In the earlier S1 attempts, the same write lacked `set -e`; its failure was therefore ignored and the shell continued to `exec` the agent outside the target cgroup.
This explains the combination of successful proxy connections, effective BPF attachments and completely empty BPF activity maps.

The diagnostic emitted `S1_DIAGNOSTIC_CLASSIFICATION=SUBJECT_PLACEMENT_FAILURE`.
Because no live agent existed in the intended cgroup, no controlled diagnostic connection was released and the spike-only hook-entry counters did not become evidence about hook execution or attribution logic.
The diagnostic did not modify attribution logic and did not use IP-derived authorization.

The first diagnostic attempt, preserved under `evidence/s1/diagnostic/attempt1-no-agent/`, timed out at the same pre-connection barrier but did not drain child stderr.
The second phase-A attempt captured the exact launcher error in `evidence/s1/diagnostic/s1-harness.txt`.
Both attempts cleaned up fully.
The final cleanup shows only `runtime/` below the delegated root, empty bpffs, zero cgroup links, zero Soglia/foreign programs and no owned netns, veth or nftables table.

**Precise next investigation.**
Keep attribution logic unchanged.
Move the trusted host PID into the Execution cgroup from a host-visible cgroup filesystem context before entering or executing inside the owned network namespace, then repeat only the pre-connection barrier and prove the PID simultaneously in `/proc/<pid>/cgroup` and the target `cgroup.procs`.
Only after that membership proof should one controlled connection be released to the already prepared hook-entry instrumentation.

At this diagnostic checkpoint S1 remained UNPROVEN with `SUBJECT_PLACEMENT_FAILURE`.
The next authorized run corrected only the experimental launch order and preserved this result as diagnostic history.

#### S1 host-first placement rerun — ATTRIBUTION_LOGIC_FAILURE

**Pre-run scope check.**
The `SPIKE_DIAGNOSTIC` BPF changes add only one array map and unconditional entry/milestone increments.
They do not change policy, allow/deny conditions, cookie or sk-storage attribution, tuple construction/publication, or authorization.
The agent, harness and shell changes add barriers, evidence capture and host-first PID placement only.
No production source file was modified.

**Fresh subject and attach state.**
The run created a fresh Execution cgroup with inode 14196 and an initially empty `cgroup.procs`.
It loaded the same six programs from `soglia-diag.o` with unchanged attribution logic and observed all six as direct and effective on that cgroup.

**Trusted host-first placement.**
The harness started host PID 33144 in a stopped state before network-namespace entry, wrote that PID to the target `cgroup.procs` from the host-visible cgroup filesystem, and observed both:

```text
/proc/33144/cgroup:
0::/system.slice/soglia-spike-s0.service/executions/s1-e1

target cgroup.procs:
33144
```

The stopped wrapper then continued and used `exec` through `ip netns exec` to the actual agent.
The agent announced PID 33144, equal to the placed host PID.
Before traffic, the harness and independent runner again observed that PID in the exact cgroup and observed agent netns inode 4026532344 equal to the owned netns inode.
Subject placement is therefore proven for this run.

The first host-first attempt is preserved under `evidence/s1/placement-fixed/attempt1-compare-bug/`.
Its raw `/proc` and `cgroup.procs` evidence already agreed, but the harness omitted the slash after `0::` while comparing the expected path and stopped without releasing traffic.
The final run corrected only that diagnostic string normalization.

**Single controlled connection.**
Before release, the diagnostic entry counters, existing counters, cookie map, tuple map and deny map were all zero or empty.
Exactly one agent connection was released.
The proxy accepted peer `10.201.0.1:51240` at local `10.200.255.1:15001`.
While Resolve was unresolved, the harness recorded zero application bytes read, zero outbound effects and no IP fallback authorization.

The immediate post-accept entry counts were:

| Diagnostic index | Observation                    | Count |
| ---------------: | ------------------------------ | ----: |
| 0                | `sock_create` entry            | 1     |
| 1                | `connect4` entry               | 1     |
| 2                | `sockops` entry                | 6     |
| 3                | connect4 attribution attempted | 1     |
| 4                | sockops TCP-connect callback   | 1     |
| 5                | sockops active-established     | 1     |
| 6                | tuple publication attempted    | 1     |

The existing counters recorded one successful publication and zero insert failures or denies.
`soglia_denies` was empty.
The ring-buffer events were not drained because the diagnostic JSON parser stopped after the raw map dumps; the event-dropped counter was zero.

**Published attribution state.**
Candidate A published socket cookie 73 to cgroup id 14196.
The tuple value carried the same cookie, A cgroup 14196, B cgroup 14196, candidate-C identity 1001001, netns cookie 8196, and sockops current cgroup 14196.
Thus hook entry and the A/B/C attribution values were observed.

The published tuple key did not represent the accepted destination port correctly:

```text
Proxy lookup key:
0ac90001 0ac8ff01 28c80000 993a0000
                                ^ dport 15001

Published map key:
0ac90001 0ac8ff01 28c80000 00000000
                                ^ dport 0
```

The tuple evidence recorded raw remote port `2570715136` (`0x993a0000`), while the stored tuple key's formatted `dport` was zero.
Resolve therefore could not find the published entry using the proxy's accepted socket tuple and timed out after two seconds.

The harness's post-dump parser expected bpftool's top-level `key` and `value` fields to be numeric, while this bpftool version emitted raw byte arrays plus numeric values under `formatted`.
It consequently ended with `bpftool array entry has no numeric key` before printing its own classification line.
This secondary evidence-parser error happened after the raw hook, counter, cookie, tuple and deny dumps and does not create or explain the tuple-key mismatch.

**Classification: ATTRIBUTION_LOGIC_FAILURE.**
Membership and hook entry are proven, and attribution state exists, but tuple attribution was not published under the correct accepted-socket key.
This is not `HOOK_ENTRY_FAILURE`, `RESOLVE_CORRELATION_FAILURE`, or `SUBJECT_PLACEMENT_FAILURE`.
S1 remains UNPROVEN and is not marked PASS.

**Cleanup and evidence.**
The run removed the test cgroups, namespace, veth, dummy interface, nftables table, BPF pins, programs and links.
The final state contains only `runtime/` below the delegated root, empty bpffs, zero Soglia/foreign programs and zero cgroup links.
Raw evidence is preserved under [evidence/s1/placement-fixed/](evidence/s1/placement-fixed/), including preflight, provenance, both membership proofs, before-connection baselines, live bpftool snapshots, harness output and cleanup proof.

**Precise next investigation.**
Do not redesign attribution or proceed to S1b.
Review the existing `sockops` remote-port conversion in `key_of` against the observed raw value and the kernel's byte-order contract, then authorize any correction separately before another S1 run.

#### S1 destination-port trace — deterministic extraction defect

The authorized port-trace rerun used a fresh Execution cgroup with inode 14562 and preserved the previous host-first launcher.
The trusted host PID and actual agent PID were both 33538, `/proc/33538/cgroup` and the target `cgroup.procs` both proved exact membership, and the agent entered the owned network namespace before traffic.
Before release, bpftool showed all six programs directly and effectively attached to the fresh target.

Exactly one connection reached the proxy from `10.201.0.1:52804` to `10.200.255.1:15001`.
While Resolve remained unresolved, the proxy read no application bytes, performed no DNS or outbound action, and did not authorize from the peer IP.
Resolve timed out fail-closed as expected for the deliberately unchanged tuple conversion.

The running kernel UAPI declares both `bpf_sock_addr.user_port` and `bpf_sock_ops.remote_port` as `__u32` values stored in network byte order.
The spike tuple declares `dport` as `__u32` in host byte order, and the Rust Resolve key writes the accepted `u16` port widened to `u32` in native byte order.
On this little-endian aarch64 host, the spike-only pre-insert diagnostics recorded:

| Trace point                                   | Decimal    | Hex          |
| --------------------------------------------- | ---------: | ------------ |
| `connect4` raw `user_port`                    | 39226      | `0x0000993a` |
| `connect4` `ntohs((u16)user_port)`            | 15001      | `0x00003a99` |
| `sockops` raw `remote_port`                   | 2570715136 | `0x993a0000` |
| `sockops` raw low half                        | 0          | `0x00000000` |
| `sockops` raw high half                       | 39226      | `0x0000993a` |
| `ntohl(sockops remote_port)`                  | 15001      | `0x00003a99` |
| existing `ntohl(remote_port) >> 16`           | 0          | `0x00000000` |
| `ntohs((u16)(remote_port >> 16))` cross-check | 15001      | `0x00003a99` |
| assigned `tuple.dport`                        | 0          | `0x00000000` |
| expected proxy port                           | 15001      | `0x00003a99` |
| `tuple.dport` immediately before insertion    | 0          | `0x00000000` |

This proves a wrong-half extraction caused by an extra shift after the full 32-bit network-to-host conversion.
The context field is correct, no 32-to-16 truncation causes the loss, and the assigned value is not overwritten before insertion.
The tuple and Resolve representations are both host-order `u32`; only the sockops extraction was wrong.

The diagnostic retained the classification `ATTRIBUTION_LOGIC_FAILURE`, recorded one successful tuple publication with A/B/C values for cgroup inode 14562 and candidate-C identity 1001001, then completed cleanup.
Raw evidence is preserved under [evidence/s1/port-trace/](evidence/s1/port-trace/), including the UAPI/source contract, membership proof, hook and port counters, published maps, proxy tuple, timeout, and zero-residue cleanup.

The evidence authorizes the minimum spike-only correction: assign `bpf_ntohl(skops->remote_port)` directly to the host-order `tuple.dport`, with no change to any other attribution or authorization semantics.

#### S1 final rerun — PASS (`S1_CHAIN_PROVEN`)

The minimum spike-only fix removed only the erroneous `>> 16` after `bpf_ntohl(skops->remote_port)`.
No policy, attribution candidate, tuple field, authorization rule, launcher topology, or production source changed.

The fresh run created Execution cgroup inode 14646 and attached all six programs directly and effectively.
Trusted host PID 33815 became the actual agent PID, appeared in both the exact `/proc/33815/cgroup` path and target `cgroup.procs`, and entered the owned netns before the single connection was released.

The proxy accepted exactly one socket from `10.201.0.1:47654` at `10.200.255.1:15001`.
Before Resolve, it read zero application bytes, performed zero outbound effects, and used no IP-derived authorization fallback.
All required diagnostic hook and milestone counts were nonzero, with exactly one `sock_create`, `connect4`, attribution attempt, active-established callback, and publication attempt.

The raw sockops port remained `0x993a0000`.
The corrected assignment and the value immediately before map insertion were both `15001`, and bpftool formatted the tuple key with `dport: 15001`.
The byte-for-byte proxy lookup key matched that published tuple key.

The tuple carried cookie 12347, candidate-A cgroup 14646, candidate-B cgroup 14646, candidate-C identity 1001001, candidate-D netns cookie 12290, and sockops current cgroup 14646.
Resolve returned `s1-execution-e1-generation-1` in 2917 ns, after which and only after which the proxy read `HELLO 0` and returned the attributed identity to the agent.
The IP/veth identity agreed as an independent cross-check and was not used for authorization.

The run emitted `S1_DIAGNOSTIC_CLASSIFICATION=S1_CHAIN_PROVEN` and `S1_RESULT=PASS`.
Cleanup removed the Execution hierarchy, netns, links, nftables table, BPF links, maps and pins; the final state again contained only `runtime/`, empty bpffs, zero Soglia/foreign programs and zero cgroup links.
Raw evidence is preserved under [evidence/s1/port-fixed/](evidence/s1/port-fixed/).

S1 is **PASS** on the tested kernel and S1b may now execute under the autonomous stop rules.

#### S1b — delayed publication / accept race: PASS

**Security property.**
Proxy accept may precede final tuple publication, but unresolved sockets must not cause application reads, DNS, outbound effects, external connections, or IP-derived authorization.
Resolve may wait only for a bounded interval and must deny on timeout.

The fresh S1b run used Execution cgroup inode 14730 and the same proven host-first launcher.
Trusted host PID and actual agent PID were both 34182, exact cgroup membership was independently observed before traffic, and bpftool showed the six programs directly and effectively attached.

The `SPIKE_DELAY_PUBLISH` variant wrote sockops evidence into `soglia_staging` instead of the final tuple map.
The harness accepted 65 concurrent sockets and verified for every accepted tuple that the final map was still empty for that key; staging was already visible, so final publication ordering did not depend on whether sockops ran before or after `accept`.
For 64 sockets the harness waited controlled delays from 50 to 200 ms, verified again that the final tuple was absent, promoted the staged evidence, and resolved only through the final tuple map.
Every result carried destination port 15001, candidate-A and candidate-B cgroup 14730, candidate-C identity 1001001, and the same current Execution identity.

No application byte was read until after each successful Resolve.
The harness recorded zero DNS, outbound effects and IP fallback authorization while unresolved.
Only after all 64 successful resolutions did it read the already-buffered `HELLO` lines and return the attributed identity.

One additional accepted socket was intentionally never promoted.
At the two-second bound its final tuple remained absent, the proxy denied by closing the socket without reading application data, and the agent observed connection reset.
The remaining single staging entry is raw evidence of that deliberately unresolved tuple; cleanup then removed it with all maps and pins.

The 64 successful accepted-to-Resolve latency samples were:

| Statistic | Latency ns | Latency ms |
| --------- | ---------: | ---------: |
| minimum   | 50024652   | 50.024652  |
| p50       | 120160258  | 120.160258 |
| p95       | 200090737  | 200.090737 |
| p99       | 200117654  | 200.117654 |
| maximum   | 200117654  | 200.117654 |

The hook snapshot recorded 65 `sock_create`, 65 `connect4`, 65 active-established and 65 publication attempts, 65 successful BPF staging publications, 64 final tuples and one unpromoted staging tuple.
No BPF event was emitted and all deny/error counters stayed zero because the bounded timeout decision occurred in the proxy harness, not as a BPF policy deny.

The run emitted `S1B_RESULT=PASS`.
Cleanup removed the fresh cgroup hierarchy, namespace, veth, dummy link, nftables table, links, maps and pins; only `runtime/` remained, bpffs was empty, and program/link counts were zero.
Raw evidence is preserved under [evidence/s1b/race/](evidence/s1b/race/).

S1b is **PASS** on the tested kernel.

#### S2 — concurrency / cross-attribution: PASS

**Security property.**
A socket and tuple originating from live Execution Ei must never resolve to another live Execution Ej.
Missing or not-yet-published final state must remain fail-closed without IP-derived authorization.

The passing run created four fresh, simultaneously live Executions with independently observed mappings:

| Execution | Cgroup inode | Agent PID | Netns inode | Source IP     | Candidate-C identity |
| --------- | -----------: | --------: | ----------: | ------------- | -------------------: |
| e0        | 15144        | 35844     | 4026532344  | `10.201.0.1`  | 2001001              |
| e1        | 15186        | 35848     | 4026532416  | `10.201.0.5`  | 2001002              |
| e2        | 15228        | 35853     | 4026532476  | `10.201.0.9`  | 2001003              |
| e3        | 15270        | 35858     | 4026532536  | `10.201.0.13` | 2001004              |

For every agent, the trusted host PID equalled the actual agent PID, `/proc/<pid>/cgroup` matched the exact Execution path, target `cgroup.procs` contained that PID, and the process netns inode matched its owned netns.
Before traffic, bpftool showed the same six approved programs directly and effectively attached to each fresh cgroup.

Each Execution opened 33 concurrent proxy sockets using the deterministic source-port range 40000–40032.
The same 33 source ports were therefore deliberately reused in all four network namespaces while distinct source addresses completed the tuple key.
The proxy accepted 132 unique complete tuples before any final tuple was promoted, producing a measured unresolved concurrency peak of 132.

The delayed-publication variant interleaved final publication and Resolve after per-socket delays.
For every successful socket the harness correlated the independent origin mapping, accepted tuple, socket cookie, candidate-A cgroup, candidate-B cgroup, candidate-C identity, tuple owner and Resolve result.
All 128 promoted tuples resolved to their originating Execution.

One source-port-40032 socket per Execution was intentionally left only in staging until the two-second bound.
All four were denied without application reads, DNS, outbound effects or IP fallback.
The peer IP remained an independent cross-check and never supplied authorization.

The primary and supporting metrics were:

| Metric                               | Value |
| ------------------------------------ | ----: |
| Executions                           | 4     |
| Connections                          | 132   |
| Peak concurrent unresolved sockets   | 132   |
| Successful bounded resolves          | 128   |
| Timeout denies                       | 4     |
| Unique live socket cookies           | 132   |
| Attribution mismatches               | 0     |
| Cross-attributions                   | 0     |
| Unexpected complete-tuple collisions | 0     |
| Unexpected map errors                | 0     |

The first attempt, preserved under [evidence/s2/run1/](evidence/s2/run1/), stopped before attachment or traffic because the new harness closed its `policy_local` map handle before program load.
The verifier rejected the dangling map FD, the runner cleaned all test resources, and the harness was corrected only to retain the map inside `Ebpf` through `map_mut`.
This was a harness lifetime defect and produced no S2 security observation.

The passing run emitted `S2_RESULT=PASS` and is preserved under [evidence/s2/run2/](evidence/s2/run2/).
Cleanup proved all four agents gone, the Execution hierarchy absent, all owned netns/veth/nft resources absent, bpffs empty, and zero Soglia/foreign programs or cgroup links.
S2 is **PASS** on the tested kernel.

#### S3 — stale state / lifecycle / reuse: PASS

**Security property.**
State belonging to an old Execution generation must never authorize a later generation, including across connection close, process death, Execution teardown and source-port reuse.

S3 exercised three fully cleaned and recreated generations with the same Execution cgroup path, owned netns name, source IP and proxy destination.
Every generation independently reproved live PID membership and all six effective BPF hooks before traffic.

The first generation used candidate-C identity 3001001 and a fixed source tuple `10.201.0.1:41000 -> 10.200.255.1:15001`, resolved to `s3-execution-generation-1`, then closed with FIN.
Its cgroup inode was 15414 and its BPF netns cookie was 5.
The phase cleanup removed the tuple and cookie maps with all other test resources before the next generation was created.

The second generation deliberately reused the exact same source and destination tuple but used fresh cgroup inode 15498, candidate-C identity 3001002 and BPF netns cookie 6.
It resolved only to `s3-execution-generation-2` and closed with RST.
No state from generation 1 resolved or authorized this socket.

The third generation used fresh cgroup inode 15582 and candidate-C identity 3001003.
After its socket resolved correctly to `s3-execution-generation-3`, the runner sent `SIGKILL` to the proven live agent PID 36830 while the connection remained active.
The harness recorded the expected child termination error, then its normal cleanup and the runner's trap removed the socket attribution state, links, maps, cgroup and network topology.
The nonzero runner status for this phase is expected evidence of observed process death, not a failed cleanup.

Across all three phases:

| Property                                    | Result |
| ------------------------------------------- | ------ |
| Fresh cgroup inode per generation           | yes    |
| Fresh observed BPF netns cookie after reuse | yes    |
| Exact source-port reuse                     | yes    |
| Old generation resolved as new              | 0      |
| Cross-generation attribution                | 0      |
| Tuple/cookie residue after each teardown    | 0      |

The final state contained only `runtime/` below the delegated root, no Execution cgroup, empty bpffs, no owned netns/veth/nft state, zero Soglia/foreign programs and zero cgroup links.
The run emitted `S3_RESULT=PASS`; raw evidence is preserved under [evidence/s3/](evidence/s3/).
S3 is **PASS** on the tested kernel.
Candidate D remains unselected; the changed netns cookies are lifecycle evidence only, not a candidate decision.

#### S4 — direct IPv4 cgroup-BPF deny: PASS

**Security property.**
The cgroup-BPF layer must be able to prevent a controlled direct IPv4 connection from establishing even when the one nftables restriction relevant to that path is temporarily relaxed.
This characterizes early denial only: nftables remains the final destination barrier and no routing or proxy steering moved into BPF.

The valid run used a fresh Execution cgroup with inode 15750.
The trusted launcher PID and actual agent PID were both 38638; the PID appeared in the exact `/proc` cgroup path and target `cgroup.procs`, and its network-namespace inode 4026532344 matched the owned namespace before traffic.
All six programs were directly and effectively attached in each experimental phase.

The experiment separated enforcement with three observations against `10.201.0.2:16001`:

1. With the normal namespace nft output policy and a spike-only BPF control that permitted only this direct target in addition to the proxy, the direct attempt timed out, the BPF `connect4` deny counter remained zero, and the bound direct listener accepted nothing. In the same phase, the proxy path to `10.200.255.1:15001` established, published attribution, and returned the attributed Execution identity.
2. The runner added exactly one namespace rule: `ip daddr 10.201.0.2 tcp dport 16001 ct state new accept comment "s4-direct-exposure"`. With that rule present and the normal diagnostic BPF policy, the direct attempt returned `EPERM`, the direct listener accepted nothing, and there was no proxy involvement. The isolated BPF instance recorded exactly one `connect4` entry, one `connect4` deny, one per-cgroup deny entry for cgroup 15750, and one deny event with reason `R_NOT_PROXY`; it published no tuple or cookie.
3. With the same nft relaxation still present and only the spike-only BPF direct-target exception restored, the connection established and the direct listener accepted `10.201.0.1:37110 -> 10.201.0.2:16001`. Its BPF deny counters and map remained zero. This proves the topology could expose the path and excludes an unobserved unrelated blocker as the explanation for phase 2.

The namespace route, input policy, established-flow handling and forward-drop policy remained active throughout.
The host test table retained anti-spoof, invalid/non-TCP and forwarding constraints; it did not add a second destination barrier.
Thus the evidence attributes normal-state denial to nft, experimental early denial to `cgroup/connect4`, remaining topology constraints to the owned namespace/host boundary, and proxy involvement only to the separately observed proxy control.

The temporary rule was deleted by its observed handle.
The before/after namespace ruleset JSON files are byte-identical with SHA-256 `fcde47585f58692d8e87f4043db94441e7ac55350f5081fc7be2862e7de4ed00`.
Cleanup then proved the Execution hierarchy, netns, veth/dummy links, host nft table, BPF links, maps and pins absent; bpffs was empty and Soglia/foreign program and cgroup-link counts were zero.

The run emitted `S4_RESULT=PASS`; raw evidence is preserved under [evidence/s4/run2/](evidence/s4/run2/).
The preceding setup-only attempt is preserved under [evidence/s4/setup-failed-1/](evidence/s4/setup-failed-1/): it found the harness binary in the wrong build-output directory, performed no attach or traffic, restored the briefly added nft rule, and verified cleanup before the valid run.
S4 is **PASS** on the tested kernel.

#### S5 — isolated hook contribution: PASS

**Security property.**
Each of the six cgroup-BPF hooks must have an empirically distinguishable contribution.
For deny hooks, the controlled operation must be denied with that hook present and reach the test listener when only that hook is omitted or its prerequisite gate is relaxed.
For `sockops`, omission must remove tuple publication without turning missing attribution into authorization.

The valid run used one fresh Execution cgroup, inode 16062, and a dual-stack owned netns.
Every phase launched a new stopped agent, placed its trusted host PID in the Execution cgroup, resumed it into the owned netns, and independently proved the actual PID, exact `/proc` cgroup path, target `cgroup.procs` membership and matching netns inode before releasing the operation.
The full phases showed six direct/effective programs; single-hook omission controls showed exactly five, with the named attach type absent.

| Hook          | Hook-present observation                                                                                                                                                  | Isolated control observation                                                                                                                                                                                    | Contribution established                                                                |
| ------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------- |
| `sock_create` | Default program denied creation of an IPv6 stream socket; counter index 3, per-cgroup deny and event each incremented once                                                | `SPIKE_RELAX_INET6_STREAM` allowed the same socket creation with all deny counters zero                                                                                                                         | early family/type socket-creation gate                                                  |
| `connect6`    | With IPv6 stream creation relaxed, the IPv6 connect returned `EPERM`; counter index 5 and deny/event evidence each incremented once; listener accepted nothing            | Omitting only `soglia_connect6` established to `[fd00:201::2]:16002` and the listener accepted                                                                                                                  | IPv6 stream connection deny after creation                                              |
| `sendmsg4`    | With datagram creation relaxed, IPv4 UDP send returned `EPERM`; counter index 6 and deny/event evidence each incremented once; listener received nothing                  | Omitting only `soglia_sendmsg4` delivered `probe` to `10.201.0.2:16003`                                                                                                                                         | IPv4 datagram send deny                                                                 |
| `sendmsg6`    | With datagram creation relaxed, IPv6 UDP send returned `EPERM`; counter index 7 and deny/event evidence each incremented once; listener received nothing                  | Omitting only `soglia_sendmsg6` delivered `probe` to `[fd00:201::2]:16004`                                                                                                                                      | IPv6 datagram send deny                                                                 |
| `connect4`    | Direct IPv4 returned `EPERM`; counter index 4 and deny/event evidence each incremented once; listener accepted nothing                                                    | Omitting only `soglia_connect4` established to `10.201.0.2:16001` and the listener accepted                                                                                                                     | IPv4 destination/policy gate and candidates A/B capture point                           |
| `sockops`     | Proxy TCP established, final tuple carried destination 15001, A/B cgroup 16062 and C identity 5001001, and Resolve returned the current Execution before application read | Omitting only `soglia_sockops` still established the proxy TCP but produced no tuple or publication count; Resolve timed out after 2 s and closed without application read, DNS, outbound effect or IP fallback | established-socket tuple publication and close-driven cleanup, not connection admission |

The `sockops` omission also left the one candidate-A cookie inserted by `connect4`, because no `sockops` state callback ran its deletion path.
That stale-in-the-live-map observation did not authorize the socket: the final tuple remained absent and Resolve denied.
Phase cleanup removed the map and its cookie state before the next test.

The first setup attempt, preserved under [evidence/s5/setup-failed-1/](evidence/s5/setup-failed-1/), stopped before attach because the host IPv6 address was still tentative.
The second attempt, preserved under [evidence/s5/setup-failed-2/](evidence/s5/setup-failed-2/), completed the `sock_create` pair and `connect6` deny but its omission control exposed a missing Neighbor Discovery allowance rather than the TCP path; its BPF deny counters stayed zero.
The final topology used `nodad` for its disposable addresses and allowed only ICMPv6 Neighbor Discovery in addition to the enumerated test flows.

The valid run emitted all six `S5_HOOK_*=ISOLATED` lines and `S5_RESULT=PASS`.
Cleanup proved the Execution hierarchy, netns, owned links and nft table, BPF links, maps and pins absent; bpffs was empty and Soglia/foreign program and cgroup-link counts were zero.
Raw evidence is preserved under [evidence/s5/run3/](evidence/s5/run3/).
S5 is **PASS** on the tested kernel.

#### S6 — actual enforcement-layer table: PASS

S6 introduced no new runtime mutation or security claim.
It traced each S1–S5 property to the layer whose relaxation or omission actually changed the observed behavior, and separated that primary enforcement from independently observed defense-in-depth and topology constraints.

The resulting [enforcement-layer table](evidence/s6/s6-enforcement-layer-table.md) establishes, among other entries:

- trusted launcher/runtime placement establishes live Execution membership; BPF consumes that subject identity but does not place the process;
- `sock_create`, `connect4`, `connect6`, `sendmsg4` and `sendmsg6` are distinct early gates with the contributions isolated by S5;
- namespace nft is the final proxy-only destination barrier demonstrated by S4, with `connect4` an earlier IPv4 defense;
- `connect4` captures candidates A/B, while `sockops` publishes established tuple evidence and participates in per-socket cleanup;
- the proxy owns bounded Resolve and the fail-closed rule for missing/delayed attribution, including the prohibition on IP fallback;
- namespace routing and host-forward drops constrain topology but are not silently credited with BPF or proxy decisions;
- at S6 synthesis time, loader-loss, helper-death and foreign-ancestor behavior were explicitly unestablished; S7–S10 subsequently test those properties.

The table links each row to its raw evidence and [s6-evidence-index.txt](evidence/s6/s6-evidence-index.txt) hashes the principal source logs plus the table itself.
A read-only before/after kernel snapshot was identical for program, link, map and bpffs state; the delegated unit remained active with only `runtime/`, zero Soglia/foreign programs and zero cgroup links.
The run emitted `S6_RESULT=PASS`; evidence is preserved under [evidence/s6/](evidence/s6/).
S6 is **PASS** for the enforcement-layer table deliverable.

#### S7 — pinned link / loader loss: PASS

**Security property.**
Abrupt loss of the process that loaded and attached the programs must not silently remove kernel enforcement when the BPF links are pinned.
The test must also distinguish retained kernel state from user-space functionality that disappeared with the loader.

The valid run created a fresh Execution topology with cgroup inode 16452 and explicitly allowed the controlled direct target `10.201.0.2:16001` through namespace nft so that `connect4` was the tested gate.
The S7 loader activated the local policy, attached all six programs with Aya links, and pinned six links and ten by-name maps.

Immediately before loader loss the directly attached program IDs were 1440–1445 for `sock_create`, `connect4`, `connect6`, `sendmsg4`, `sendmsg6` and `sockops` respectively.
The runner sent `SIGKILL`; exit status was 137 and `/proc/<loader-pid>` was absent.
After process death:

- the same six program IDs, names and attach types remained directly/effectively attached;
- the exact bpffs pin set was unchanged;
- all six link pins and all ten maps pinned by this object remained;
- there was no surviving loader process or loader-owned FD/event-management loop.

A newly launched, independently placed agent then attempted the exposed direct path.
It received `EPERM`, the host listener accepted nothing, diagnostic `connect4` entry count became one, the `connect4` deny counter became one, and the per-cgroup deny map gained one entry.
Thus pinned kernel enforcement and writable map state survived loader loss.

As the causal control, the runner removed only `/sys/fs/bpf/soglia-spike/s7/links/connect4` after the loader was already gone.
The cgroup state then contained five programs and no `soglia_connect4`; the same direct connection established and the listener accepted it.
This proves both that the pin retained the link and that deleting the last link reference detached that single gate.

What was lost was user-space loader functionality: no process remained to own non-pinned FDs, consume ring events, change policy, or perform automatic unpin/cleanup.
What remained was kernel execution of pinned programs plus retained and updated pinned map state.
This loader was not the proxy or Enforcer, so S7 makes no claim about their death behavior; that belongs to S8.

The first otherwise successful run is preserved under [evidence/s7/setup-validation-failed-1/](evidence/s7/setup-validation-failed-1/).
Its runner incorrectly expected 11 pinned maps even though `soglia_staging` exists only in the delay variant; the raw before/after list already showed the same ten pins.
The valid rerun corrected the validation to compare the exact bpffs set and assert ten maps.

Cleanup explicitly removed the remaining five link pins and all map pins, killed/removed the test Execution, and removed the netns/veth/nft topology.
The final delegated root contained only `runtime/`, bpffs was empty, and Soglia/foreign program and cgroup-link counts were zero.
The run emitted `S7_RESULT=PASS`; raw evidence is preserved under [evidence/s7/run2/](evidence/s7/run2/).
S7 is **PASS** on the tested kernel.

#### S8 — Enforcer death: PASS after production fix

**Required property.**
Enforcer death must close the admission and effect window: no new admission, DNS, outbound socket,
HTTP/CONNECT traffic or pending resolution may continue; sandboxd must terminate affected
Executions, kernel confinement must remain, and restart must recover recorded residue before
accepting work.

##### Before fix: authoritative FAIL

**Fresh preflight and trusted topology.**
The authoritative pre-fix run is [evidence/s8/run4/](evidence/s8/run4/). Before starting it, the delegated
S0 unit was active with `Delegate=yes`, controllers `cpu cpuset io memory pids`, inode 12456 and only
its `runtime` child. There were zero Soglia netns, `sgh-*` veths, `soglia0`, Soglia nft tables,
unexpected test processes, Soglia/foreign BPF programs and cgroup-BPF links; bpffs was empty.

The S8 runtime ran in a fresh delegated unit, inode 19676. The trusted runtime lifecycle identified
PID 45889 as Supervisor, PID 45891 as its `__sandboxd` child and PID 45892 as its `__enforcer`
child; `/proc` reported PPID 45889 for both helpers and all three in the unit's `runtime` cgroup.
Before agent network traffic, three fresh Executions were captured with exact IDs, live agent PIDs,
cgroup paths/inodes and distinct netns identities. Each netns had its own nft `soglia` table with
default-drop input/output and only the agent-ingress and proxy-egress exceptions. The active Phase-0
runtime had no cgroup-BPF backend, programs or links; S8 therefore measured retained nft confinement
and recorded BPF as not applicable rather than implying BPF enforcement.

**Loss and the undetected interval.**
The runner sent only `SIGKILL` to Enforcer PID 45892 at
`2026-09-27T07:29:10.547933325Z`. The command succeeded; `/proc/45892/stat` then reported state `Z`,
PPID 45889 and exit code 9. The Supervisor and sandboxd remained alive, the ingress listener remained
open, and three Executions remained active. No `runtime.helper_lost` event had occurred.

The already-open `allowed.test:443` CONNECT tunnel remained established. At 1,975 ms after helper
death the Execution sent application byte 80 through the tunnel and the independent upstream
listener received and echoed it, proving bidirectional application traffic rather than merely a live
TCP state. At 3,980 ms after helper death, a second already-admitted Execution resolved
`allowed.test` to `11.0.0.1` and established a new connection to `11.0.0.1:444`; both endpoints were
captured as `ESTABLISHED`, and the proxy logged `egress.allowed`. No resolve was pending at the kill
instant, but a resolve initiated after death completed before detection.

This is the decisive fail-closed violation: privileged Enforcer death did not itself close or cancel
the effect path.

**Detection, lifecycle and recovery.**
A fourth admission was then used solely to force an Enforcer channel operation. That Execution was
admitted into slot 3, `Prepare` hit `Broken pipe`, and `runtime.helper_lost` followed 7 ms after the
trigger and 4,058 ms after helper death. The ingress listener closed and a subsequent admission
failed to connect (`curl` status 7 / HTTP `000`). However, immediately after detection both existing
outbound tunnels were still `ESTABLISHED`, the existing HTTP work continued to its agent response,
and teardown failures quarantined the Executions. Callers received HTTP 500 because destruction
could not be verified. The runtime eventually logged `shutdown.incomplete` and exited status 1;
sandboxd's channel-close handling killed the agent processes, but stopped runc containers and
recorded cgroup/netns/nft resources remained for recovery.

On restart, sandboxd swept the three recorded sandboxes and Enforcer swept the three recorded
networks before `startup.ready`. At readiness there were zero Execution cgroups, netns, `sgh-*`
veths, agent processes and runc containers. This proves the supported restart/sweep behavior, but it
does not repair the already-demonstrated post-death effect window.

##### Production fix

The root cause was that `Helper` retained a `std::process::Child` but had no lifecycle watcher.
The Supervisor learned about permanent helper loss only when an RPC returned
`HelperError::Channel`; the stop watch ended listener accept loops but did not reach already-spawned
ingress connections, egress connections, DNS/connect/HTTP work or detached CONNECT tunnels.
The helper-loss path then entered the normal graceful drain, leaving a bounded but security-relevant
effect window.

The minimum production change is confined to lifecycle orchestration and proxy cancellation:

- `Helper::watch_exit` polls each actual child's exit status independently of RPC without retaining
  the process lock between polls, while a duplicate Supervisor socket descriptor lets the loss
  transition interrupt an in-flight exchange without taking its lock.
- `RuntimeState` provides one atomic, one-way and idempotent helper-loss transition shared by child
  exit and permanent IPC error.
- The transition stops admission first, broadcasts cancellation to ingress and egress, closes both
  helper channels, and only then publishes the fatal runtime signal.
- Active ingress connections and egress HTTP connections now observe cancellation; dropping their
  handler futures cancels pending DNS, outbound connect and HTTP-forward work.
- Detached CONNECT upgrades/tunnels observe the same cancellation and close immediately.
- Closing sandboxd's channel invokes its existing trusted EOF kill-all path; the runtime waits for
  sandboxd exit as the Execution-termination barrier rather than performing the old graceful drain.
- Helper watchers start before listener readiness, and a completed watcher prevents
  `startup.ready`; the existing helper hello/sweep sequence remains the recovery prerequisite.

No cgroup-BPF data-path behavior, nft policy, proxy steering, attribution candidate or later-phase
component changed.

Production regressions cover child exit without RPC, healthy channel closure, idempotent loss state,
admission closure/cancellation ordering, active ingress cancellation, active CONNECT cancellation and
dropping an in-flight DNS resolver future.
The full serial unprivileged workspace suite passed with 104 tests and 17 privileged tests ignored as
declared; the focused proxy/Supervisor run passed 47 tests.
Formatting, licence headers, shell syntax and `git diff --check` passed.
Clippy was unavailable because the VM's Rust 1.97 toolchain has no `cargo-clippy` component, so no
Clippy success is claimed.
No `markdownlint` executable was installed, so no Markdown-lint success is claimed.
A first parallel workspace run hit the pre-existing fixed-port
`an_absent_listener_is_never_ready` test while another test owned that port; the same test and full
suite passed serially.

##### After fix: authoritative PASS

The authoritative post-fix run is
[evidence/s8/after-fix-run6/](evidence/s8/after-fix-run6/).
Its preflight found the delegated S0 unit active with inode 12456 and only `runtime/`; there were zero
test netns, veths, `soglia0`, nft tables, unexpected processes, Soglia/foreign BPF programs and cgroup
links, and bpffs was empty.

The fresh S8 unit had inode 24557.
The trusted runtime lifecycle recorded Supervisor PID 57866, sandboxd PID 57868 and Enforcer PID
57869, with both helpers direct children in the unit's `runtime` cgroup.
Three live agent PIDs were proved in three exact fresh Execution cgroups (inodes 24885, 24978 and
25071) and distinct owned netns before traffic.
The per-netns default-drop nft policy and host nft sets/rules were captured.

The runner sent `SIGKILL(9)` to Enforcer at `2026-09-27T07:54:00.865417863Z` and issued no later
Enforcer RPC.
Journald recorded `runtime.helper_lost`, helper `enforcer`, reason `child exited from signal 9`, at
`2026-09-27T07:54:00.874086Z`, 8.029 ms after the numeric epoch sample immediately before the kill;
the independent 100 ms polling observer bounded detection at 109 ms.
Ingress was observed absent within 119 ms, all agent processes were gone within 125 ms, the
established CONNECT path was absent within 130 ms, and the runtime had exited failed-closed within
131 ms.

During a 7,039 ms observation window, the already-open tunnel transferred no application pulse, the
independent port-444 listener saw no connection, `egress.allowed` remained at its single pre-loss
event, and admission count remained three.
The post-detection admission attempt failed to connect (`curl` 7), while all three active caller
connections ended with an empty reply (`curl` 52).
The pending-DNS production regression independently proved that cancellation drops the resolver
future and closes the proxy connection.

The host nft table and all recorded network policy remained installed after Enforcer death.
As in the pre-fix characterization, the current Phase-0 runtime had no cgroup-BPF backend active, so
the run makes no BPF-enforcement claim.
On restart, sandboxd swept all three sandboxes and Enforcer swept all three networks on journal lines
2–7, privileges dropped on line 8, and `startup.ready` occurred only on line 9.
At readiness there were zero Execution cgroups, netns, veths, agent processes and runc containers.

Final cleanup removed the transient unit/cgroup, state directory, upstream dummy, `soglia0`, netns,
veths, nft tables, test processes and ephemeral test files.
The saved `/etc/hosts` baseline was restored, bpffs was empty, and Soglia BPF-program and cgroup-link
counts were zero.
The runner exited zero and emitted `S8_RESULT=PASS`.
An independent post-run read-only check reconfirmed the active S0 delegated unit with only
`runtime/`, absence of every S8 unit/state/network/process/BPF residue, empty bpffs and the exact
saved `/etc/hosts` hash.

The pre-fix attempts are preserved:

- [evidence/s8/run1/](evidence/s8/run1/) reached the behavior but is non-authoritative because the
  runner treated a zombie as live and had accidentally disabled `errexit`. Its original cleanup
  checks appeared clean but omitted `soglia0`; run2 exposed that gap, and the interface was then
  inspected and removed as test-owned residue.
- [evidence/s8/run2/](evidence/s8/run2/) stopped before any Execution because the backend correctly
  refused an unrecorded `soglia0` left by the first runner's incomplete scratch cleanup. The exact
  test-owned interface was inspected, removed and the resulting clean state recorded.
- [evidence/s8/run3/](evidence/s8/run3/) completed and independently reproduced the result. Run4
  added raw helper PPID/zombie/exit-code evidence and a bidirectional application-byte control, so it
  is the authoritative pre-fix classification run.

Pre-fix final cleanup removed the test unit and cgroups, state directory, runc resources, netns/veths,
`soglia0`, upstream dummy, nft state and ephemeral S8 rootfs/config; `/etc/hosts` matched its saved
baseline. There were zero test processes, Soglia BPF programs and cgroup links, and bpffs was empty.
The runner exited zero, emitted `S8_RESULT=FAIL`, and `git diff --check` remained clean.

Post-fix diagnostic attempts are also preserved rather than hidden:

- [evidence/s8/after-fix-run1/](evidence/s8/after-fix-run1/) captured a correct autonomous production
  transition, but its observer timed out because `pipefail` treated journald's expected `SIGPIPE`
  after `grep -q` as failure.
- [evidence/s8/after-fix-run2/](evidence/s8/after-fix-run2/) passed the security oracle, but sampled
  runtime-exit time only after the full seven-second no-effect window.
- [evidence/s8/after-fix-run3/](evidence/s8/after-fix-run3/) stopped in timestamp extraction because
  journald represents ANSI-bearing `MESSAGE` fields as byte arrays; its delayed cleanup overlapped
  after-fix-run4.
- [evidence/s8/after-fix-run4/](evidence/s8/after-fix-run4/) again proved bounded fail-closed runtime
  behavior, but the overlap made its `/etc/hosts` restoration check false, so it is non-authoritative.
  The exact test-owned marker and trailing separator were removed, and the restored hash
  `33129f26…ab561` matched the clean after-fix-run2 baseline before the final run.
- [evidence/s8/after-fix-run5/](evidence/s8/after-fix-run5/) used a type-aware journald filter,
  started with no overlapping runner and passed all assertions; it predates the final adjustment
  that avoids holding the process lock while the watcher awaits child exit.
- After-fix-run6 rebuilt and retested that final non-blocking watcher and passed every runtime,
  recovery and cleanup assertion.

**Historical violated invariant:** Enforcer death did not itself stop existing application traffic,
DNS or creation of a new outbound effect by already-admitted work; detection was deferred until
another helper RPC.

**Resolution:** the Supervisor now directly watches the helper child and uses one idempotent,
fail-closed cancellation transition; the authoritative regression proves the historical invariant is
no longer violated.

S8 is **PASS AFTER PRODUCTION FIX**.

#### S9 — foreign ancestor allow coexistence: PASS

**Authoritative evidence:** [evidence/s9/run4/](evidence/s9/run4/).

The fresh ancestor was
`/sys/fs/cgroup/system.slice/soglia-spike-s0.service/executions`, inode **25842**;
the child was `executions/s4-e1`, inode **25884**. The reused S4 causal harness retains its
historical `s4-*` labels, but all files for this run live under `evidence/s9/run4/`.
Before attach both fresh cgroups were empty and their direct/effective BPF snapshots were empty.
The actual agent PID **61334** was then proven in the exact child by both
`/proc/61334/cgroup` and `cgroup.procs`, and its netns inode **4026532344** equalled the owned
netns inode before traffic.

The unchanged synthetic object `/var/tmp/spike/bpf/foreign.o` had sha256
`5d8afe05…395e`. Only `foreign_allow` was attached to the ancestor, by legacy
`BPF_F_ALLOW_MULTI`; `foreign_rewrite` was loaded/pinned by `loadall` but never attached.
The allow program was id **1626**, tag `824ab03dccc4ea22`, type `cgroup_sock_addr`, attach type
`cgroup_inet4_connect`, and the ancestor direct snapshot reported `attach_flags: multi`.
Its id/tag remained identical after both security cases. Six child link attaches were direct and
seven programs were effective at the child (the six Soglia programs plus the ancestor allow).
These arrays prove presence/effectiveness only; **no execution order is inferred from their list
order**.

The spike-only userspace reader in
[harness/src/bin/foreign_trace.rs](harness/src/bin/foreign_trace.rs) consumed the existing
`foreign_trace` ring buffer without changing BPF enforcement semantics. It recorded exactly four
`who=2`, `rewritten=0` invocations in the harness command chronology: three direct
`10.201.0.2:16001` attempts and the proxy control to `10.200.255.1:15001`. Thus the ancestor allow
was not merely listed as effective: it actually ran for the security deny attempt and returned
ALLOW. This chronology does not establish, and the architecture does not require, a relative
foreign-versus-child program execution order.

For causal isolation, the namespace nft ruleset retained its default-drop input/output/forward
policy and proxy exception, while exactly one temporary output exception exposed
`10.201.0.2:16001`. Host anti-spoof/non-TCP checks and forwarding drops remained in place.
The before/after nft JSON hashes are identical (`fcde4758…ed00`); no unrelated nft rule changed.

| Case | Effective composition                                               | Observed result                                                                                                                                         |
| ---- | ------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------- |
| A    | ancestor `foreign_allow` + child Soglia deny                        | `connect4` entry 1, deny counter 1, per-cgroup deny entry 1 and deny event 1; process received `EPERM`; listener accepted nothing; no proxy involvement |
| B    | same ancestor `foreign_allow` + spike-only permissive child control | `connect4` entry 1, deny counter 0; connection established and the direct listener accepted it; no proxy involvement                                    |

This proves on kernel `6.8.0-134-generic` that the tested foreign ancestor ALLOW cannot neutralize
the child Soglia DENY. The successful B control excludes nft, route, listener and remaining topology
as alternative explanations for A's denial.

Cleanup removed the agent/harness/trace-reader processes, child and ancestor cgroups, both foreign
program pins, all Soglia links/maps/pins, netns, veth/dummy links and the test nft tables/rule.
Program, link, map and bpffs final snapshots equal their fresh baselines byte-for-byte; tuple/cookie
state therefore has no surviving map. The independent post-run check recorded zero Soglia/foreign
programs, zero cgroup links, empty bpffs, only `runtime/` below the delegated root, and
`independent_cleanup=PASS`.

Three non-authoritative attempts remain preserved rather than hidden:

- [run1](evidence/s9/run1/) completed the network comparison but the attempted `bpftool map
  event_pipe` reader rejected a ring-buffer map as non-perf-event, so its summary remained
  UNPROVEN.
- [run2](evidence/s9/run2/) added the correct Aya userspace reader and captured all four records,
  but a wrapper oracle incorrectly expected the first diagnostic counter to be zero.
- [run3](evidence/s9/run3/) again captured the complete behavior, but an over-constrained spacing
  expression made the wrapper miscount the otherwise present port records.

Run4 corrected only those evidence-oracle defects, independently repeated the fresh execution and
emitted `S9_RESULT=PASS`. No production file or S8 fix was changed for S9, no A/B/C/D candidate was
selected, and S10 was not started during that session.

#### S10 — ancestor destination rewrite / final nft barrier: PASS

**Authoritative evidence:** [evidence/s10/run3/](evidence/s10/run3/).

**Hard-gate question.** Can a foreign ancestor `cgroup/connect4` rewrite make traffic establish to
a final destination prohibited by Soglia's proxy-only nft policy? In the qualified kernel and
disposable topology tested here, **NO**. The causal control proves nft, rather than child BPF or an
unrelated layer, was the decisive barrier.

The fresh ancestor `executions/` had inode **26187** and the child `executions/s10-e1` inode
**26229**; both were empty before attach. Actual agent PID **62908** was proven in that exact child
by `/proc/62908/cgroup` and `cgroup.procs`, and its netns inode **4026532344** equalled the owned
namespace inode before traffic. Six child programs were direct and seven effective, including the
foreign ancestor program.

S10 added only compile-time defaults for the already-reserved spike program. The dedicated
`foreign-s10.o` (sha256 `eb6fed5f…8c5`) configured:

```text
original  10.200.255.1:15001  (native IPv4 u32 33540106, host port 15001)
rewrite   10.201.0.2:16001    (native IPv4 u32 33605898, host port 16001)
```

The object's `.rodata` bytes and build defines are preserved. Only `foreign_rewrite` was attached
to the ancestor in legacy MULTI mode; `foreign_allow` was loaded/pinned by `loadall` but was not
attached. The rewrite program was id **1693**, tag `8ee3f7fbc98e427b`, attach type
`cgroup_inet4_connect`, and remained the same id/tag through all observations.

The foreign ring buffer recorded exactly three invocations with `who=3`, original raw address
`33540106`, original port `15001` and `rewritten=1`. This proves invocation and mutation rather than
inferring them from source or a bpftool listing. The independent post-rewrite evidence was the nft
rule counter and, in the exposure control, the listener bound to `10.201.0.2:16001`.

The decisive pair kept the same foreign program, agent, child spike-only permissive BPF instance,
listeners, route and topology:

| Case                     | nft difference                                                                                             | Child BPF evidence                                                                      | Result                                                                                                            |
| ------------------------ | ---------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------- |
| A — normal final barrier | normal proxy exception only; rewritten destination matched a counter-only rule and then output-policy DROP | child saw original port 15001; `connect4` entry 1, deny counter/map/event all zero      | nft post-rewrite counter rose 0→2; process timed out; original and rewritten listeners accepted nothing           |
| B — narrow exposure      | added only `ip daddr 10.201.0.2 tcp dport 16001 ct state new counter accept`                               | same child instance; cumulative `connect4` entries 2, deny counter/map/event still zero | counter rose 2→3; rewritten listener accepted `10.201.0.1 → 10.201.0.2:16001`; original listener accepted nothing |

Because the child admitted both attempts and the same rewritten path established when only that
single nft verdict changed, another BPF hook, routing failure, namespace boundary or listener defect
cannot explain A. nft evaluated the **post-rewrite** tuple and was the final destination barrier.
The exposure rule was deleted by its captured handle. The normal namespace rule structure before
and after is identical with sha256 `70f50600…1547`; counter values are intentionally excluded from
that structural comparison because they are the observation.

**Normal Soglia composition.** With `foreign_rewrite`, the normal six Soglia programs and normal nft
policy, the Soglia diagnostic context observed original port **15001**, recorded no `connect4` deny,
and the foreign ring record then proved the rewrite. The nft post-rewrite counter advanced again
(3→5), neither listener accepted, and the process timed out. On this kernel/run the measured
chronology is therefore child sees original → foreign rewrites → nft sees rewritten and drops.
That statement derives from the child context and foreign/nft diagnostic events, **not** bpftool
list order. No universal kernel ordering claim is made and correctness does not depend on it.

Cleanup removed the agent, harness, trace reader, child and ancestor cgroups, foreign attachment and
pins, Soglia links/maps/pins, netns, veth/dummy links, host test table and namespace nft state.
Program, link, map and bpffs final snapshots equal their baselines byte-for-byte. Host nft structure
also equals baseline; the raw JSON preserves unrelated Lima DNS packet/byte counter churn. The
independent audit found only `runtime/` below the delegated root, zero Soglia/foreign programs, zero
cgroup links, empty bpffs, no owned process/network/nft residue, and `independent_cleanup=PASS`.

Two diagnostic attempts are preserved:

- [run1](evidence/s10/run1/) stopped before attach/traffic because `foreign_rewrite` lists its
  `.rodata` map before `foreign_trace`, unlike `foreign_allow`; selecting map id zero therefore found
  the wrong map. Cleanup and program/link/map/bpffs equality passed.
- [run2](evidence/s10/run2/) completed the full experiment and harness successfully, but the wrapper
  required byte-identical global host nft JSON. Only unrelated Lima DNS counters advanced, so the
  wrapper stopped before the final summary; its prematurely written zero status file is
  non-authoritative. Run3 compares raw files plus structure with only packet/byte counters removed.

Run3 independently repeated the topology and emitted `S10_RESULT=PASS`. This PASS is limited to the
qualified kernel and tested topology: it does not establish universal cgroup-BPF ordering, does not
authorize BPF steering, and does not weaken nft's architectural role. No production code or S8 fix
was changed for S10, no A/B/C/D candidate was selected, and S11 was not started.

#### S11 — complete zero-residue lifecycle: PASS

**Authoritative evidence:** [evidence/s11/run1/](evidence/s11/run1/).

The fresh baseline was captured immediately before S11 rather than inherited from S10. The
delegated unit was active at inode **12456** with only its pre-existing `runtime/` child (inode
**12516**). There was no `executions/` subtree, test process or runc container, owned netns/link/nft
table, bpffs path, Soglia/foreign program, cgroup BPF link, Soglia map or spike runtime marker.
Full raw process, cgroup, runc/runtime, netns/link, nft, bpffs and BPF program/link/map snapshots are
preserved; external/non-owned objects were recorded separately.

S11 reused the already-proven S1 topology without introducing another architecture. It created
Execution cgroup inode **26406**, live agent PID **63687**, owned netns inode **4026532344**, the
veth and proxy dummy link, host and namespace nft state, six direct/effective cgroup programs, six
pinned BPF links and ten applicable pinned maps. The diagnostic object has no delayed-publication
staging map, so ten rather than eleven maps is the expected applicable set. Nine `/run` barrier and
ownership markers made the spike's ephemeral runtime state independently observable.

Before traffic, `/proc/63687/cgroup` and the target `cgroup.procs` both proved exact membership, and
the agent's network-namespace inode equalled the owned namespace inode. While the agent remained
live, the proxy accepted `10.201.0.1:59278 -> 10.200.255.1:15001`; the tuple and cookie maps each
contained one entry, candidates A/B/C all resolved the current Execution, and Resolve returned
`s11-execution-generation-1`. The established socket, tuple key, map dumps, direct/effective hook
sets, pins, nft rules and runtime markers were captured before teardown. Thus absence was not
inferred from a lifecycle that failed to create the resources.

The trusted runner was then terminated deliberately after the live snapshot, so its recorded exit
status **143** is the teardown trigger rather than an unexpected test failure. Its S11-only cleanup
trace observed this practical order:

```text
freeze / prevent new effects (cgroup.events: frozen 1)
  -> cgroup.kill
  -> wait/reap process tree and harness
  -> remove runtime markers
  -> remove nft state
  -> remove veth/netns/dummy
  -> remove Execution cgroups
  -> remove BPF links/maps/pins and attribution maps
  -> release ownership/slot
```

No cgroup retry after BPF release was needed. This ordering instrumentation is spike-only and does
not change production code or attribution semantics.

The post-teardown verifier independently established all ten required absence classes:

| Owned class        | Post-teardown observation                                                                                 |
| ------------------ | --------------------------------------------------------------------------------------------------------- |
| processes          | agent PID gone; no exact `s1_attribution` or `soglia-spike-agent` process; delegated process set restored |
| cgroups            | Execution and `executions/` absent; only baseline `runtime/` remained                                     |
| container/runtime  | no runc container or `/run/runc` state; all nine spike markers absent                                     |
| network namespace  | owned namespace absent; host netns set restored                                                           |
| links              | test veth and dummy absent; normalized host link structure restored                                       |
| nftables           | host test table absent with namespace removal; normalized host ruleset structure restored                 |
| BPF links/programs | zero Soglia/foreign programs and zero cgroup links; normalized host sets restored                         |
| bpffs              | empty, with no map or link pin                                                                            |
| attribution        | zero Soglia maps, so tuple/cookie/staging/owner state cannot survive the Execution                        |
| ownership metadata | no `executions/` ownership slot and no runtime marker capable of claiming a future Execution              |

The combined owned-state snapshot is byte-identical before and after. BPF program/link/map sets,
normalized host link structure, normalized nft structure and the host netns set are also unchanged;
no external churn required an ownership exception. Whole-host process and packet counters were not
used as equality oracles, while the delegated-unit process set and all Soglia-owned objects were.
An independent audit after the runner completed again found only `runtime/`, empty bpffs, no test
process/runtime/network/nft object, and zero owned BPF programs, cgroup links and maps.

The first independent audit command used `pgrep -f` and therefore displayed its own command line;
that diagnostic output is preserved as `s11-independent-final-validation-attempt1-self-match.txt`.
The authoritative second audit matches exact process names and reports
`independent_cleanup=PASS`. The optional failure-in-teardown control was not repeated: existing S3
process-kill plus S7/S8 residue verifiers already demonstrate detection of partial lifecycle state.

S11 emitted `S11_RESULT=PASS`. No production file or S8 lifecycle fix was changed, no A/B/C/D
candidate was selected, and S12 was not started.

#### S12 — bounded map exhaustion / fail-closed: PASS

**Authoritative evidence:** [evidence/s12/run1/](evidence/s12/run1/).

S12 exercised the existing small-capacity mechanism rather than consuming normal limits. The
capacity-only `soglia-small.o` is built from the same source with only `SPIKE_TUPLE_MAX=8`; its BPF
program disassembly is identical to the normal object's after normalizing the object header. The
executed `soglia-small-diag.o` adds only the already-used entry counters and a passive S12 array
recording helper attempts, failures and signed return values. It does not change an update, policy,
publication, Resolve or deny branch. No production source or behavior changed.

Source and loaded-map inspection classified the state relevant to the currently exercised chain:

| Map/state                                               | Loaded type/capacity                       | Role and observed failure behavior                                                                                                                                       |
| ------------------------------------------------------- | ------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `soglia_tuples`                                         | hash, 8 entries (4096 normal)              | final sockops publication consumed by Resolve; failed update increments `C_TUPLE_INSERT_FAILED`, emits `EV_MAP_FULL`, and leaves no resolvable tuple                     |
| `soglia_cookie_a`                                       | hash, 8 entries (4096 normal)              | connect4 cookie-to-cgroup handoff consumed by sockops; failed update leaves candidate-A evidence absent and cannot itself authorize                                      |
| `soglia_sk_b`                                           | sk-storage, kernel reports `max_entries=0` | per-socket candidate-B handoff; allocation failure would leave B absent, but this map has no finite capacity knob that the current kernel/API can deterministically fill |
| `policy_local`                                          | one-element array                          | trusted loader updates the existing key and aborts setup on failure; it is not a dynamic insertion-exhaustion case                                                       |
| `soglia_policy`                                         | hash, 1024 entries                         | not read by this per-Execution `exec_ident != 0` path                                                                                                                    |
| `soglia_staging`                                        | absent from this non-delay object          | S1b-only staging, never read by Resolve                                                                                                                                  |
| counters, denies, ring buffer, diagnostics and metadata | diagnostic/metadata maps                   | observations only, never authorization state                                                                                                                             |

Candidate C is loader-set rodata, not a map insertion. Candidate D remains only a recorded netns
cookie in this spike; the trusted owner map required to test it has not been implemented. This map
inventory is a characterization of the chain, not selection of A, B, C or D.

The fresh Execution cgroup had inode **26583**. Before fill traffic, actual agent PID **64619** was
independently present in its exact `/proc` cgroup and `cgroup.procs`, and its netns inode
**4026532344** equalled the owned namespace inode. Six programs were direct and effective. Tuple
and cookie baselines were empty. A single pre-exhaustion connection published complete A/B/C
evidence, resolved to `s12-execution-generation-1`, and only then allowed the proxy to read
`HELLO 0`, proving the path worked before resource pressure.

**Phase A — proven full.** Eight concurrent sockets remained live. Their accepted tuples were
distinct, their eight socket cookies were distinct, every tuple publication succeeded, and every
entry carried A/B cgroup **26583** plus C identity **12001001**. Independent pinned-map dumps and
the live socket snapshot both showed exactly eight entries/sockets. The loaded contract reported
`max_entries=8` for both `soglia_tuples` and `soglia_cookie_a`; occupancy 8 therefore proves actual
fullness rather than inferring it from the number of operations. No application byte was read while
building the full state.

**Phase B — one overflow.** With all eight sockets still established, the proxy accepted exactly
one additional tuple, `10.201.0.1:42158 -> 10.200.255.1:15001`. Both bounded hash updates returned
the signed value **-7** on this kernel. That numeric result is reported only as this run's observed
helper behavior, not as a portable errno requirement. The cookie and tuple failure diagnostics each
advanced exactly once; sk-storage recorded zero allocation failures. `C_TUPLE_INSERT_FAILED`
became 1, one `EV_MAP_FULL` carried cookie 377 and destination port 15001, and successful tuple
publications remained at the preceding nine cumulative operations (one pre-control plus eight fill
sockets).

Occupancy stayed 8 before and after the failure, and the ninth accepted tuple was absent. Resolve
waited the bounded **2000 ms**, never repaired the missing tuple from peer IP, read zero application
bytes and performed zero DNS or outbound effects, then denied by closing the socket. The agent
observed connection reset (`errno 104`), but S12 does not make that particular userspace errno
normative. The decisive property is `UNRESOLVED -> DENY` with no fallback or effect.

**Causal capacity control.** The harness resolved and closed one specifically recorded fill tuple,
reducing both bounded-map occupancies from 8 to 7. Without changing BPF, nft, topology or policy, a
fresh same-class connection from source port 42168 then repopulated the free slot, carried complete
A/B/C evidence, resolved to the same Execution, and received its verdict. Failure counters did not
advance. This establishes exhaustion, rather than an unrelated path defect, as the cause of the
previous denial. Closing the remaining sockets returned tuple and cookie occupancy to zero.

Cleanup removed all agents/sockets, the Execution hierarchy, runtime markers, netns, veth/dummy,
nft table, BPF links/programs/maps and pins. Program, link, map and bpffs final snapshots are
byte-identical to their fresh baselines, and no tuple/cookie map remains in which attribution could
survive. The independent final audit found only baseline `runtime/`, empty bpffs, zero test
processes, zero Soglia/foreign programs, zero cgroup links, zero Soglia maps and no owned
network/nft/runtime object; it emitted `independent_cleanup=PASS`.

S12 emitted `S12_RESULT=PASS`. No production file or S8 lifecycle fix was changed, no A/B/C/D
candidate was selected, and S13 was not started.

#### S13 — pinned state compatibility / restart / ownership: FAIL

**Authoritative evidence:** [evidence/s13/run1/](evidence/s13/run1/).

S13 recovered the current pin contract before creating any state. `soglia_meta` is a one-element
array whose value is four `u64`s, but none of those slots has a defined owner, schema, ABI/layout or
generation meaning. The comment says that the loader writes the map; exhaustive harness inspection
found that loaders only name/pin it and never write or validate it. There is likewise no startup pin
inventory, compatibility decision or supported sweep/recreate state machine. The cleanup code uses
fixed known filenames and empty-directory removal; no broad recursive bpffs deletion was found, but
path membership itself is not trusted ownership metadata. Consequently the current contract cannot
distinguish owned-compatible, owned-incompatible and unknown state.

The fresh baseline reproved the active delegated unit at inode **12456**, with only its existing
`runtime/` child at inode **12516**. There was no `executions/` hierarchy, bpffs object, cgroup BPF
attachment, S13 process, netns or S13 nft/link state. Program, link and map snapshots were captured
before the experiment.

**Case A — current-object residue, compatibility unprovable.** The existing S7 loader loaded the
current `soglia-diag.o`, attached all six programs and pinned ten maps plus six links. S13 inserted
one explicit stale entry into each of `soglia_policy`, `soglia_cookie_a` and `soglia_tuples`; the
tuple represented `10.201.0.1:41000 -> 10.200.255.1:15001`. Before loader loss, raw dumps proved
those entries and all pins. `soglia_meta` was still exactly `[0, 0, 0, 0]`. After loader `SIGKILL`,
the same pinned kernel state and contents remained. This was a real prior-run pin set made from the
current object, but it could not be classified as trusted compatible state: no owner or compatibility
field exists. Case A is therefore **UNPROVEN**, not treated as compatible merely because the object
and path looked familiar.

**Case B — incompatible metadata unrepresentable.** S13 did not assign an invented meaning to one
of the four zero metadata words. There is no already-defined compatibility field that can be varied,
so no legitimate incompatible-owned fixture can be constructed or recognized. Startup/admission
was not claimed for this case. Case B is **UNPROVEN** with the missing schema/ABI/layout/owner
contract recorded explicitly.

**Case D — actual stale-map reuse at readiness.** After removing only the test-created old link
pins, the stale maps remained pinned. A fresh cgroup (inode **27138**) invoked the current loader
against the existing map root. It published `PINNED_READY` and reused the exact map identities:

| Map               | ID before restart | ID at new readiness | Stale entries at ready |
| ----------------- | ----------------: | ------------------: | ---------------------: |
| `soglia_policy`   | 973               | 973                 | 1                      |
| `soglia_tuples`   | 976               | 976                 | 1                      |
| `soglia_cookie_a` | 977               | 977                 | 1                      |
| `soglia_meta`     | 969               | 969                 | `[0,0,0,0]`            |

No inspection, ownership/compatibility decision or sweep happened before readiness. This run did
not claim that an agent completed an authorization from the stale tuple; the stronger prerequisite
already failed: stale attribution maps and their contents were silently reused by a new loader and
new Execution cgroup at readiness. That behavior is an explicit S13 FAIL condition and cannot be
justified by assuming identifiers are never reused.

**Case C — foreign state preserved but ignored.** In a separate clean pin root S13 created an array
map named `s13_foreign`, pinned as
`/sys/fs/bpf/soglia-spike/s13/foreign/maps/soglia-looking-foreign`, with recorded test provenance and
map ID **986**. It carried no valid Soglia metadata. The loader left the foreign object unchanged
(ID 986 and contents were identical), which proves it was not deleted by path. However, startup
performed no unknown-state diagnostic or ownership decision and still published `PINNED_READY`.
Thus the required unknown-state fail-closed ordering was not present even though the non-deletion
half of the control passed.

The combined result is **S13 FAIL**, rather than merely UNPROVEN: Cases A/B expose the undefined
contract, while Cases C/D empirically show forbidden runtime behavior—readiness with unclassified
foreign state and silent reuse of stale authorization maps. A future investigation must first define
a trusted ownership plus schema/ABI/layout/generation contract and a pre-readiness recovery state
machine; S13 deliberately did not invent either in this run.

Cleanup removed only objects whose test provenance was known. In particular, the foreign map was
kept through the startup attempt, its ID was rechecked, and only then removed as the exact object
created by the S13 runner. Final program, link, map and bpffs snapshots are byte-identical to the
fresh baseline. The independent audit found only baseline `runtime/`, empty bpffs, no Execution
cgroups, cgroup links, S13 processes, netns/veth/nft state or runtime markers and emitted
`independent_cleanup=PASS`.

Two non-authoritative setup attempts are retained separately. The first used a per-pin `bpftool`
link query unsupported for part of this link set; the second exposed a stale test readiness marker
left by that aborted collector. Neither produced an S13 result. Both were cleaned, the runner was
hardened to require marker absence, and the authoritative run starts from a newly captured clean
baseline. No production file or S8 fix was changed, no attribution candidate was selected, and S14
was not started.

#### S13 authorized spike-contract rerun: PASS

**Authoritative remediation evidence:** [evidence/s13/run2/](evidence/s13/run2/). The preceding
S13 FAIL and its [run1 evidence](evidence/s13/run1/) remain unchanged historical evidence.

The authorized work introduced only a spike contract, documented in
[S13-CONTRACT.md](S13-CONTRACT.md), plus a spike-only state manager and runner. It did not implement
the production `CgroupBpfBackend`, change the S8 lifecycle fix or select attribution candidate
A/B/C/D.

**Trust anchor and minimum binding.** The design follows Soglia's existing ownership-record
convention. `/run/soglia/cgroup-bpf-spike/state.json` is outside bpffs, under Soglia's root-owned
mode-`0700` state tree. Startup rejects symlinks, wrong uid/gid or mode, and publishes the mode-`0600`
record as a complete temporary file followed by file sync, atomic rename and directory sync. The
threat boundary does not claim protection from an attacker able to rewrite every root-owned Soglia
file and kernel object.
Runtime validation observed uid/gid `0:0`, modes `0700/0700/0600` for the parent, record directory
and record respectively; separate mode-`0755` and symlink controls both exited with the
unknown-state classification and no readiness marker.

The record contains only fields needed for classification and exact recovery: magic, record-schema
version, BPF ABI version, random 128-bit state ID, generation, `INTENT`/`READY` phase, exact pin root,
BPF-object SHA-256, original cgroup path/inode and the validated kernel map/program/link IDs.
`soglia_meta` now contains six `u64` slots carrying magic, schema, ABI, the same 128-bit state ID and
generation. The map is corroborating state only: a copied pathname or metadata map without the
matching trusted record cannot establish ownership.

**Object contract and readiness.** ABI 1 fixes ten map roles and six links. The manager queries the
kernel for every map's type, key/value widths, capacity and flags; the six program names/types and
attach types; every cgroup link's type, program ID, attach type and cgroup inode; exact pin inventory;
and recorded object identity. A missing, extra or mismatched object refuses startup. The exact BPF
object digest additionally prevents a different build from being treated as compatible. Compatible
means safe to identify and sweep, never safe to reuse for authorization.

Creation is write-ahead ordered:

```text
validate trust/classify old state
  -> validate and exactly sweep compatible residue
  -> verify old kernel IDs and pin root absent
  -> atomically publish new INTENT
  -> create pins and matching soglia_meta
  -> validate kernel object contract
  -> atomically publish READY with exact IDs
  -> startup.ready
```

Four injected crashes empirically covered `INTENT` before bpffs, pins before metadata, validated
objects before the READY record, and READY record before runtime readiness. Every crash had no
readiness marker; the next startup classified the residue, swept it where present, advanced from
generation 1 to 2, rebuilt clean state and only then published ready. A temporary or absent record
never authenticates an existing pin root. An unexpected object under the recorded root is unknown,
not removable residue.

**Case A — known compatible.** Generation 1 used a genuine current object and trusted record. Its
policy, cookie and tuple maps each received one stale authorization entry. Restart matched the
external record, six-word metadata, object digest and complete kernel manifest, then removed and
verified absence of every old map/program/link before creating generation 2. Old map IDs
**1082–1092** (non-contiguous by role) had no intersection with new IDs **1096–1106**. The fresh
policy, cookie and tuple maps were empty when readiness appeared. Recovery log order was compatible
classification, verified sweep, new INTENT, new READY, then `startup_ready=true`.

**Case B — known incompatible.** The test changed only the trusted record's ABI from 1 to 2 while
preserving its valid owner/state binding and kernel objects. Startup exited with the dedicated
incompatible classification, emitted no readiness marker, attached nothing to the new cgroup and
left all old object IDs, metadata and stale tuple state unchanged. It performed no silent migration
or admission. The test harness restored the exact trusted record it had created before invoking
contract-aware cleanup.

**Case C — unknown/foreign.** With no trusted record, a foreign array map was placed at the especially
dangerous expected pathname `.../maps/soglia_policy`. Startup classified the existing bpffs root as
unknown, emitted no readiness marker and did not inspect the name as ownership proof. Foreign map ID
**1123**, type and contents were identical before and after the attempt. Only the S13 harness that
created and rechecked ID 1123 removed it during test cleanup.

**Case D — stale generation.** The old and new records carried distinct 128-bit state IDs and
generation advanced from 1 to 2. All old map/program/link IDs were absent before readiness, new
authorization maps were empty, and an explicit lookup of the old
`10.201.0.1:41000 -> 10.200.255.1:15001` tuple in the new map returned absent. This is lifecycle and
generation proof, not an assumption that kernel IDs never repeat: no old state object or entry
exists in the new authorization generation.

The final program, link, map and bpffs snapshots are byte-identical to the fresh baseline. An
independent audit found only the baseline `runtime/` cgroup, empty bpffs, no Execution cgroups,
record/ready marker, test process, netns/link or nft state and emitted `independent_cleanup=PASS`.
The runner emitted `S13_RESULT=PASS_AFTER_SPIKE_CONTRACT`; S13 is therefore **PASS after the
spike-only contract**, with the original FAIL explicitly retained. S14 was not executed in that
S13 session; it is characterized separately below.

#### S14 — Candidate-C operational cost / scaling: PASS

**Authoritative evidence:** [evidence/s14/run1/](evidence/s14/run1/). The raw matrix runner exited
1 when it discovered the bounded N=64 resource limit; that exit and the partial N=64 log are
preserved. The overall S14 classification is PASS under the stated characterization rule because
N=1/4/16/32 completed, the first higher point was bounded to an exact resource and operation, and
both the successful points and limit path returned to the clean baseline. The limit was not tuned
away.

**Recovered resource model.** Candidate C remains unselected. Each Execution receives a separately
loaded object whose loader overrides the read-only `exec_ident`; the local one-element
`policy_local` map is activated for that instance. Each instance loads six separate programs,
attaches six separate cgroup links to its fresh cgroup and pins those six links below its own link
directory. Eight `soglia_*` maps are pinned by name and empirically shared across all instances:
policy, tuple, cookie-A, sk-storage-B, events, counters, denies and metadata. Each instance adds only
two unpinned maps, `policy_local` and `.rodata`. S14 did not change this implementation to improve
its measurements.

The observed count equations over every complete point are:

```text
programs(N)              = 6N
cgroup links(N)          = 6N
maps(N)                  = 8 shared + 2N
pins(N)                  = 8 shared-map pins + 6N link pins
translated program bytes = 5,736N
JIT program bytes        = 4,728N
program memlock bytes    = 24,576N
map memlock bytes        = 1,175,280 shared + 800N
```

The byte values are kernel-reported `bpftool` accounting on this kernel, not estimates of total
host memory. Full raw program/link/map IDs and per-name groupings are retained at every point.

**Scaling matrix.** Network topology was created before the Candidate-C preparation timer. Setup is
the measured full load/configure/attach/pin loop; the component columns are contained within that
total and do not account for every userspace orchestration instruction. BPF teardown covers
unpin/close/removal of Candidate-C BPF state. Full teardown additionally covers the experiment's
cgroups and network namespaces.

| N requested | Result        | Complete instances | Programs                                           | Links       | Maps                                       | Pins        | Object load ms | Local policy ms | Program load ms | Attach ms    | Pin ms       | Setup ms      | BPF teardown ms | Full teardown ms | Attribution checks   |
| ----------: | ------------- | -----------------: | -------------------------------------------------: | ----------: | -----------------------------------------: | ----------: | -------------: | --------------: | --------------: | -----------: | -----------: | ------------: | --------------: | ---------------: | -------------------: |
| 1           | PASS          | 1                  | 6                                                  | 6           | 10                                         | 14          | 0.492          | 0.001           | 0.493           | 0.099        | 0.015        | 10.786        | 0.125           | 13.370           | 1                    |
| 4           | PASS          | 4                  | 24                                                 | 24          | 16                                         | 32          | 0.935          | 0.003           | 1.855           | 0.156        | 0.065        | 37.178        | 0.218           | 18.283           | 2                    |
| 16          | PASS          | 16                 | 96                                                 | 96          | 40                                         | 104         | 2.316          | 0.011           | 6.923           | 0.254        | 0.243        | 139.339       | 0.470           | 58.068           | 3                    |
| 32          | PASS          | 32                 | 192                                                | 192         | 72                                         | 200         | 4.097          | 0.020           | 13.154          | 0.389        | 0.414        | 295.545       | 0.877           | 111.789          | 3                    |
| 64          | BOUNDED LIMIT | 44                 | 264 derived from 44 complete six-program instances | 264 derived | not snapshotted before fail-closed cleanup | 272 derived | partial only   | partial only    | partial only    | partial only | partial only | not completed | n/a             | cleanup only     | traffic not released |

At N=1 the fixed sample was Execution 0; at N=4 it was first/last; at N=16 and N=32 it was
first/middle/last. The sampling rule was written before results. For every sampled connection, the
trusted host PID equalled the actual agent PID, `/proc/<pid>/cgroup` and `cgroup.procs` named the
exact fresh Execution cgroup, and the process netns inode equalled the owned netns inode. All six
programs were direct and effective for every Execution. Resolve used the accepted socket tuple to
read Candidate-C identity, mapped it uniquely to that Execution, and only then read application
bytes. A/B cgroup evidence independently matched the cgroup inode. Across nine checks there was no
identity alias, cross-attribution or IP-derived authorization.

**Bounded resource limit.** N=64 was attempted only after N=32 passed and the VM still had more
than 7 GiB available memory. The authoritative run completed instances 0–43 and failed while
`EbpfLoader::load_file` was processing a pinned map for instance index 44 (the 45th instance), naming
`soglia_cookie_a`. A narrow rerun of only that boundary recorded the process soft/hard open-file
limits as 1024/1048576, four open FDs initially, and an exact increase of 23 FDs per complete
instance: 993 before instance 43, 1016 after it, then failure during instance 44. Aya's structured
error was `MapError(CreateError { name: "soglia_meta", io_error: ... code: 24 ... "Too many open
files" })`. The particular map reached at exhaustion varied with map processing order; both runs
agree on the exact `load_file` map phase, instance boundary and `EMFILE` cause. No limit was raised,
and S14 stopped increasing N.

The +23 FD delta is empirical. S14 did not fully attribute every retained FD to a particular Aya
handle, so that internal breakdown remains an unresolved operational detail rather than an inferred
fact.

After each complete point, normalized program/link/map identities and the bpffs tree matched the
point's fresh baseline. The N=64 authoritative failure and the FD diagnostic independently removed
all exact pins, programs, links, maps, cgroups and runtime files. The final audit found only the
baseline `runtime/` child, empty bpffs, no Execution cgroup, S14 process, netns, veth, nft state,
tuple/cookie attribution or S13 trusted-record scratch state. S14 therefore emitted the synthesized
`S14_RESULT=PASS`; it did not select Candidate C, change production code or start B1–B7.

## 11. Final spike handoff

### Status matrix

| Stage | Final status                                                            |
| ----- | ----------------------------------------------------------------------- |
| S0    | PASS; environment plus S0.1–S0.5, with no security claim                |
| S1    | PASS / `S1_CHAIN_PROVEN` after the minimum spike-only port fix          |
| S1b   | PASS                                                                    |
| S2    | PASS                                                                    |
| S3    | PASS                                                                    |
| S4    | PASS                                                                    |
| S5    | PASS                                                                    |
| S6    | PASS as evidence synthesis                                              |
| S7    | PASS                                                                    |
| S8    | PASS AFTER PRODUCTION FIX; authoritative pre-fix FAIL preserved         |
| S9    | PASS                                                                    |
| S10   | PASS                                                                    |
| S11   | PASS                                                                    |
| S12   | PASS                                                                    |
| S13   | PASS AFTER SPIKE-ONLY CONTRACT; original FAIL preserved                 |
| S14   | PASS characterization; N=64 bounded by the 45th-instance `EMFILE` limit |
| B1–B7 | NOT STARTED / NOT PASSED                                                |

### Historical FAIL → fix → regression sequences

- **S1:** the original accepted connections had no BPF state because the live agent was not in the
  attached cgroup. Host-first PID placement proved exact cgroup/netns membership and hook entry, then
  exposed `tuple.dport=0`. Raw port tracing proved an extra right shift after full-width `ntohl`;
  removing only that shift produced the correct port 15001 and the complete trusted Resolve chain.
- **S8:** Enforcer `SIGKILL` was invisible until a later RPC and left a proven four-second effect
  window. The authorized production fix added independent child-exit watching plus one-way runtime
  cancellation across ingress, egress, DNS, tunnels and sandbox termination. The final regression
  detected loss in 8 ms, bounded complete shutdown within 131 ms, observed no effects for 7,039 ms,
  and proved ordered restart recovery.
- **S13:** the original pin scheme had no trusted owner/schema/ABI/generation contract and reused
  stale authorization maps at readiness. The authorized spike-only manager added the external
  root-owned trust record, corroborating metadata, exact manifest validation, compatible
  sweep/recreate, incompatible/unknown refusal and write-ahead crash recovery. Run2 passed all four
  classifications and crash boundaries without becoming production code.

### Surviving candidate facts and unresolved questions

| Candidate                                  | Facts surviving the spike                                                                                                                                | Candidate-specific unresolved questions                                                                                                                                                                             |
| ------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| A — socket cookie → cgroup ID              | Published and resolved correctly in S1–S3; concurrent and lifecycle cases had zero cross-attribution; bounded cookie-map exhaustion failed closed in S12 | Production owner/state integration, sizing and eviction/cleanup policy, and behavior over the full supported kernel/deployment matrix                                                                               |
| B — socket local storage → cgroup ID       | Published and resolved correctly in S1–S3 and matched trusted cgroup identity; socket lifetime owns storage                                              | Deterministic allocation-pressure characterization was not possible with the exposed `sk_storage` capacity model; production ownership, observability and kernel-matrix behavior remain open                        |
| C — per-Execution object/embedded identity | Correct in S1–S3 and every S14 sample; exact scaling is 6 programs, 6 links, 2 private maps and 6 link pins per Execution plus 8 shared maps/pins        | How production would avoid or budget the measured +23 loader FDs per live instance; whether loaders are sharded/short-lived; production identity provisioning, restart ownership and acceptable setup/teardown cost |
| D — netns cookie                           | Helper availability and distinct lifecycle cookies were observed under the approved licence                                                              | Trusted live cookie→Execution owner mapping, lifecycle/reuse safety, authorization use, stale-state behavior and scaled operation were not tested                                                                   |

This table is intentionally not a ranking. No A/B/C/D candidate is selected or eliminated by S14.
The separate cgroup-storage route in section 6 remains unavailable through the two tested
non-GPL-compatible pointer-acquisition paths on this kernel; ordinary hash state remains possible.

### Production requirements learned

1. Place and independently verify the actual live agent PID in the exact attached cgroup before
   releasing traffic; do not infer placement from runtime configuration.
2. Keep tuple key representations explicit. On this kernel `sock_ops.remote_port` needs one
   full-width network-to-host conversion and no subsequent half-word shift.
3. Resolve must remain bounded and fail closed before application reads, DNS, outbound effects or
   any IP-derived fallback.
4. nftables remains the final destination barrier. cgroup-BPF supplies early denial and attribution,
   not routing or proxy steering.
5. Preserve all six required hooks and validate direct/effective attachment plus ancestor
   composition on startup.
6. Treat link/map/pin state as owned only through a trusted external record and exact kernel
   manifest; compatible restart recreates empty authorization state, while incompatible or unknown
   state refuses readiness.
7. Make helper death an autonomous lifecycle event that cancels every active/pending effect and
   terminates affected Executions before recovery readiness.
8. Bound maps, surface update/allocation failures, and make missing attribution deny rather than
   repair from network identity.
9. Budget kernel program/link/map/JIT/memlock resources and userspace FDs as concurrent Executions
   grow. A single long-lived Candidate-C Aya loader under soft `RLIMIT_NOFILE=1024` cannot reach 45
   complete instances in this implementation.
10. Teardown must use exact recorded ownership, verify absence across cgroups/BPF/bpffs/network/nft
    and runtime state, and never delete unknown objects by pathname alone.

### Explicitly not proven

- No final attribution candidate or production Phase-1 architecture has been selected.
- Production `CgroupBpfBackend` is not implemented; the S13 manager remains spike-only.
- B1–B7 have not started and have no PASS evidence.
- Results are limited to the recorded Linux 6.8.0-134 aarch64 VM; portability to other kernels,
  architectures and BPF implementations is not established.
- S14 is not a throughput, tail-latency or sustained-churn benchmark. It does not establish an
  acceptable product performance threshold.
- Candidate C did not complete N=64 under the measured single-loader soft-FD limit; operation at
  N≥45 in that process shape is not proven.
- Candidate D's trusted owner mapping and Candidate B's deterministic allocation-exhaustion behavior
  remain unproven.
- Long-duration hostile workloads, production upgrade/migration, multi-process loader coordination,
  and crash recovery of a future production backend remain untested.

### Repository and evidence hygiene

All historical failure, setup-diagnostic and successful evidence remains present. S14 adds only
spike code/runners and [evidence/s14/run1/](evidence/s14/run1/); the raw N=64 exit status 1 and both
map names observed at the FD boundary are retained rather than normalized away. No commit was made.
The only production modifications in the worktree remain the previously authorized S8
lifecycle/cancellation fix; S14 did not modify it. The spike leaves the VM with the delegated unit
active, only baseline `runtime/`, empty bpffs and no test-owned cgroup, process, namespace, veth, nft,
pin, map, program, link, attribution or S13 record residue.

The next action is human review of candidates A/B/C/D. Do not start B1–B7 or implement
`CgroupBpfBackend` without separate authorization.

## 12. Handoff

**Resume the VM:**

```sh
limactl list                                   # soglia-spike, vz, aarch64
limactl start soglia-spike                     # if stopped
limactl shell --workdir /soglia soglia-spike   # repository at /soglia
```

**Recreate the VM from scratch** (commands already executed once):

```sh
limactl create --tty=false --name=soglia-spike spikes/cgroup-bpf/lima.yaml
limactl start --tty=false soglia-spike
limactl shell soglia-spike -- sudo DEBIAN_FRONTEND=noninteractive apt-get install -y \
    clang llvm libbpf-dev linux-libc-dev linux-tools-common "linux-tools-$(uname -r)" \
    iproute2 nftables runc jq build-essential musl-tools pkg-config
limactl shell soglia-spike -- bash -c 'curl --proto "=https" --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain 1.97'
limactl shell soglia-spike -- bash -c '. ~/.cargo/env && rustup target add aarch64-unknown-linux-musl'
```

**Rebuild what exists:**

```sh
limactl shell --workdir /soglia soglia-spike -- spikes/cgroup-bpf/build.sh /var/tmp/spike/bpf
limactl shell --workdir /soglia/spikes/cgroup-bpf soglia-spike -- bash -c \
    '. ~/.cargo/env && CARGO_TARGET_DIR=/var/tmp/spike/target cargo build --release -p soglia-spike-agent --target aarch64-unknown-linux-musl'
limactl shell --workdir /soglia soglia-spike -- bash -c \
    '. ~/.cargo/env && CARGO_TARGET_DIR=/var/tmp/spike/target cargo build --release --manifest-path spikes/cgroup-bpf/Cargo.toml -p soglia-spike-harness --bin s1_attribution --bin foreign_trace --bin s10_rewrite --bin s12_exhaustion --bin s14_scaling'
```

**Reproduce the licence verdicts:**

```sh
limactl shell --workdir /var/tmp/spike/bpf soglia-spike -- sudo bash -c \
    'for o in soglia netns-probe foreign gpl-probe-task-btf gpl-probe-cgroup-from-id; do
         bpftool prog loadall $o.o /sys/fs/bpf/verify-$o && echo "$o LOADED" || echo "$o REJECTED"
         rm -rf /sys/fs/bpf/verify-$o
     done; rm -f /sys/fs/bpf/soglia_*'
```

The final `rm` matters: `loadall` pins the objects' by-name maps under `/sys/fs/bpf/`.

**Artifact paths in the VM:**

| Path                                                                          | What                                                    |
| ----------------------------------------------------------------------------- | ------------------------------------------------------- |
| `/var/tmp/spike/bpf/*.o`, `/var/tmp/spike/bpf/vmlinux.h`                      | BPF objects, generated header                           |
| `/var/tmp/spike/target/aarch64-unknown-linux-musl/release/soglia-spike-agent` | Spike agent                                             |
| `/var/tmp/spike/target/release/foreign_trace`                                 | S9/S10 spike-only ring reader                           |
| `/var/tmp/spike/target/release/s10_rewrite`                                   | S10 spike-only harness                                  |
| `/var/tmp/spike/target/release/s12_exhaustion`                                | S12 spike-only harness                                  |
| `/var/tmp/spike/target/release/s14_scaling`                                   | S14 spike-only scaling harness                          |
| `/var/tmp/spike/target/release/s7_pinned_loader`                              | S7/S13 spike-only pin loader                            |
| `spikes/cgroup-bpf/run-s13.sh`                                                | S13 characterization runner                             |
| `spikes/cgroup-bpf/s13-state-manager.sh`                                      | S13 spike ownership manager                             |
| `spikes/cgroup-bpf/run-s13-v2.sh`                                             | S13 contract rerun                                      |
| `spikes/cgroup-bpf/S13-CONTRACT.md`                                           | S13 spike-only contract                                 |
| `spikes/cgroup-bpf/run-s14.sh`                                                | S14 authoritative matrix runner                         |
| `spikes/cgroup-bpf/run-s14-limit-diagnostic.sh`                               | S14 FD-boundary diagnostic runner                       |
| `spikes/cgroup-bpf/evidence/s0/` (host and VM, via the `/soglia` mount)       | S0 evidence files                                       |
| `spikes/cgroup-bpf/evidence/s9/run4/`                                         | Authoritative S9 evidence                               |
| `spikes/cgroup-bpf/evidence/s10/run3/`                                        | Authoritative S10 evidence                              |
| `spikes/cgroup-bpf/evidence/s11/run1/`                                        | Authoritative S11 evidence                              |
| `spikes/cgroup-bpf/evidence/s12/run1/`                                        | Authoritative S12 evidence                              |
| `spikes/cgroup-bpf/evidence/s13/run1/`                                        | Historical S13 FAIL evidence                            |
| `spikes/cgroup-bpf/evidence/s13/run2/`                                        | Authoritative S13 PASS rerun                            |
| `spikes/cgroup-bpf/evidence/s14/run1/`                                        | Authoritative S14 evidence and bounded-limit diagnostic |

**State left behind:** the VM is running.
The delegated unit `soglia-spike-s0.service` is active, with MainPID 22563 and delegated-root inode 12456; below the root only `runtime/` exists.
S0.5 removed the S0.4 `executions/` (13326) and `s0-probe` (13368); inodes 5160, 13326 and 13368 are all historical.
`/sys/fs/bpf/` is empty; no Soglia/foreign program or cgroup link is loaded or attached; no test netns, veth or nftables table of Soglia exists in the VM.
S9's independently verified cleanup removed its fresh `executions/` ancestor (inode 25842) and child (inode 25884), and restored program/link/map/bpffs state exactly to baseline.
S10's independently verified cleanup removed its fresh `executions/` ancestor (inode 26187) and child (inode 26229), restored program/link/map/bpffs exactly, and restored host nft structure; only unrelated Lima DNS packet/byte counters advanced in the preserved raw JSON.
S11's independently verified cleanup removed its fresh Execution (inode 26406), agent PID 63687, runtime markers, netns, links and nft state; restored the exact owned baseline and normalized host link/nft/netns and BPF sets; and left zero Soglia maps, programs, cgroup links or bpffs pins.
S12's independently verified cleanup removed its fresh Execution (inode 26583), all test agents/sockets, runtime markers, netns, links and nft state; restored program/link/map/bpffs sets byte-for-byte; and left no small-map object or tuple/cookie attribution state loaded.
S13's independently verified cleanup removed the fresh cgroups, six-link pin sets, reused stale maps, exact test-created foreign map and runtime markers; restored program/link/map/bpffs sets byte-for-byte; and left no S13 process, network/nft state or unpinned attribution object loaded.
S13 run2 independently removed every contract-rerun cgroup, record/ready marker, compatible or incompatible test-owned pin set and exact-ID foreign control; restored program/link/map/bpffs byte-for-byte; and left `/run/soglia/cgroup-bpf-spike` absent.
S14 restored normalized program/link/map identity sets and bpffs after every complete scale point. Its N=64 limit path and narrow `EMFILE` diagnostic also removed all 44 complete partial instances and every exact test-owned cgroup, pin, program, link, map and runtime file. Final bpffs is empty and no S14 namespace, veth, nft state, process, attribution map or S13 trusted-record scratch state remains.
Stopping or restarting the unit removes its cgroups; every later step that needs a target cgroup starts with a new preflight and records the new inode.
