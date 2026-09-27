<!-- Copyright (c) 2022 Nitro Agility S.r.l. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Reproducible cgroup-BPF spike

This directory contains the second-generation Soglia cgroup-BPF qualification suite.
It is experimental test machinery and is not part of the production runtime.

The completed exploratory spike is preserved without modification in `../cgroup-bpf-historical/`.
The new suite migrates its validated BPF and agent semantics while moving lifecycle control, assertions, evidence, ownership, cleanup and verdicts into one Rust runner.

## Execution modes

`soglia-spike-dev` is the reusable development VM.
Diagnostic commands such as `run --only s0` may execute there and always record `authoritative: false`.
The development wrapper rejects `run` without `--only` or `--from`; only
`run-fresh.sh` may invoke the authoritative command shape.

An authoritative run uses a newly created `soglia-spike-replay-<id>` VM with no prior authoritative marker.
It starts at S0, runs in canonical order, never retries a security observation, and stops at the first non-PASS result.

After the first complete replay passes, the unchanged source and bootstrap are run on a second newly created VM.
Candidate review remains out of scope until both independent replays pass.

## Host entry points

```sh
./spikes/cgroup-bpf/host/run-dev.sh doctor
./spikes/cgroup-bpf/host/run-dev.sh run --only s0
./spikes/cgroup-bpf/host/run-fresh.sh
```

The host scripts create or start Lima, provision packages, build every artifact inside Linux, invoke the runner and propagate its exit code.
Only the Rust runner classifies security results and verifies cleanup.

See [SPEC.md](SPEC.md) for the normative suite contract and [MIGRATION.md](MIGRATION.md) for the old-to-new mapping.

After reproducibility confirmation and candidate review, the human reviewer selected Candidate A for the first production design.
See [PRODUCTION-DESIGN.md](PRODUCTION-DESIGN.md) for the design and the unexecuted B1-B7 qualification matrix.
