---
title: Run Soglia
description: Build Soglia, give it a delegated cgroup subtree, start it and send it a first call.
---

<!-- Copyright (c) 2022 Nitro Agility S.r.l. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Run Soglia

This page takes you from a Linux host to a first call answered by a fresh Execution.

## Requirements

Soglia runs only on Linux, and the `soglia` binary builds only for Linux.

| Requirement                  | Why                                                   |
| ---------------------------- | ----------------------------------------------------- |
| Rust 1.97+                   | Build Soglia                                          |
| cgroup v2, delegated subtree | Per-Execution resource limits and teardown            |
| `nft` (nftables)             | Network policy for each Execution                     |
| `ip` (iproute2)              | Network namespaces, veth pairs, addresses and routes  |
| `runc`                       | Start each Execution from an OCI bundle               |
| Task or Make                 | Run the project workflows                             |

On macOS or Windows, build and run Soglia inside the Linux development container of the repository, in [`.devcontainer/`](https://github.com/permguard/soglia/tree/main/.devcontainer).

## Build

From a clone of [permguard/soglia](https://github.com/permguard/soglia):

```sh
task build RELEASE=1
```

The binary is `target/release/soglia`.

## Configure

A configuration names the unprivileged user Soglia drops to, the ingress address, the destinations agents may reach and the agents themselves.
Start from the minimal example in the repository, [`examples/soglia.yaml`](https://github.com/permguard/soglia/blob/main/examples/soglia.yaml):

```yaml
runtime:
  # The unprivileged user the Supervisor, ingress and egress proxy run as after startup.
  uid: 990
  gid: 990
  max_concurrency: 4
  max_queue: 16

ingress:
  listen: 127.0.0.1:8088

network:
  backend: cgroup-bpf

egress:
  allow:
    - host: api.example.com
      ports: [443]

agents:
  echo:
    # A read-only root filesystem holding the agent and the directories /proc, /dev, /sys and /tmp.
    rootfs: /var/lib/soglia/rootfs/echo
    command: ["/agent"]
    env:
      AGENT_PORT: "8080"
    port: 8080
```

Every field not written takes its default.
Unknown fields are refused, so a misspelt setting stops the runtime instead of being ignored.
The network default is `cgroup-bpf`, which requires the qualified Linux cgroup v2, systemd delegation, bpffs and BPF capabilities.
Startup fails closed when they are unavailable; Soglia never downgrades automatically.
Set `network.backend: netns-nft` explicitly only for a compatibility deployment.

## Give Soglia a delegated cgroup

Soglia creates each Execution's cgroup below a cgroup v2 subtree delegated to it.
With systemd, run it as a unit with `Delegate=yes`, like the one in the repository, [`dev/systemd/soglia.service`](https://github.com/permguard/soglia/blob/main/dev/systemd/soglia.service):

```ini
[Unit]
Description=Soglia Runtime
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/soglia run -f /etc/soglia/soglia.yaml
Delegate=yes
KillMode=mixed
TimeoutStopSec=90
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

## Start it

`soglia run` starts as root, starts its two privileged helpers, and then drops to the unprivileged user the configuration names.

```sh
soglia run -f examples/soglia.yaml
```

Soglia admits calls only once it logs `startup.ready`.

## Send a first call

```sh
curl -X POST --data 'echo hello' http://127.0.0.1:8088/v1/execute/echo
```

The call runs in a fresh Execution of the `echo` agent.
By the time the response reaches you, that Execution has been destroyed.

## Uninstall Soglia

Stop the Soglia runtime before uninstalling it, and verify that the systemd unit is no longer running.
Start with a dry run, which performs the same ownership validation and displays the exact plan without changing the host:

```sh
soglia uninstall --dry-run -f /etc/soglia/soglia.yaml
soglia uninstall -f /etc/soglia/soglia.yaml
```

Verified uninstall removes only resources whose durable records and current kernel identities prove that Soglia owns them.
There is no `--force` option, and unproved state is preserved for operator inspection.
If an uninstall is interrupted after its durable intent is recorded, run the same command again to resume that exact plan.

| Exit status | Meaning | What to do |
| ----------- | ------- | ---------- |
| `0` | Uninstall completed, resumed successfully, or the host was already clean | No further cleanup is required |
| `20` | Recorded schema, ABI or object is incompatible | Use the matching Soglia version or a qualified migration, and do not delete the state manually |
| `21` | Ownership is unknown or recorded and kernel identities disagree | Inspect the reported trusted state path and preserve the objects until ownership is resolved |
| `22` | A required kernel or host capability is unsupported | Restore the required capability on a qualified host and retry |
| `23` | An independent host, I/O or service operation failed | Correct the reported infrastructure problem and retry |
| `24` | The cgroup-BPF attachment topology is incompatible | Resolve the reported hook and errno conflict, then retry without deleting pins manually |

On systemd 255, a stopped unit can occasionally leave an empty `runtime` cgroup after systemd ignores an `EBUSY` pruning race.
The empty leaf contains no process and is harmless: the next trusted startup reuses it, and verified uninstall removes it by exact path.

## Next

- [How it works](../how-it-works): what happens between the call and the response.
- [Use cases](../use-cases): where the same pattern applies.
