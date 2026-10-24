<!-- Copyright (c) 2022 Nitro Agility S.r.l. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Soglia

[![licence](https://img.shields.io/badge/licence-Apache--2.0-blue)](LICENSE)

<p align="center">
  <img src="https://raw.githubusercontent.com/permguard/soglia/main/assets/readme/hero.png?v=2" alt="Soglia. Trusted execution for AI agents. One call, one fresh Execution, gone when it ends. Agentic Execution Fabric, in development. Soglia is Italian for threshold." width="820">
</p>

<p align="center">
  <a href="https://github.com/permguard/permguard"><b>Permguard</b></a> ·
  <a href="https://www.pic-protocol.org"><b>PIC protocol</b></a> ·
  <a href="#status"><b>Status</b></a> ·
  <a href="#running"><b>Running</b></a>
</p>

**Trusted execution for AI agents and mission-critical workloads, under authority that never expands.**

*Soglia* is Italian for **threshold**: the boundary something must cross before it can have an effect on the outside world.
For an autonomous agent, Soglia is that boundary.
Agents think and propose.
Soglia decides what may execute, isolates the code that executes it, and lets its effects leave only through mediated boundaries.

> [!IMPORTANT]
> Soglia is under development.
> The pictures below describe the target security model; [Status](#status) says exactly what Phase 0 runs today.

## The missing security boundary

Modern authorization can decide **who may do what**.
PIC goes further: it proves **which causal execution the authority belongs to**, and whether that authority may continue to the next step.
One boundary is still left: **the code that actually exercises that authority.**

<p align="center">
  <img src="https://raw.githubusercontent.com/permguard/soglia/main/assets/readme/compare.png" alt="Left, a traditional server: requests A, B and C share one long-lived process with its credentials, caches, connections and global state, which become ambient authority. Right, Soglia: each request gets its own Execution with its own authority, destroyed at the end, so B never reuses A's authority. The process is no longer the security unit. The invocation is." width="820">
</p>

Traditional workers and API servers execute many requests inside the same long-lived process.
Credentials, globals, caches, connections and mutable state become ambient authority.
Security then depends on every function always receiving, preserving and using the correct context, and that is too weak for untrusted or probabilistic AI code.

Soglia changes the unit of security from the **service** to the **execution occurrence**: one request, one authority context, one fresh isolated Execution.
It borrows the per-invocation execution model popularized by serverless, and uses it as a security primitive rather than only as a scaling abstraction.

> **Do not ask untrusted code to carry the security context correctly. Make the execution boundary carry it.**

## Authority becomes physical

<p align="center">
  <img src="https://raw.githubusercontent.com/permguard/soglia/main/assets/readme/flow.png" alt="The path of a call in the target security model. The Caller sends a request; Ingress swaps real authority for virtual; a fresh Execution runs the AI agent or workload, untrusted code in any framework, with virtual authority only and HTTP and gRPC only through Egress; Egress swaps virtual authority back for real, toward a PIC continuation for PIC-aware destinations or the Credential Anchor for legacy ones. The Execution Context, with Permguard, runs PIC validation, policy evaluation and IFC labels on the way in and out. The response is held until the Execution is destroyed. PIC controls authority flow, IFC controls information flow, Soglia controls execution and effects." width="820">
</p>

Inside the Execution there are no real backend credentials.
The agent holds only virtual authority bound to that Execution: copied, stolen or replayed anywhere else, it is worthless.
Every security decision lives in the **Execution Context**, with Permguard: PIC validation and exchange, policy evaluation and IFC labels, on the way in and on the way out.
Ingress and Egress only carry the traffic: they swap real authority for virtual on the way in, and back on the way out.

If the agent wants to affect the outside world, the effect must cross a Soglia boundary.
For a PIC-aware destination, authority continues as PIC, and can only narrow.
For a legacy destination, the real credential is materialized **outside the Execution**, at the Credential Anchor; the agent never receives it.

When the invocation ends, the Execution is destroyed, before the caller reads the response.
There is no long-lived application process in which request B can accidentally reuse request A's authority.

| Layer      | Controls                  |
| ---------- | ------------------------- |
| **PIC**    | authority flow            |
| **IFC**    | information flow          |
| **Soglia** | execution and effect flow |

Permguard proves why authority may continue.
Soglia makes that authority enforceable at the exact boundary where **intent becomes effect**.

## Bring your own agent

Soglia is not another agent framework.
The framework owns the agent's internals; Soglia owns the execution around it.
LangChain, Google ADK, Microsoft Agent Framework, Strands or your own code: the agent runs as it is.

| Step | What you do                         | What Soglia does                                                                  |
| ---- | ----------------------------------- | --------------------------------------------------------------------------------- |
| 01   | Package the agent as you already do | Nothing inside it changes.                                                        |
| 02   | Declare its security context        | Turns the declaration into boundaries the kernel enforces, for every single call. |
| 03   | Call it                             | Gives every call its own fresh Execution, destroyed before you read the response. |

## Two layers

<p align="center">
  <img src="https://raw.githubusercontent.com/permguard/soglia/main/assets/readme/stack.png" alt="Three layers. Permguard decides and verifies authority, with the Control Plane, the Data Plane and the Trust Plane, in development. Soglia confines each Execution, with the Proxy, the Supervisor, sandboxd and the Enforcer. The Linux kernel enforces it physically, with namespaces, cgroup v2, nftables and eBPF." width="820">
</p>

Soglia works beside Permguard, and the two stay separate.

| Layer     | What it is                                                                   |
| --------- | ---------------------------------------------------------------------------- |
| Permguard | Control Plane, Data Plane and Trust Plane: PIC, trust, policy and authority  |
| Soglia    | The agent execution runtime: isolation, mediation, lifecycle and enforcement |

Permguard decides and verifies authority.
Soglia creates and confines the concrete Execution that must obey it.
Soglia is the implementation of the **Agentic Execution Fabric** architecture.

| Component      | Crate               | Role                                                                                                                                     |
| -------------- | ------------------- | ---------------------------------------------------------------------------------------------------------------------------------------- |
| **Proxy**      | `soglia-proxy`      | The only way into an Execution and the only way out; Ingress releases the response only after the Execution is destroyed.                |
| **Supervisor** | `soglia-supervisor` | The unprivileged coordinator: admits invocations and allocates each Execution's identity, address and concurrency slot.                  |
| **sandboxd**   | `soglia-sandbox`    | The isolation boundary: a privileged helper that creates each Execution's cgroup and OCI bundle, starts it with `runc`, and destroys it. |
| **Enforcer**   | `soglia-enforcer`   | The network confinement: a privileged helper that owns each Execution's network namespace, routes and rules, and its anti-spoofing.      |
| core           | `soglia-core`       | The portable logic and contracts the others share.                                                                                       |

## How an invocation runs

One request creates one fresh, isolated Execution.

```text
Caller
 -> ingress proxy
 -> Supervisor
 -> fresh sandbox (namespaces, cgroup, read-only rootfs)
 -> agent
 -> egress proxy -> allowed destination
 -> response buffered
 -> Execution destroyed
 -> response to Caller
```

The agent can reach the network only through the Soglia egress proxy.
When the Caller receives a successful response, the Execution that produced it is already gone.

## Status

Soglia is under development.
The first version, Phase 0, proves the execution loop and the mediated network path end to end.
It is not a production security release.

| Today, in Phase 0                                    | Later phases                                       |
| ---------------------------------------------------- | -------------------------------------------------- |
| one fresh, isolated Execution per invocation         | PIC and virtual authority                          |
| namespaces, cgroup v2 and a read-only rootfs         | Permguard integration and information-flow control |
| egress only through the Soglia proxy                 | the Credential Anchor                              |
| response held until the Execution is destroyed       | TLS interception and L7 TLS identity enforcement   |
| network confinement with `cgroup-bpf` or `netns-nft` | gRPC and Connectors                                |

The interfaces of the later phases exist, and fail explicitly if they are called.

Phase-0 `CONNECT` mediation authorizes the tunnel endpoint but does not provide L7 TLS identity enforcement.
Shared-IP/SNI-mismatch or domain-fronting-style behavior remains outside the Phase-0 security claim and is addressed by a later TLS mediation phase.

## Requirements

Soglia runs only on Linux, and the `soglia` binary builds only for Linux.
Only the portable crates, `soglia-core` and `soglia-proxy`, also build on macOS: they are plain logic, with no kernel dependency.
Every other crate stops with an explicit error when built for another system.

| Requirement                  | Why                                                  |
| ---------------------------- | ---------------------------------------------------- |
| Rust 1.97+                   | Build Soglia                                         |
| cgroup v2, delegated subtree | Per-Execution resource limits and teardown           |
| `nft` (nftables)             | Network policy for each Execution                    |
| `ip` (iproute2)              | Network namespaces, veth pairs, addresses and routes |
| `runc`                       | Start each Execution from an OCI bundle              |
| Task or Make                 | Run the project workflows                            |

On macOS or Windows, build and test the rest inside the Linux development container described below.

## Running

`soglia run` starts as root, starts its two privileged helpers, and then drops to the unprivileged user the configuration names.

```sh
soglia run -f examples/soglia.yaml
curl -X POST --data 'echo hello' http://127.0.0.1:8088/v1/execute/echo
```

The default network backend is `cgroup-bpf`.
It requires the qualified Linux cgroup v2, systemd delegation, bpffs and BPF capabilities, and fails startup closed when they are absent.
There is no automatic downgrade.
A compatibility deployment must set `network.backend: netns-nft` explicitly.

Run it inside a cgroup subtree delegated to it.
[dev/systemd/soglia.service](dev/systemd/soglia.service) shows the unit, with `Delegate=yes`.

### Uninstalling

Stop the Soglia runtime before uninstalling it, and verify that the unit is no longer running.
Use the dry run first to validate ownership and inspect the exact removal plan without changing the host:

```sh
soglia uninstall --dry-run -f /etc/soglia/soglia.yaml
soglia uninstall -f /etc/soglia/soglia.yaml
```

Verified uninstall removes only resources whose durable records and current kernel identities prove that Soglia owns them.
It has no `--force` option and preserves any state whose ownership cannot be proved.
If the command is interrupted after recording its intent, run the same command again to resume the exact recorded plan.

| Exit status | Meaning                   | Operator action                   |
| ----------- | ------------------------- | --------------------------------- |
| `0`         | Complete or already clean | No further cleanup                |
| `20`        | Incompatible state        | Use a matching version/migration  |
| `21`        | Unproved ownership        | Inspect and preserve the state    |
| `22`        | Unsupported capability    | Restore the capability and retry  |
| `23`        | Runtime active/host error | Stop or repair the host and retry |
| `24`        | Incompatible BPF topology | Resolve the conflict and retry    |

Status `20` requires the matching Soglia version or a qualified migration; do not delete the recorded state manually.
Status `21` means recorded and kernel identities do not prove ownership, so inspect the reported trusted path and preserve its objects.
Status `22` means the host lacks a required kernel or environment capability.
The most common status `23` refusal is an active Soglia runtime: stop the service and retry; if it is already stopped, correct the reported host, I/O or service failure.
Status `24` reports the conflicting cgroup-BPF hook and errno; resolve that topology conflict before retrying without deleting pins manually.

On systemd 255, a stopped unit can occasionally leave an empty `runtime` cgroup after systemd ignores an `EBUSY` pruning race.
The empty leaf contains no process and is harmless: the next trusted startup reuses it, and verified uninstall removes it by exact path.

## Development

The repository exposes the same workflows through `Taskfile.yml` and `Makefile`.
All of them run on Linux, and inside the development container:

```sh
task check             # lint, headers, Phase-0 dependency check, supply chain, unit tests
task test:acceptance   # privileged T1-T10/H1-H4 with default cgroup-bpf and explicit netns-nft
```

On macOS there are two ways to work.

| Where                              | What runs                                                                |
| ---------------------------------- | ------------------------------------------------------------------------ |
| Natively                           | `task test:portable`: lint and tests of `soglia-core` and `soglia-proxy` |
| In [.devcontainer/](.devcontainer) | Everything, with the editor and rust-analyzer running inside Linux       |

The devcontainer is built from [dev/linux/Dockerfile](dev/linux/Dockerfile), the same image `dev/linux/run.sh` and the CI use.
Outside an editor, `dev/linux/run.sh make check` runs the full gate in that image.

`task test:acceptance` runs the privileged suite in place inside the devcontainer, and in a fresh privileged container anywhere else, a Linux host included, because the suite creates network namespaces, links and nftables tables.
That container has its own cgroup namespace, where [dev/linux/cgroup-init.sh](dev/linux/cgroup-init.sh) delegates a subtree to Soglia the way a systemd unit would.

## Part of Permguard

Soglia is the execution side of the [Permguard](https://github.com/permguard) Agentic Fabric.
[Permguard](https://github.com/permguard/permguard) decides and verifies authority; the [PIC protocol](https://www.pic-protocol.org) carries it from one execution to the next; Soglia confines the code that exercises it.

## License

Apache-2.0.
See [LICENSE](LICENSE).
