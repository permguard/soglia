<!-- Copyright (c) 2022 Nitro Agility S.r.l. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Soglia

[![licence](https://img.shields.io/badge/licence-Apache--2.0-blue)](LICENSE)

<p align="center">
  <img src="assets/soglia-banner.png" alt="Soglia Runtime" width="820">
</p>

**Trusted execution for AI agents and mission-critical workloads under authority that never expands.**

*Soglia* is Italian for **threshold**: the boundary something must cross before it can have an effect on the outside world.

For an autonomous agent, Soglia is that boundary.

## The missing security boundary

Modern authorization can decide **who may do what**.

PIC goes further: it proves **which causal execution the authority belongs to** and whether that authority may continue to the next step.

But there is still one boundary left:

**the code that actually exercises that authority.**

Traditional workers and API servers execute many requests inside the same long-lived process. Credentials, globals, caches, connections and mutable state become ambient authority.

```text
request A --\
            +--> same long-lived process
request B --/        |
                     +-- global state
                     +-- credentials
                     +-- connections
                     `-- mutable context
```

At that point, security depends on every function always receiving, preserving and using the correct context.

That is too weak for untrusted or probabilistic AI code.

Soglia changes the unit of security from the **service** to the **execution occurrence**.

```text
one request
    =
one authority context
    =
one fresh isolated Execution
```

## Authority becomes physical

```text
                    PERMGUARD
              Authority Continuity
                     / PIC
                       |
                       v
Caller --------> HTTP / gRPC ingress
                       |
                       v
                Execution Context
                       |
                       v
        +================================+
        |             SOGLIA             |
        |                                |
        |      fresh Execution E123      |
        |                                |
        |   authority + input + labels   |
        |              |                 |
        |              v                 |
        |          AI Agent              |
        |       untrusted code           |
        |              |                 |
        |        HTTP / gRPC only        |
        +--------------+-----------------+
                       |
                       v
                Soglia Egress
                       |
              +--------+--------+
              |                 |
              v                 v

      PIC-aware boundary     Legacy boundary

      PIC continuation       Credential Anchor
              |                 |
              v                 | materialize
       Connector / next         | real credential
       Soglia Execution         v
              |          External service
              v
         Backend effect


        response + IFC labels
                 |
                 v
        Execution destroyed
                 |
                 v
              Caller
```

**PIC controls authority flow.**
**IFC controls information flow.**
**Soglia controls execution and effect flow.**

Inside the Execution there are no real backend credentials. The agent receives only authority material bound to that Execution.

If the agent wants to affect the outside world, the effect must cross a Soglia boundary.

For a PIC-aware destination, authority continues as PIC.

For a legacy destination, the real credential is materialized **outside the Execution**, at the trusted mediation boundary.

The agent never receives it.

When the invocation ends, the Execution is destroyed.

```text
request A -> Execution E123 -> authority A -> destroy
request B -> Execution E124 -> authority B -> destroy
```

There is no long-lived application process in which request B can accidentally reuse request A's authority.

This is the key idea behind Soglia:

> **Do not ask untrusted code to carry the security context correctly. Make the execution boundary carry it.**

Soglia borrows the **per-invocation execution model popularized by serverless**, but uses it as a security primitive rather than only as a scaling abstraction.

A traditional server keeps a process alive and feeds many requests through it.

Soglia instead treats each invocation as a temporary security domain:

```text
traditional server

request A --\
request B ----> long-lived process ----> shared authority/state
request C --/


Soglia

request A ----> fresh Execution A ----> destroy
request B ----> fresh Execution B ----> destroy
request C ----> fresh Execution C ----> destroy
```

The process is no longer the security unit. **The invocation is.**

Permguard proves why authority may continue.

Soglia makes that authority enforceable at the exact boundary where **intent becomes effect**.

> **Target security model:** the sections above describe the intended end-state architecture. The implementation status and currently active features are listed below.

Soglia is the runtime where AI agents run and act on the outside world under Permguard's control.
Agents think and propose.
Soglia decides what may execute, isolates the code that executes it, and lets its effects leave only through mediated boundaries.

## Two layers

Soglia works beside Permguard, and the two stay separate.

| Layer | What it is |
| --- | --- |
| Permguard | Control Plane, Data Plane and Trust Plane: PIC, trust, policy and authority |
| Soglia | The agent execution runtime: isolation, mediation, lifecycle and enforcement |

Permguard decides and verifies authority.
Soglia creates and confines the concrete Execution that must obey it.
Soglia is the implementation of the Agentic Execution Fabric architecture.

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

Phase 0 deliberately leaves out PIC, virtual authority, Permguard integration, information-flow control, the Credential Anchor, TLS interception, gRPC, Connectors and eBPF.
Their interfaces exist, and fail explicitly if they are called.

Phase-0 `CONNECT` mediation authorizes the tunnel endpoint but does not provide L7 TLS identity enforcement.
Shared-IP/SNI-mismatch or domain-fronting-style behavior remains outside the Phase-0 security claim and is addressed by a later TLS mediation phase.

## Requirements

Soglia runs only on Linux, and the `soglia` binary builds only for Linux.
Only the portable crates, `soglia-core` and `soglia-proxy`, also build on macOS: they are plain logic, with no kernel dependency.
Every other crate stops with an explicit error when built for another system.

| Requirement | Why |
| --- | --- |
| Rust 1.97+ | Build Soglia |
| cgroup v2, delegated subtree | Per-Execution resource limits and teardown |
| `nft` (nftables) | Network policy for each Execution |
| `ip` (iproute2) | Network namespaces, veth pairs, addresses and routes |
| `runc` | Start each Execution from an OCI bundle |
| Task or Make | Run the project workflows |

On macOS or Windows, build and test the rest inside the Linux development container described below.

## Running

`soglia run` starts as root, starts its two privileged helpers, and then drops to the unprivileged user the configuration names.

```sh
soglia run -f examples/soglia.yaml
curl -X POST --data 'echo hello' http://127.0.0.1:8088/v1/execute/echo
```

Run it inside a cgroup subtree delegated to it.
[dev/systemd/soglia.service](dev/systemd/soglia.service) shows the unit, with `Delegate=yes`.

## Development

The repository exposes the same workflows through `Taskfile.yml` and `Makefile`.
All of them run on Linux, and inside the development container:

```sh
task check             # lint, headers, Phase-0 dependency check, supply chain, unit tests
task test:acceptance   # the privileged suite: T1-T10, H1-H4, and the backends on a real kernel
```

On macOS there are two ways to work.

| Where | What runs |
| --- | --- |
| Natively | `task test:portable`: lint and tests of `soglia-core` and `soglia-proxy` |
| In [.devcontainer/](.devcontainer) | Everything, with the editor and rust-analyzer running inside Linux |

The devcontainer is built from [dev/linux/Dockerfile](dev/linux/Dockerfile), the same image `dev/linux/run.sh` and the CI use.
Outside an editor, `dev/linux/run.sh make check` runs the full gate in that image.

`task test:acceptance` runs the privileged suite in place inside the devcontainer, and in a fresh privileged container anywhere else, a Linux host included, because the suite creates network namespaces, links and nftables tables.
That container has its own cgroup namespace, where [dev/linux/cgroup-init.sh](dev/linux/cgroup-init.sh) delegates a subtree to Soglia the way a systemd unit would.

## License

Apache-2.0.
See [LICENSE](LICENSE).
