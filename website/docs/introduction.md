---
title: Introduction
description: What Soglia is, what runs today, and where to start.
---

<!-- Copyright (c) 2022 Nitro Agility S.r.l. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Introduction

Soglia is the runtime where AI agents and mission-critical workloads run and act on the outside world under Permguard's control.
Agents think and propose.
Soglia decides what may execute, isolates the code that executes it, and lets its effects leave only through mediated boundaries.

One request creates one fresh, isolated Execution:

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

::: warning Phase 0
Soglia is under development.
The first version, Phase 0, proves the execution loop and the mediated network path end to end.
It is not a production security release.

Phase 0 deliberately leaves out PIC, virtual authority, Permguard integration, information-flow control, the Credential Anchor, TLS interception, gRPC, Connectors and eBPF.
Their interfaces exist, and fail explicitly if they are called.
:::

## Where to start

- [Run Soglia](./running): the requirements, a build, a first configuration and a first call.
- [How it works](../how-it-works): the model behind Soglia, from the Execution Context to the kernel-enforced sandbox.
