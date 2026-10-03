<!-- Copyright (c) 2022 Nitro Agility S.r.l. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Parallel Candidate-A Resolve design

## Status and scope

Status: `QUALIFIED` on production baseline `cfb2d375e76de59694e25374ec5df47c2bfb6c6a`, aggregate run `qualification-20261002T152506Z-81876`.

This is the SOG-2.02 design for deferred Resolve option B.
It replaces the one-exchange-at-a-time Candidate-A channel with a bounded, request-ID-correlated pipeline and a fixed stateless Enforcer worker pool.
It also closes the Phase 2 R3-R5 gaps for accepted ingress connections, proxy connections, pending Resolve work and attribution registries.

SOG-2.03 is authorized to implement this contract.

## Baseline and unchanged security properties

The qualified baseline is production commit `7dd0840e4d51078c01ab26343c9eebfd315e5e5e` with harness commit `22cfba0c93e78621c6abe6849fa0d046fbd285f6`.
The current channel already carries a monotonic `request_id`, but an async mutex permits only one write/read exchange at a time and the Enforcer has one Resolve loop using `try_lock` on the lifecycle backend.

Option B changes concurrency, not attribution semantics.
The complete `BindingKey`, publication deadline, typed outcomes, S8 Enforcer-loss transition, freeze behavior, no-fallback rule and Candidate-A map ownership remain unchanged.
No application byte is read and no DNS lookup or outbound connection is attempted until one Resolve returns a trusted current `BindingKey` and the proxy validates its destination policy.

## Resolver protocol version 2

### Framing and negotiation

Resolver protocol version 2 keeps the existing authenticated Unix socketpair and the existing frame envelope: a four-byte big-endian length followed by strict JSON.
Resolver messages get a dedicated 4 KiB frame limit even though generic helper IPC remains capped at 1 MiB.
Every resolver type uses `deny_unknown_fields`, fixed-width integer fields and explicit enum tags.

Before the Enforcer reports global `READY`, the Supervisor and Enforcer exchange:

```text
ResolverHelloV2 {
  protocol_version: 2,
  max_pending_resolves: u32,
  resolve_workers: u16
}

ResolverReadyV2 {
  protocol_version: 2,
  max_pending_resolves: u32,
  resolve_workers: u16
}
```

The values must match the independently parsed configuration on both sides.
An absent handshake, unknown version, mismatched limit or malformed frame is `Incompatible`, prevents `READY` and never falls back to protocol version 1.
The BPF object ABI is independent and does not change merely because the resolver protocol changes.

After the handshake, the request and response bodies are:

```text
ResolveV2 {
  request_id: u64,
  tuple: SocketTupleV4
}

ResolveReplyV2 {
  request_id: u64,
  attempt: Pending(TupleAbsent | BackendBusy)
         | Complete(ResolveResult)
         | QueueFull
}
```

`QueueFull` is terminal, typed and health-neutral.
It is returned locally when Supervisor admission is full and may also be returned by the Enforcer if its independently bounded request queue is full.

### Request identifiers and correlation

Request IDs start at one, increase monotonically across the lifetime of one resolver channel and are never reused.
Exhaustion of the `u64` space poisons the channel rather than wrapping.
The Supervisor inserts an ID into its bounded in-flight table before the writer may emit its frame.
The reader removes exactly that entry when it dispatches the matching reply.

Replies may arrive in any order.
A reply with ID zero, an unknown ID, a duplicate ID or an ID whose entry was already completed is a protocol-integrity failure: the channel is poisoned, S8 begins and the reply is never consumed by another connection.

The Enforcer maintains a monotonic received-ID high-water mark plus a bounded in-flight set.
A duplicate, zero or non-increasing request ID is a protocol-integrity failure and closes the resolver channel.

If a caller is cancelled before its request is written, the writer drops the unsent entry without sending a frame.
If cancellation happens after any request byte is written, the entry becomes `ABANDONED` but remains owned by the resolver until its reply arrives or the watchdog poisons the channel.
The reader validates and discards a valid abandoned reply; it never gives that reply to another caller.
No unbounded tombstone collection is needed because every written request remains in the same capacity-limited in-flight table.

A response that arrives after the publication deadline is not automatically a protocol failure.
As in the qualified one-shot design, a late `Pending` becomes `Timeout` without a health transition, while a late `Complete` is consumed because the tuple has already been removed.
A response after the independent exchange watchdog is invalid because that watchdog has already poisoned and closed the channel.

## Supervisor pipeline

The Supervisor owns four bounded components:

1. a fair semaphore for logical Resolve admission;
2. an in-flight table keyed by `request_id`;
3. a single writer task fed by a bounded MPSC queue;
4. a single reader task that continuously validates and dispatches replies.

The semaphore permit is held from the start of a logical Resolve until its terminal outcome, including retries for tuple publication.
Each non-blocking retry receives a new request ID, while the logical Resolve retains one publication deadline and one admission permit.
The publication deadline begins before admission and therefore includes semaphore, writer-queue and retry delay.

If the admission semaphore is full, the connection gets immediate `QueueFull` and no frame is sent.
If an admitted request expires while still wholly queued, it is removed and becomes `Timeout`.
Once the writer begins a frame it must finish within the one-second exchange watchdog; partial write, read failure or watchdog expiry poisons the channel.
The writer and reader own the stream halves until shutdown, so cancellation of a caller cannot interleave frames or leave an unowned read.

The current two-millisecond publication retry interval and two-second maximum publication deadline remain unchanged initially.
The one-second exchange watchdog remains independent of the publication deadline.
No in-process channel reconstruction is permitted after poisoning; recovery is the qualified S8 restart path.

## Stateless Enforcer worker pool

The Enforcer starts a fixed worker pool before global `READY`.
One reader validates frames and IDs and submits jobs to a bounded queue.
One writer serializes replies from a bounded result queue.
Workers may finish out of order and carry no per-Execution or per-request state between jobs.

Actual parallel lookup requires separating the Resolve data plane from the lifecycle mutex.
Workers share a `ResolveView` containing duplicated owned BPF map descriptors and an immutable ownership/policy snapshot behind a reader-writer synchronization boundary.
Resolve workers take shared access; lifecycle prepare, activate, freeze, destroy, sweep and generation changes take exclusive access and publish a complete new snapshot only after their kernel and durable-state transition is valid.
The whole `BindingKey` is still compared at every boundary before authorization.

The pool does not spawn replacement workers in process.
A worker panic is caught at the job boundary, produces `IntegrityFailure` for the affected request when possible, marks the pool unhealthy, closes the resolver channel and triggers S8.
A worker that exceeds the Supervisor watchdog causes the same channel-poison and S8 transition; it is not detached and replaced while it may still access maps.
A map decode error, poisoned ownership snapshot or impossible lifecycle state is likewise `IntegrityFailure`, not `NotFound` or `QueueFull`.

The lifecycle helper channel remains distinct from the resolver pipeline.
Lifecycle operations may temporarily cause `Pending(BackendBusy)`, but cannot be starved by Resolve traffic; an exclusive lifecycle waiter prevents new readers from overtaking it.

## Declared bounds and configuration

The following values are the recommended initial contract and require approval:

| Setting                           | Default | Valid range | Saturation result               |
| --------------------------------- | ------: | ----------: | ------------------------------- |
| `runtime.max_ingress_connections` |      32 |      1-1024 | HTTP refusal/close              |
| `network.max_proxy_connections`   |     512 |      1-4096 | TCP close before read           |
| `cgroup_bpf.max_pending_resolves` |      64 |      1-4096 | `QueueFull`                     |
| `cgroup_bpf.resolve_workers`      |       4 |        1-64 | bounded queue, then `QueueFull` |

`max_pending_resolves` is independent of `runtime.max_concurrency` because one active Execution may open more than one connection and lifecycle concurrency is not a proxy-connection budget.
Configuration validation requires `resolve_workers <= max_pending_resolves <= network.max_proxy_connections <= cgroup_bpf.max_tracked_sockets`.
It also requires `runtime.max_ingress_connections >= runtime.max_concurrency + runtime.max_queue`, with checked arithmetic.
The Enforcer request queue, result queue and in-flight set each have capacity `max_pending_resolves` and allocate that capacity before `READY`.

The ingress limit is acquired immediately after accept and before spawning a connection task.
The proxy limit is acquired immediately after accept and before attribution or reading application bytes.
Refusal at either boundary is counted, bounded and produces no DNS or outbound effect.

The IP and Candidate-A attribution tables get a local hard ceiling equal to `runtime.max_concurrency + runtime.cleanup_failure_threshold`.
Insertion above that ceiling is an integrity failure because Supervisor admission should already have prevented it; the runtime stops admitting work and follows the fail-closed health path.
The cgroup-BPF live registry gets the same explicit execution capacity plus the qualified cleanup-failure allowance.

Every bounded channel and table uses checked arithmetic at configuration time.
The configuration parser rejects zero, inconsistent values, values over the fixed maxima and a total preallocation budget that overflows `usize`.

## Failure semantics

| Condition                           | Connection result  | Runtime health |
| ----------------------------------- | ------------------ | -------------- |
| Local admission full                | `QueueFull`        | unchanged      |
| Enforcer request queue full         | `QueueFull`        | unchanged      |
| Tuple absent until deadline         | `Timeout`          | unchanged      |
| Lifecycle busy until deadline       | `Timeout`          | unchanged      |
| Valid complete reply after deadline | complete result    | unchanged      |
| Malformed, duplicate or unknown ID  | `Unavailable`      | S8 fail-closed |
| Read/write/watchdog failure         | `Unavailable`      | S8 fail-closed |
| Worker panic or corrupt owned state | `IntegrityFailure` | fail-closed    |
| Enforcer process loss               | `Unavailable`      | S8 fail-closed |

Protocol poisoning is permanent for the process lifetime.
It closes both stream directions exactly once, rejects every pending and future Resolve, stops admission, marks readiness false and invokes the existing Enforcer-loss transition.
Diagnostic text is never used to select one of these outcomes.

## R3-R5 closure

R3 is closed for Phase 2 only when all accepted ingress tasks, proxy tasks, logical Resolve operations, frames, worker jobs, responses and attribution entries have the declared local hard bounds above.
No task may be spawned before its owning permit is acquired, and the task owns the permit until its socket and state are closed.

R4 host memory and disk reservation remains a Phase 3 obligation.
Phase 2 nevertheless records the deterministic memory reserved by the pipeline and refuses startup when its checked preallocation cannot be represented or allocated.

R5 is closed for these queues when saturation returns the typed bounded result without OOM, unbounded waiting, DNS, outbound traffic or application reads.
The publication and exchange deadlines remain separate so ordinary tuple absence cannot become a runtime-wide health failure.

## Observability and health

The Supervisor emits one bounded `cgroup_bpf.resolve_pipeline_health` snapshot per health interval with:

- configured capacity, current occupancy and high-water for ingress, proxy and logical Resolve admission;
- writer-queue and in-flight occupancy/high-water;
- admitted, locally refused, Enforcer-refused, timed-out, cancelled and abandoned counts;
- resolved outcomes, retries and delayed hits;
- p50, p95, p99 and maximum end-to-end Resolve latency plus `interval_ms`;
- channel poison count and typed poison reason.

The Enforcer snapshot records worker count, busy-worker high-water, request/result queue occupancy, attempts by outcome, out-of-order replies, backend-busy replies, worker panics, watchdog-triggered shutdown and protocol errors.
Metrics use fixed labels only and never expose raw cookie, tuple, `BindingKey`, `ExecutionId` or request ID as a metric label.
Per-request IDs may appear only in trusted rate-limited diagnostic logs.

An observability decode or integrity error remains fail-closed under the qualified health contract.
Counter saturation is explicit and uses saturating counters plus a structured saturation event.

## Qualification plan

Any implementation changes the production baseline and requires a complete authoritative B1-B7 plus uninstall replay before release.
B1 must prove protocol-version negotiation happens before `READY` and that mismatched version/limits refuse startup without durable mutation.
B2 must repeat every typed attribution outcome with out-of-order successful replies, cancellation and late `Pending`/`Complete` cases.
B3 must race parallel Resolve against activate, freeze, destroy and generation changes while preserving whole-`BindingKey` atomicity.
B4 must prove exact local and Enforcer `max_pending_resolves` saturation, worker-queue saturation, recovery after capacity release and zero stale entries.
B5 must re-prove no reads, DNS or outbound effects before a successful Resolve and for every new refusal boundary.
B6 must inject reader, writer, worker, watchdog and Enforcer loss and prove the S8 transition, durable recovery and `READY`-last ordering.
B7 must include the new connection/task/table bounds in its resource envelope and prove return to baseline.
Uninstall remains in the aggregate qualification because the production baseline and helper protocol changed.

### New B8 parallel-load gate

B8 enters `spike:qualify` between B7 and uninstall.
It uses production binaries and the production BPF object on a fresh VM and records the same fingerprints, cleanup and pre-teardown residue evidence as the existing gates.

The recommended initial supported profile is 64 concurrent pending Resolves, four workers and 500 successful present-tuple Resolves per second for 60 seconds.
It records p50, p95, p99 and maximum latency without hiding retries; the proposed PASS threshold is p99 at or below 20 ms for already-published tuples, zero wrong correlations, zero negative outcomes within the admitted profile and at least 95% of the target rate.
After load stops, every pipeline queue, task, FD, attribution entry and BPF tuple/cookie entry must return to its recorded baseline within 60 seconds.

An out-of-envelope burst must produce only the exact number of typed `QueueFull` refusals beyond capacity, with zero application reads, DNS or outbound attempts for refused connections, followed by an immediate successful control Resolve.
Fault injection covers duplicate and unknown IDs, out-of-order replies, caller cancellation before and after write, partial frames, wrong protocol version, stalled writer, stalled worker, worker panic, malformed result, lifecycle write contention and helper exit.

The gate also runs a mixed workload of ingress calls, multiple outbound connections per Execution and lifecycle churn.
It asserts that ingress, proxy and Resolve high-water marks never exceed their configured limits and that the attribution maps never exceed `runtime.max_concurrency + runtime.cleanup_failure_threshold`.

After the supported-profile PASS workload, B8 performs a step ramp until either p99 exceeds 20 ms or a typed `QueueFull` first appears.
The maximum sustained throughput before that boundary is recorded as characterization for capacity planning and is not an additional PASS criterion.

## Alternatives rejected

- **Keep the single exchange gate:** rejected because unrelated connections serialize behind tuple-absent retries and cannot meet the Phase 2 concurrency objective.
- **One socketpair per Resolve:** rejected because it adds unbounded descriptors and trusted channel setup to the hot path.
- **Multiple independent resolver channels:** rejected because correlation, health and shutdown become sharded and capacity is harder to prove globally.
- **Unbounded Tokio tasks or Enforcer threads:** rejected because they violate R3 and turn refusal load into memory or scheduler pressure.
- **Reuse `max_concurrency` as Resolve depth:** rejected because Execution lifecycle capacity and live connection capacity are different resources.
- **Replace a stuck or panicked worker in process:** rejected because the old worker may still hold or mutate trusted map state.
- **Share the lifecycle mutex across all workers:** rejected because it preserves serialization and allows Resolve pressure to interfere with lifecycle progress.
- **Treat unknown or late response IDs as harmless:** rejected because a response could be delivered to the wrong connection after cancellation or timeout.
- **Automatic downgrade to the version-1 channel or `netns-nft`:** rejected because it would silently weaken a selected and qualified security contract.

## Approved decisions

1. Resolver protocol version 2 uses a strict pre-`READY` handshake and has no version-1 fallback.
2. The initial defaults and hard ranges are the values in [Declared bounds and configuration](#declared-bounds-and-configuration), including 512 proxy connections.
3. `ResolveView` uses shared reads and exclusive lifecycle publication instead of the current single backend mutex.
4. A worker panic or watchdog expiry permanently poisons the channel and is followed by S8, with no in-process worker replacement.
5. B8 enters `spike:qualify` with the 64-pending/four-worker/500-per-second supported profile, p99 target, 60-second baseline-return deadline and separate step-ramp characterization.
6. The first implementation keeps the two-second publication deadline, two-millisecond retry interval and one-second independent exchange watchdog.
7. Aggregate host memory and disk reservation remain Phase 3 work, while Phase 2 requires checked pipeline preallocation and typed startup refusal.
