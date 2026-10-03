<!-- Copyright (c) 2022 Nitro Agility S.r.l. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# User namespace and seccomp allow-list

## Status and scope

Status: `APPROVED`, revised after independent review.

This is the SOG-3.02 design.
It closes the user-namespace clause of I1 and the least-privilege seccomp clause of I5 for the `runc` profile.
The private Execution volume (SOG-3.03), I/O limits and aggregate reservation (SOG-3.04) are separate work items.

The qualified baseline today runs the agent as a configured non-root UID with empty capability sets, `noNewPrivileges`, a read-only root, fresh PID, IPC, UTS, mount and cgroup namespaces, a network namespace joined by path, and a default-allow seccomp profile with an explicit deny-list.
That baseline creates no user namespace, and the agent UID is a real host UID.

## Goals

1. An agent process never holds a host UID or GID outside a range reserved for its own Execution.
2. Two live Executions never share a host UID or GID.
3. Root inside the user namespace, if it ever appeared, would map to an unprivileged host UID and hold no capability over host objects.
4. Every syscall an agent can make is explicitly allowed by a versioned, architecture-specific profile.
5. The profile and the UID range are recorded in durable Execution state and in qualification evidence.
6. Teardown proves that no process, no namespace reference, no mount and no owned object remains under the Execution's range before the range is reused.

## User namespace

### Per-Execution ranges

Soglia reserves one dedicated ID block for Executions, declared in configuration.
Because runc runs as host root, the kernel never consults `/etc/subuid` or `/etc/subgid`; the block is therefore protected by explicit startup validation, not by those files.
Startup refuses with `Incompatible` when the block overlaps any of:

- every entry in `/etc/subuid` and `/etc/subgid`, including distribution defaults from 100000 and container managers such as LXD;
- the systemd dynamic-user range 61184–65519 and the systemd container range 524288–1879048191;
- every NSS account and group, including the Soglia runtime and Supervisor UID;
- IDs 65535 and 4294967295.

The block is divided into fixed-size ranges of 65,536 IDs, each mapped by a single extent.
Each live Execution leases exactly one range, so its in-namespace IDs 0 to 65,535 map to a contiguous host range used by no other Execution.
The range pool is bounded by `runtime.max_concurrency` plus the cleanup-failure allowance, exactly like the attribution tables.

The lease is part of the durable Execution record.
Recovery reconstructs leases from trusted records before admission and treats an untracked process, namespace or object inside the block as `Unknown`.

### Verified release

A range is released only when all of these hold:

- the Execution cgroup reports `populated 0` and has been removed, and the PID-namespace init has been reaped;
- no `/proc/*/task/*/status` shows an ID of the range in any of the four `Uid` fields, the four `Gid` fields or `Groups`;
- the Execution's user-namespace inode appears in no `/proc/*/task/*/ns/user` and in no nsfs mount in the host `mountinfo`;
- no Soglia host process holds a descriptor received from the agent;
- no file or directory owned by an ID of the range remains in the Execution's volume or bundle;
- the Execution's idmapped root mount has been unmounted and its absence verified.

A range whose release cannot be verified stays quarantined and counts against the cleanup-failure threshold.

### Mapping and identity

The OCI bundle declares `linux.uidMappings` and `linux.gidMappings` with one entry each: container ID 0, the leased host base, size 65,536.
The agent runs as its configured in-namespace UID and GID, with no supplementary groups.
Capability sets stay empty and `noNewPrivileges` stays set, so the namespace adds a boundary without granting anything.

`setgroups` is unavailable to the agent because it holds no `CAP_SETGID` and the seccomp profile refuses it with `EPERM` by name.
A root-invoked runc leaves `/proc/<pid>/setgroups` at `allow`; the design does not rely on it.

The default in-namespace agent UID and GID change from 65534.
65534 is the kernel overflow ID, so unmapped host objects would appear owned by the agent.
The new default is 10001, and 65534 is refused as an agent identity.

### Idmapped root filesystem

The OCI specification offers no idmap option for `root.path`; runc applies mount-level `uidMappings` only to bind entries in `mounts[]`.
The privileged Sandbox helper therefore builds the root mount on the host before invoking runc:

1. `open_tree(OPEN_TREE_CLONE)` on the trusted rootfs directory, from the image store or the configured rootfs path;
2. `mount_setattr` on the detached mount with `MOUNT_ATTR_IDMAP`, `MOUNT_ATTR_RDONLY`, `MOUNT_ATTR_NOSUID` and `MOUNT_ATTR_NODEV`, using a user-namespace descriptor that carries the leased map;
3. `move_mount` to a private-propagation directory owned by that Execution, which becomes `root.path`.

runc's recursive self-bind of the root preserves the idmap.
The host mount is recorded in the bundle's durable ownership state.
Teardown unmounts it by exact path, verifies it is absent from host `mountinfo` and verifies that it never propagated elsewhere.
A host or filesystem without idmapped-mount support refuses with a typed `Unsupported` refusal; there is no fallback to an unmapped Execution.
On kernel 6.8, ext4 and xfs support idmapped mounts since 5.12, btrfs since 5.15, overlayfs since 5.19 and tmpfs since 6.3.

### Namespace ordering

runc joins namespaces given by path before it unshares the new user namespace, while it still holds `CAP_SYS_ADMIN` in the initial user namespace.
The Execution therefore joins the Enforcer-created network namespace, which is owned by the initial user namespace, and then creates its own user namespace.
The agent never obtains a capability over that network namespace.

### `/sys` replacement

The kernel allows a `sysfs` mount only with `CAP_SYS_ADMIN` over the user namespace that owns the network namespace, so the Execution's user namespace cannot mount it.
`/sys` becomes a read-only, size-limited tmpfs containing only a read-only `cgroup2` mount at `/sys/fs/cgroup`.
`cgroup2` is mountable because runc creates the cgroup namespace after the user namespace, which then owns it.
The bundle lists `/sys` before `/sys/fs/cgroup`; runc mounts the tmpfs writable and remounts it read-only after the nested mountpoint exists.

runc may replace a failed `sysfs` or `cgroup2` mount with a bind of the host path.
The bundle therefore contains no `sysfs` entry, a unit test asserts that, and qualification asserts from `/proc/self/mountinfo` that `/sys` is `tmpfs` and `/sys/fs/cgroup` is `cgroup2`, read-only, with root `/`.
Any other observed shape fails the gate.

## Seccomp allow-list

### Shape

The profile declares `defaultAction: SCMP_ACT_ERRNO` with `defaultErrnoRet: 38` (`ENOSYS`) and an `ociVersion` that carries that field.
Every allowed syscall is listed explicitly per architecture, for `x86_64` and `aarch64`.
`ENOSYS` for unlisted syscalls lets C libraries and language runtimes fall back from newer interfaces, as they already do for `clone3`.

Foreign ABIs are refused: the profile declares only the native architecture, and the behavior of a foreign-ABI call (i386 `int 0x80`, the x32 bit `0x40000000`, AArch32 compat) is verified on runc 1.3.4 and recorded.
Where the kernel supports it, hosts boot with `ia32_emulation=false`.

The explicitly dangerous syscalls return `EPERM` and stay listed by name, so their refusal does not depend on the default action:
namespace and mount operations, `bpf`, `perf_event_open`, `ptrace`, `process_vm_*`, `pidfd_getfd`, `userfaultfd`, the key-management calls, `open_by_handle_at`, `name_to_handle_at`, module, `kexec`, `reboot`, swap, `acct`, `quotactl`, `setgroups` and io_uring.
io_uring stays refused also because `IORING_OP_SOCKET` would bypass the socket filter.

These are never allowed: `modify_ldt`, `iopl`, `ioperm`, `syslog`, `fanotify_init`, `mbind`, `migrate_pages`, `move_pages`, `set_mempolicy`, the clock and time setters, `uselib`, `vhangup`, `lookup_dcookie`, `nfsservctl` and `_sysctl`.

### Argument filtering

Every argument filter on a 32-bit value compares with `SCMP_CMP_MASKED_EQ` and mask `0xffffffff`, because seccomp compares all 64 bits of the register.
Filtering is by allow-matches, which fail closed, rather than by deny-matches.

- `clone` has one conditional allow: the masked value of all `CLONE_NEW*` flags must be zero. `clone3` keeps `ENOSYS`.
- `socket` and `socketpair` compare `type & 0xf` and allow only:
  - `AF_INET` and `AF_INET6` with `SOCK_STREAM` or `SOCK_DGRAM`;
  - `AF_UNIX` with `SOCK_STREAM`, `SOCK_DGRAM` or `SOCK_SEQPACKET`;
  - `AF_NETLINK` with `SOCK_RAW` or `SOCK_DGRAM` and protocol `0` (`NETLINK_ROUTE`), which glibc and Go use for address configuration.
- Every other family, including `AF_PACKET`, `AF_VSOCK`, `AF_ALG` and `AF_KEY`, returns `EAFNOSUPPORT`.
- `AF_VSOCK` is not scoped by the network namespace, so for it the family filter is the primary boundary.
- `personality` is allowed only for the exact values `0`, `0x8`, `0x20000`, `0x20008` and `0xffffffff`.
- `ioctl` refuses `TIOCSTI` and `TIOCLINUX` with masked comparison; hosts set `dev.tty.legacy_tiocsti=0`, verified by the capability probe.

### Baseline and versioning

The allow-list is built from the syscalls the qualification agents actually use, recorded with a diagnostic logging profile and reviewed by hand; it is not derived from today's default-allow profile.
It is a versioned artifact with a stable digest recorded in each durable Execution record and in qualification evidence.
An agent may declare a narrower per-agent profile that removes whole syscalls; it can never add a syscall or relax an argument rule.
Production never uses `SCMP_ACT_LOG`.

## Failure semantics

| Condition                                        | Refusal class    | Host mutation |
| ------------------------------------------------ | ---------------- | ------------- |
| ID block absent, overlapping or foreign          | `Incompatible`   | None          |
| Agent UID or GID 65534                           | `Incompatible`   | None          |
| Range pool exhausted                             | `Capacity`       | None          |
| Idmapped mounts unsupported                      | `Unsupported`    | None          |
| Seccomp architecture or profile unsupported      | `Unsupported`    | None          |
| `dev.tty.legacy_tiocsti` enabled                 | `Unsupported`    | None          |
| Untracked process or object inside the block     | `Unknown`        | Preserved     |
| Range release cannot be verified                 | quarantine       | Preserved     |

Range exhaustion during call admission is a typed per-call refusal, like `QueueFull`, not a process exit.

## Qualification

The isolation gate proves each property with a positive and a negative case, inside `spike:qualify`.

- `/proc/self/uid_map` and `gid_map` show exactly the leased range; the host sees the agent under that range.
- Two concurrent Executions have disjoint host ranges.
- Startup refuses an ID block overlapping subuid, systemd or NSS ranges.
- `/proc/self/mountinfo` shows `/sys` as `tmpfs` and `/sys/fs/cgroup` as read-only `cgroup2` with root `/`; no `sysfs` appears.
- The root is an idmapped, read-only mount; image files owned by host root appear as in-namespace root; the host mount is removed after teardown and never propagated.
- Nested `unshare(CLONE_NEWUSER)`, `clone` with each namespace flag, `mount`, `setns`, `ptrace`, `pidfd_getfd` and `setgroups` are refused.
- A syscall outside the allow-list returns `ENOSYS`; each explicitly dangerous syscall returns `EPERM`.
- `ioctl(TIOCSTI)` is refused, including with high bits set in the command argument.
- Socket families and types are tested with and without `SOCK_CLOEXEC` and `SOCK_NONBLOCK`; `AF_VSOCK`, `AF_ALG`, `AF_KEY` and `AF_PACKET` return `EAFNOSUPPORT`; a TCP connection through the proxy and a netlink route query still work.
- i386, x32 and AArch32 calls are refused as recorded for the pinned runc.
- Representative runtimes start and complete a call, with expected values written per runtime and version: a static Rust binary, Go 1.25 or later reading `cpu.max`, Python and Node.js.
- After teardown every release condition holds; the range is reused only after that proof; a failed proof quarantines the range.
- A crash between lease, root-mount creation, start and release is recovered from durable records without reusing a live range or leaking a host mount.
- The T1–T10/H1–H4 acceptance and B1–B8 stay green with the user namespace enabled.

## Approved decisions

1. **Range allocation:** one unique 65,536-ID range per live Execution, from a dedicated block validated against subuid, systemd and NSS ranges, released only after verified teardown.
2. **Range size:** 65,536 in a single extent.
3. **`/sys`:** a read-only tmpfs with only a read-only cgroup2 mount, replacing sysfs, with no runc fallback accepted.
4. **Seccomp default:** `ENOSYS` through `defaultErrnoRet` for unlisted syscalls and `EPERM` for the explicitly dangerous ones.
5. **Socket families:** `AF_INET`, `AF_INET6`, `AF_UNIX` and `NETLINK_ROUTE`, filtered on the masked type, all others `EAFNOSUPPORT`.
6. **Per-agent profiles:** may only remove whole syscalls.
7. **Kernel requirement:** probe-based; idmapped mounts and disabled legacy `TIOCSTI` are required.
8. **Feasibility spike first:** prove the host-built idmapped root, the netns join and the replacement `/sys` with the pinned runc before implementation.

## Decision added by review

9. **Default agent identity (approved 2026-10-02):** the default in-namespace UID and GID become 10001, and 65534 is refused because it is the kernel overflow ID.
