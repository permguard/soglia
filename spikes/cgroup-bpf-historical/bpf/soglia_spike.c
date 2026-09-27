// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

// The Phase-1 cgroup-BPF spike programs. EXPERIMENTAL: not production code.
//
// One object carries every hook the reviewed plan evaluates, and the evidence of all four
// attribution candidates at once, so every candidate is judged on the same connections:
//
//   A  connect4 records socket cookie -> cgroup id; sockops looks the cookie up again.
//   B  connect4 stores the cgroup id in the socket's own storage; sockops reads it back.
//   C  `exec_ident` is fixed per loaded instance (one instance per Execution); sockops copies it.
//   D  sockops reads the network namespace cookie of the socket.
//
// sockops publishes, for each established client connection, the final tuple -> the evidence of
// every candidate. The harness resolves the tuple the proxy accepted and decides.
//
// Test-only variants are compiled from this same source with SPIKE_* defines, by build.sh:
//
//   SPIKE_RELAX_INET6_STREAM  sock_create also admits AF_INET6 stream sockets (connect6 isolation)
//   SPIKE_RELAX_DGRAM         sock_create also admits UDP sockets (sendmsg4/6 isolation)
//   SPIKE_DELAY_PUBLISH       sockops publishes into `soglia_staging`; the harness promotes later
//   SPIKE_TUPLE_MAX=<n>       a small tuple map, for exhaustion
//   SPIKE_TRACE               connect4 appends the destination it saw to `soglia_trace`
//   SPIKE_DIAGNOSTIC          unconditional entry/milestone counters for the S1 diagnostic only
//   SPIKE_MAP_FAILURE_DIAGNOSTIC records raw update/allocation results for S12 only
//
// The production-shaped variant is built with none of them.

#include <linux/bpf.h>
#include <linux/in.h>
#include <sys/socket.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "Apache-2.0";

#ifndef SPIKE_TUPLE_MAX
#define SPIKE_TUPLE_MAX 4096
#endif

// Policy states. Zero is DENY on purpose: an absent or zeroed state denies.
#define STATE_FROZEN 0
#define STATE_ACTIVE 1

// Counters, indices of `soglia_counters`.
#define C_EVENTS_DROPPED 0
#define C_TUPLE_INSERT_FAILED 1
#define C_PUBLISHED 2
#define C_SOCK_CREATE_DENY 3
#define C_CONNECT4_DENY 4
#define C_CONNECT6_DENY 5
#define C_SENDMSG4_DENY 6
#define C_SENDMSG6_DENY 7
#define C_UNPUBLISHED 8
#define C_COUNT 9

// Event kinds and reasons.
#define EV_CONNECT_DENY 1
#define EV_MAP_FULL 2
#define EV_SOCK_CREATE_DENY 3
#define EV_SENDMSG_DENY 4
#define R_NOT_ACTIVE 1
#define R_NOT_TCP 2
#define R_NOT_PROXY 3
#define R_IPV6 4
#define R_FAMILY 5
#define R_UDP 6

// Loader-set constants.
const volatile __u32 proxy_ip4 = 0;  // network byte order
const volatile __u32 proxy_port = 0; // host byte order
// S4 negative-control target. It is consulted only by the SPIKE_ALLOW_DIRECT4 build.
const volatile __u32 direct_ip4 = 0;   // network byte order
const volatile __u32 direct_port = 0;  // host byte order
const volatile __u64 exec_ident = 0; // candidate C; 0 in the shared instance

struct policy_value {
    __u64 state;
    __u64 tag;
};

// Global policy, keyed by the Execution cgroup id.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u64);
    __type(value, struct policy_value);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} soglia_policy SEC(".maps");

// Per-instance policy (candidate C): one element, zero = FROZEN. Not pinned, so every loaded
// instance owns its own.
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} policy_local SEC(".maps");

struct tuple {
    __u32 saddr; // network byte order
    __u32 daddr; // network byte order
    __u32 sport; // host byte order
    __u32 dport; // host byte order
};

struct evidence {
    __u64 sock_cookie;
    __u64 a_cgid;
    __u64 b_cgid;
    __u64 c_ident;
    __u64 d_netns;
    __u64 ts_ns;
    __u64 sockops_current_cgid;
    __u64 raw_remote_port;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, SPIKE_TUPLE_MAX);
    __type(key, struct tuple);
    __type(value, struct evidence);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} soglia_tuples SEC(".maps");

#ifdef SPIKE_DELAY_PUBLISH
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, SPIKE_TUPLE_MAX);
    __type(key, struct tuple);
    __type(value, struct evidence);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} soglia_staging SEC(".maps");
#endif

// Candidate A: socket cookie -> cgroup id, from connect4 to the socket's close.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, SPIKE_TUPLE_MAX);
    __type(key, __u64);
    __type(value, __u64);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} soglia_cookie_a SEC(".maps");

// Candidate B: the cgroup id in the socket's own storage; freed with the socket.
struct {
    __uint(type, BPF_MAP_TYPE_SK_STORAGE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, int);
    __type(value, __u64);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} soglia_sk_b SEC(".maps");

struct event {
    __u32 kind;
    __u32 reason;
    __u64 cgid;
    __u64 cookie;
    __u32 family;
    __u32 type;
    __u32 daddr;
    __u32 dport;
    __u64 ts_ns;
};

// Bounded: a hostile agent that loops on denied operations fills this and then only the dropped
// counter moves.
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 64 * 1024);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} soglia_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, C_COUNT);
    __type(key, __u32);
    __type(value, __u64);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} soglia_counters SEC(".maps");

#ifdef SPIKE_MAP_FAILURE_DIAGNOSTIC
// S12 diagnostic only. These values observe the existing helper results without changing any
// policy, publication or failure branch.
#define M_COOKIE_ATTEMPTS 0
#define M_COOKIE_FAILURES 1
#define M_COOKIE_LAST_RET 2
#define M_SK_ATTEMPTS 3
#define M_SK_FAILURES 4
#define M_TUPLE_ATTEMPTS 5
#define M_TUPLE_FAILURES 6
#define M_TUPLE_LAST_RET 7
#define M_COUNT 8

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, M_COUNT);
    __type(key, __u32);
    __type(value, __s64);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} soglia_map_fail_diag SEC(".maps");

static __always_inline void map_diag_bump(__u32 index)
{
    __s64 *value = bpf_map_lookup_elem(&soglia_map_fail_diag, &index);
    if (value)
        __sync_fetch_and_add(value, 1);
}

static __always_inline void map_diag_set(__u32 index, long observed)
{
    __s64 *value = bpf_map_lookup_elem(&soglia_map_fail_diag, &index);
    if (value)
        *value = observed;
}
#else
static __always_inline void map_diag_bump(__u32 index)
{
    (void)index;
}

static __always_inline void map_diag_set(__u32 index, long observed)
{
    (void)index;
    (void)observed;
}
#endif

// Destination-port trace points for the narrow S1 diagnostic. All values are retained as u32 so
// the evidence shows every half-word and conversion without implicit truncation.
#define P_CONNECT_RAW 0
#define P_CONNECT_LOW16 1
#define P_CONNECT_NTOHS_LOW16 2
#define P_SOCKOPS_RAW 3
#define P_SOCKOPS_LOW16 4
#define P_SOCKOPS_HIGH16 5
#define P_SOCKOPS_NTOHL 6
#define P_SOCKOPS_OLD_EXTRACT 7
#define P_SOCKOPS_NTOHS_HIGH16 8
#define P_TUPLE_ASSIGNED 9
#define P_EXPECTED 10
#define P_TUPLE_BEFORE_INSERT 11
#define P_COUNT 12

#ifdef SPIKE_DIAGNOSTIC
// S1 diagnostic only. These are entry/milestone observations, not production telemetry design.
#define D_SOCK_CREATE_ENTRY 0
#define D_CONNECT4_ENTRY 1
#define D_SOCKOPS_ENTRY 2
#define D_CONNECT4_ATTRIBUTION_ATTEMPT 3
#define D_SOCKOPS_TCP_CONNECT 4
#define D_SOCKOPS_ACTIVE_ESTABLISHED 5
#define D_SOCKOPS_PUBLISH_ATTEMPT 6
#define D_COUNT 7

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, D_COUNT);
    __type(key, __u32);
    __type(value, __u64);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} soglia_diag_entries SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, P_COUNT);
    __type(key, __u32);
    __type(value, __u32);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} soglia_port_diag SEC(".maps");

static __always_inline void diag_bump(__u32 index)
{
    __u64 *value = bpf_map_lookup_elem(&soglia_diag_entries, &index);
    if (value)
        __sync_fetch_and_add(value, 1);
}

static __always_inline void port_diag_set(__u32 index, __u32 observed)
{
    __u32 *value = bpf_map_lookup_elem(&soglia_port_diag, &index);
    if (value)
        *value = observed;
}
#else
static __always_inline void diag_bump(__u32 index)
{
    (void)index;
}

static __always_inline void port_diag_set(__u32 index, __u32 observed)
{
    (void)index;
    (void)observed;
}
#endif

// Denies per Execution cgroup: counts that cannot be dropped, unlike events.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u64);
    __type(value, __u64);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} soglia_denies SEC(".maps");

// S13 spike-only state binding, written and validated by the managed loader. No BPF program reads
// it and it is never an authorization input. The six u64 slots contain, in order: magic bytes,
// schema version, ABI version, a 128-bit opaque state id (two slots), and generation. Ownership is
// established by the matching root-owned record outside bpffs, never by this map alone.
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64[6]);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} soglia_meta SEC(".maps");

#ifdef SPIKE_TRACE
struct trace_record {
    __u64 seq;
    __u32 who; // 1 = soglia connect4
    __u32 daddr;
    __u32 dport;
    __u32 _pad;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 16 * 1024);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} spike_trace SEC(".maps");
#endif

static __always_inline void bump(__u32 index)
{
    __u64 *value = bpf_map_lookup_elem(&soglia_counters, &index);
    if (value)
        __sync_fetch_and_add(value, 1);
}

static __always_inline void deny_count(__u64 cgid)
{
    __u64 *value = bpf_map_lookup_elem(&soglia_denies, &cgid);
    if (value) {
        __sync_fetch_and_add(value, 1);
    } else {
        __u64 one = 1;
        bpf_map_update_elem(&soglia_denies, &cgid, &one, BPF_NOEXIST);
    }
}

static __always_inline void emit(__u32 kind, __u32 reason, __u64 cgid, __u64 cookie, __u32 family,
                                 __u32 type, __u32 daddr, __u32 dport)
{
    struct event event = {
        .kind = kind,
        .reason = reason,
        .cgid = cgid,
        .cookie = cookie,
        .family = family,
        .type = type,
        .daddr = daddr,
        .dport = dport,
        .ts_ns = bpf_ktime_get_ns(),
    };
    if (bpf_ringbuf_output(&soglia_events, &event, sizeof(event), 0))
        bump(C_EVENTS_DROPPED);
}

static __always_inline int active(__u64 cgid)
{
    if (exec_ident) {
        __u32 zero = 0;
        __u64 *state = bpf_map_lookup_elem(&policy_local, &zero);
        return state && *state == STATE_ACTIVE;
    }
    struct policy_value *policy = bpf_map_lookup_elem(&soglia_policy, &cgid);
    return policy && policy->state == STATE_ACTIVE;
}

SEC("cgroup/sock_create")
int soglia_sock_create(struct bpf_sock *sk)
{
    diag_bump(0);
    __u32 family = sk->family;
    __u32 type = sk->type;
    __u32 protocol = sk->protocol;

    if (family == AF_INET && type == SOCK_STREAM && protocol == IPPROTO_TCP)
        return 1;
#ifdef SPIKE_RELAX_INET6_STREAM
    if (family == AF_INET6 && type == SOCK_STREAM)
        return 1;
#endif
#ifdef SPIKE_RELAX_DGRAM
    if ((family == AF_INET || family == AF_INET6) && type == SOCK_DGRAM)
        return 1;
#endif
    __u64 cgid = bpf_get_current_cgroup_id();
    bump(C_SOCK_CREATE_DENY);
    deny_count(cgid);
    emit(EV_SOCK_CREATE_DENY, R_FAMILY, cgid, 0, family, type, 0, 0);
    return 0;
}

SEC("cgroup/connect4")
int soglia_connect4(struct bpf_sock_addr *ctx)
{
    diag_bump(1);
    __u64 cgid = bpf_get_current_cgroup_id();
    __u32 daddr = ctx->user_ip4;
    port_diag_set(P_CONNECT_RAW, ctx->user_port);
    port_diag_set(P_CONNECT_LOW16, ctx->user_port & 0xffff);
    port_diag_set(P_CONNECT_NTOHS_LOW16, bpf_ntohs((__u16)ctx->user_port));
    __u32 dport = bpf_ntohs((__u16)ctx->user_port);
    __u32 reason = 0;

#ifdef SPIKE_TRACE
    struct trace_record record = { .seq = bpf_ktime_get_ns(), .who = 1, .daddr = daddr, .dport = dport };
    bpf_ringbuf_output(&spike_trace, &record, sizeof(record), 0);
#endif

    if (!active(cgid))
        reason = R_NOT_ACTIVE;
    else if (ctx->type != SOCK_STREAM || ctx->protocol != IPPROTO_TCP)
        reason = R_NOT_TCP;
    else if (daddr != proxy_ip4 || dport != proxy_port) {
#ifdef SPIKE_ALLOW_DIRECT4
        if (daddr != direct_ip4 || dport != direct_port)
            reason = R_NOT_PROXY;
#else
        reason = R_NOT_PROXY;
#endif
    }

    if (reason) {
        bump(C_CONNECT4_DENY);
        deny_count(cgid);
        emit(EV_CONNECT_DENY, reason, cgid, bpf_get_socket_cookie(ctx), AF_INET, ctx->type, daddr, dport);
        return 0;
    }

    diag_bump(3);
    // Candidate A.
    __u64 cookie = bpf_get_socket_cookie(ctx);
    map_diag_bump(0);
    long cookie_result = bpf_map_update_elem(&soglia_cookie_a, &cookie, &cgid, BPF_ANY);
    map_diag_set(2, cookie_result);
    if (cookie_result)
        map_diag_bump(1);

    // Candidate B.
    struct bpf_sock *sk = ctx->sk;
    if (sk) {
        map_diag_bump(3);
        __u64 *stored = bpf_sk_storage_get(&soglia_sk_b, sk, 0, BPF_SK_STORAGE_GET_F_CREATE);
        if (stored)
            *stored = cgid;
        else
            map_diag_bump(4);
    }

    return 1;
}

SEC("cgroup/connect6")
int soglia_connect6(struct bpf_sock_addr *ctx)
{
    __u64 cgid = bpf_get_current_cgroup_id();
    bump(C_CONNECT6_DENY);
    deny_count(cgid);
    emit(EV_CONNECT_DENY, R_IPV6, cgid, bpf_get_socket_cookie(ctx), AF_INET6, ctx->type, 0,
         bpf_ntohs((__u16)ctx->user_port));
    return 0;
}

SEC("cgroup/sendmsg4")
int soglia_sendmsg4(struct bpf_sock_addr *ctx)
{
    __u64 cgid = bpf_get_current_cgroup_id();
    bump(C_SENDMSG4_DENY);
    deny_count(cgid);
    emit(EV_SENDMSG_DENY, R_UDP, cgid, bpf_get_socket_cookie(ctx), AF_INET, ctx->type, ctx->user_ip4,
         bpf_ntohs((__u16)ctx->user_port));
    return 0;
}

SEC("cgroup/sendmsg6")
int soglia_sendmsg6(struct bpf_sock_addr *ctx)
{
    __u64 cgid = bpf_get_current_cgroup_id();
    bump(C_SENDMSG6_DENY);
    deny_count(cgid);
    emit(EV_SENDMSG_DENY, R_IPV6, cgid, bpf_get_socket_cookie(ctx), AF_INET6, ctx->type, 0,
         bpf_ntohs((__u16)ctx->user_port));
    return 0;
}

static __always_inline void key_of(struct bpf_sock_ops *skops, struct tuple *key)
{
    key->saddr = skops->local_ip4;
    key->daddr = skops->remote_ip4;
    key->sport = skops->local_port;
    // remote_port is a network-order u32; the full-width conversion yields the host-order port.
    key->dport = bpf_ntohl(skops->remote_port);
}

static __always_inline void publish(struct bpf_sock_ops *skops)
{
    diag_bump(6);
    struct tuple key = {};
    struct evidence evidence = {};

    key_of(skops, &key);
    __u32 raw_remote_port = skops->remote_port;
    port_diag_set(P_SOCKOPS_RAW, raw_remote_port);
    port_diag_set(P_SOCKOPS_LOW16, raw_remote_port & 0xffff);
    port_diag_set(P_SOCKOPS_HIGH16, raw_remote_port >> 16);
    port_diag_set(P_SOCKOPS_NTOHL, bpf_ntohl(raw_remote_port));
    port_diag_set(P_SOCKOPS_OLD_EXTRACT, bpf_ntohl(raw_remote_port) >> 16);
    port_diag_set(P_SOCKOPS_NTOHS_HIGH16, bpf_ntohs((__u16)(raw_remote_port >> 16)));
    port_diag_set(P_TUPLE_ASSIGNED, key.dport);
    port_diag_set(P_EXPECTED, proxy_port);
    evidence.sock_cookie = bpf_get_socket_cookie(skops);
    __u64 *a = bpf_map_lookup_elem(&soglia_cookie_a, &evidence.sock_cookie);
    evidence.a_cgid = a ? *a : 0;
    struct bpf_sock *sk = skops->sk;
    if (sk) {
        __u64 *b = bpf_sk_storage_get(&soglia_sk_b, sk, 0, 0);
        evidence.b_cgid = b ? *b : 0;
    }
    evidence.c_ident = exec_ident;
    evidence.d_netns = bpf_get_netns_cookie(skops);
    evidence.ts_ns = bpf_ktime_get_ns();
    evidence.sockops_current_cgid = bpf_get_current_cgroup_id();
    evidence.raw_remote_port = skops->remote_port;

#ifdef SPIKE_DELAY_PUBLISH
    void *target = &soglia_staging;
#else
    void *target = &soglia_tuples;
#endif
    port_diag_set(P_TUPLE_BEFORE_INSERT, key.dport);
    map_diag_bump(5);
    long tuple_result = bpf_map_update_elem(target, &key, &evidence, BPF_ANY);
    map_diag_set(7, tuple_result);
    if (tuple_result) {
        map_diag_bump(6);
        bump(C_TUPLE_INSERT_FAILED);
        emit(EV_MAP_FULL, 0, evidence.a_cgid, evidence.sock_cookie, AF_INET, SOCK_STREAM, key.daddr,
             key.dport);
    } else {
        bump(C_PUBLISHED);
    }
}

static __always_inline void unpublish(struct bpf_sock_ops *skops)
{
    struct tuple key = {};
    __u64 cookie = bpf_get_socket_cookie(skops);

    key_of(skops, &key);
    struct evidence *evidence = bpf_map_lookup_elem(&soglia_tuples, &key);
    // Only this socket's own entry: a later connection that reused the tuple keeps its own.
    if (evidence && evidence->sock_cookie == cookie) {
        bpf_map_delete_elem(&soglia_tuples, &key);
        bump(C_UNPUBLISHED);
    }
    bpf_map_delete_elem(&soglia_cookie_a, &cookie);
}

SEC("sockops")
int soglia_sockops(struct bpf_sock_ops *skops)
{
    diag_bump(2);
    switch (skops->op) {
    case BPF_SOCK_OPS_TCP_CONNECT_CB:
        diag_bump(4);
        bpf_sock_ops_cb_flags_set(skops, BPF_SOCK_OPS_STATE_CB_FLAG);
        break;
    case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB:
        diag_bump(5);
        publish(skops);
        break;
    case BPF_SOCK_OPS_STATE_CB:
        if (skops->args[1] == BPF_TCP_CLOSE)
            unpublish(skops);
        break;
    default:
        break;
    }
    return 1;
}
