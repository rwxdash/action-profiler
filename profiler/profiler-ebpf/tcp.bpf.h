#if !defined(__TCP_BPF_H)
#define __TCP_BPF_H

#include "profiler.bpf.h"

// ============================================================
// TCP connection tracking via tp_btf/inet_sock_set_state (CO-RE).
//
// tp_btf gives us struct sock *sk directly
// IPs and ports read via BPF_CORE_READ on sk->__sk_common,
// stable across kernel versions.
//
// tp_btf signature (from kernel source):
//   trace_inet_sock_set_state(struct sock *sk, int oldstate, int newstate)
//
// State machine:
//   SYN_SENT                -> stash pid/timestamp in TCP_CONN_START
//   SYN_SENT -> ESTABLISHED -> emit connect event (with handshake latency)
//   SYN_RECV -> ESTABLISHED -> emit accept event
//   * -> CLOSE              -> emit close event (with connection duration)
//
// Key struct sock fields (via sk->__sk_common):
//   skc_family       (__u16)           - AF_INET=2, AF_INET6=10
//   skc_num          (__u16)           - Source port (host byte order)
//   skc_dport        (__be16)          - Dest port (network byte order, use bpf_ntohs)
//   skc_rcv_saddr    (__be32)          - Source IPv4
//   skc_daddr        (__be32)          - Dest IPv4
//   skc_v6_rcv_saddr (struct in6_addr) - Source IPv6
//   skc_v6_daddr     (struct in6_addr) - Dest IPv6
// ============================================================

// Check if IPv4 address is loopback (127.0.0.0/8)
// saddr is in network byte order: first byte is the high octet
static __always_inline int is_loopback_v4(__u32 addr)
{
    return (addr & 0xFF) == 127;
}

// Check if IPv6 address is ::1
static __always_inline int is_loopback_v6(__u8 addr[16])
{
    // ::1 = 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01
    for (int i = 0; i < 15; i++) {
        if (addr[i] != 0) {
            return 0;
        }
    }

    return addr[15] == 1;
}

static __always_inline int is_loopback(struct tcp_event *evt)
{
    if (evt->family == 2) {
        return is_loopback_v4(evt->saddr_v4) || is_loopback_v4(evt->daddr_v4);
    }

    if (evt->family == 10) {
        return is_loopback_v6(evt->saddr_v6) || is_loopback_v6(evt->daddr_v6);
    }

    return 0;
}

// Read IPs and ports from struct sock using CO-RE
static __always_inline void read_sock_info(struct sock *sk, struct tcp_event *evt)
{
    evt->family = BPF_CORE_READ(sk, __sk_common.skc_family);

    // skc_num (source port) is host byte order, skc_dport is network byte order
    evt->sport = BPF_CORE_READ(sk, __sk_common.skc_num);
    evt->dport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));

    if (evt->family == 2 /* AF_INET */) {
        evt->saddr_v4 = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
        evt->daddr_v4 = BPF_CORE_READ(sk, __sk_common.skc_daddr);
    } else if (evt->family == 10 /* AF_INET6 */) {
        BPF_CORE_READ_INTO(&evt->saddr_v6, sk, __sk_common.skc_v6_rcv_saddr.in6_u.u6_addr8);
        BPF_CORE_READ_INTO(&evt->daddr_v6, sk, __sk_common.skc_v6_daddr.in6_u.u6_addr8);
    }
}

// tp_btf gives us the struct sock directly
// Kernel signature: trace_inet_sock_set_state(struct sock *sk, int oldstate, int newstate)
SEC("tp_btf/inet_sock_set_state")
int BPF_PROG(handle_inet_sock_set_state, struct sock *sk, int oldstate, int newstate)
{
    __u64 skaddr = (__u64) sk;
    __u64 now    = bpf_ktime_get_boot_ns();

    // SYN_SENT: stash timestamp for connect latency
    if (newstate == TCP_ST_SYN_SENT) {
        struct tcp_conn_stash stash = {};
        stash.time_ns               = now;
        stash.pid                   = bpf_get_current_pid_tgid() >> 32;

        bpf_get_current_comm(stash.name, sizeof(stash.name));
        bpf_map_update_elem(&TCP_CONN_START, &skaddr, &stash, BPF_ANY);

        return 0;
    }

    // ESTABLISHED: emit connect or accept event
    if (newstate == TCP_ST_ESTABLISHED) {
        struct tcp_event *evt = bpf_ringbuf_reserve(&EVENTS, sizeof(*evt), 0);
        if (!evt) {
            return 0;
        }

        __builtin_memset(evt, 0, sizeof(*evt));

        evt->time_ns    = now;
        evt->event_type = EVENT_TCP;

        read_sock_info(sk, evt);

        if (is_loopback(evt)) {
            bpf_ringbuf_discard(evt, 0);
            return 0;
        }

        if (oldstate == TCP_ST_SYN_SENT) {
            // Outbound connect
            evt->type = TCP_TYPE_CONNECT;

            // Compute connect latency from SYN_SENT stash
            struct tcp_conn_stash *stash = bpf_map_lookup_elem(&TCP_CONN_START, &skaddr);
            if (stash) {
                evt->duration_ns = now - stash->time_ns;
                evt->pid         = stash->pid;

                __builtin_memcpy(evt->name, stash->name, sizeof(evt->name));
            } else {
                evt->pid = bpf_get_current_pid_tgid() >> 32;
                bpf_get_current_comm(evt->name, sizeof(evt->name));
            }
        } else if (oldstate == TCP_ST_SYN_RECV || oldstate == TCP_ST_NEW_SYN_RECV) {
            // Inbound accept
            evt->type = TCP_TYPE_ACCEPT;
            evt->pid  = bpf_get_current_pid_tgid() >> 32;

            bpf_get_current_comm(evt->name, sizeof(evt->name));
        } else {
            bpf_ringbuf_discard(evt, 0);

            return 0;
        }

        // Re-stash for duration tracking on close
        struct tcp_conn_stash conn = {};
        conn.time_ns               = now;
        conn.pid                   = evt->pid;

        __builtin_memcpy(conn.name, evt->name, sizeof(conn.name));

        bpf_map_update_elem(&TCP_CONN_START, &skaddr, &conn, BPF_ANY);
        bpf_ringbuf_submit(evt, 0);

        return 0;
    }

    // CLOSE: emit close event with connection duration
    if (newstate == TCP_ST_CLOSE) {
        struct tcp_conn_stash *stash = bpf_map_lookup_elem(&TCP_CONN_START, &skaddr);
        if (!stash) {
            return 0; // connection started before profiler
        }

        struct tcp_conn_stash saved = *stash;
        bpf_map_delete_elem(&TCP_CONN_START, &skaddr);

        struct tcp_event *evt = bpf_ringbuf_reserve(&EVENTS, sizeof(*evt), 0);
        if (!evt) {
            return 0;
        }

        __builtin_memset(evt, 0, sizeof(*evt));

        evt->time_ns     = now;
        evt->event_type  = EVENT_TCP;
        evt->type        = TCP_TYPE_CLOSE;
        evt->pid         = saved.pid;
        evt->duration_ns = now - saved.time_ns;

        __builtin_memcpy(evt->name, saved.name, sizeof(evt->name));

        read_sock_info(sk, evt);

        if (is_loopback(evt)) {
            bpf_ringbuf_discard(evt, 0);

            return 0;
        }

        bpf_ringbuf_submit(evt, 0);

        return 0;
    }

    return 0;
}

#endif // __TCP_BPF_H
