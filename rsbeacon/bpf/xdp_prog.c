// XDP program for the `smoltcp-xdp` rsbeacon network backend.
//
// Selectively redirects ingress ARP, ICMP packets, TCP packets whose
// destination port is registered in `tcp_ports`, and UDP packets whose
// destination port is registered in `udp_ports`, into the beacon's
// AF_XDP socket via `xsks_map`; everything else gets XDP_PASS so the
// host kernel's normal network stack (and any other traffic sharing
// this interface, e.g. SSH) is completely unaffected.
//
// filter_config: single-entry ARRAY holding the smoltcp stack's own IPv4
// address (network byte order), written from Rust at backend init
// (`--xdp-ip`). Every redirect branch requires the packet to target THAT
// address — never the host kernel's address:
//
//   - ARP: redirected only when the target protocol address (TPA) is the
//     smoltcp IP. ARP has no ports and smoltcp must resolve neighbor MACs
//     itself (design D6), so it needs "who-has <smoltcp-ip>" requests and
//     the replies to its own requests — both carry TPA == smoltcp IP.
//     Redirecting ARP unconditionally starves the HOST kernel's ARP on a
//     shared interface: neighbors' caches for the host expire and the
//     host becomes unreachable (observed: SSH/curl on the VM died minutes
//     after attach). smoltcp therefore MUST run on its own address,
//     distinct from the interface's kernel address — enforced by backend
//     init.
//   - ICMP/TCP/UDP: redirected only when ip->daddr is the smoltcp IP
//     (plus a registered destination port for TCP/UDP).
//
// If filter_config is unset (0), everything is XDP_PASS-ed — fail-safe,
// the backend never steals traffic it wasn't configured for.
//
// Originally ported from xdplganger's bpf/xdp_prog.c
// (../../xdplganger/bpf/xdp_prog.c) — see design decision D4 in
// openspec/changes/add-beacon-smoltcp-xdp-netstack/design.md. NOTE: the
// xdplganger source only redirects ICMP+TCP, not UDP — the `udp_ports`
// map and its redirect branch below are an addition on top of that
// reference, needed because this design's Goals (unlike xdplganger's own
// scope) include working `smoltcp` UDP sockets. Two separate maps
// (rather than one shared by both protocols) are used because TCP and
// UDP port numbers are independent namespaces — tracking port 53 for
// TCP must never cause UDP DNS traffic on port 53 to be redirected too.
//
// Compiled ahead-of-time to BPF bytecode (clang -target bpf) and checked
// into the repo as xdp_prog.o, matching xdplganger's approach of not
// requiring a BPF toolchain at rsbeacon's own build/run time. Rebuild with:
//   clang -O2 -g -target bpf -D__TARGET_ARCH_x86 \
//       -I/usr/include/$(uname -m)-linux-gnu \
//       -c bpf/xdp_prog.c -o bpf/xdp_prog.o

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// <linux/if_arp.h> drags in libc headers (via <linux/netdevice.h>) that
// don't exist in a -target bpf sysroot without multilib; the one constant
// needed is trivially defined here instead.
#ifndef ARPHRD_ETHER
#define ARPHRD_ETHER 1
#endif
// Bare ARP header — same layout as struct arphdr (ar_sha/ar_sip/... are
// parsed manually below, so only the fixed part is declared).
struct arphdr {
    __u16 ar_hrd;
    __u16 ar_pro;
    __u8 ar_hln;
    __u8 ar_pln;
    __u16 ar_op;
};

struct {
    __uint(type, BPF_MAP_TYPE_XSKMAP);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 64);
} xsks_map SEC(".maps");

// filter_config[0]: the smoltcp stack's own IPv4 address, network byte
// order. 0 = unset → XDP_PASS everything (fail-safe). See file header.
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 1);
} filter_config SEC(".maps");

static __always_inline __u32 smoltcp_ip(void)
{
    __u32 key = 0;
    __u32 *ip = bpf_map_lookup_elem(&filter_config, &key);
    return ip ? *ip : 0;
}

// tcp_ports: set of local TCP ports currently owned by the smoltcp-xdp
// backend's userspace socket table. Key = destination port in host byte
// order (stored as u32 for alignment). Updated from Rust as smoltcp TCP
// sockets listen/connect and close (see net_backend/smoltcp_xdp/bpf.rs).
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u8);
    __uint(max_entries, 1024);
} tcp_ports SEC(".maps");

// udp_ports: same as tcp_ports, but for local UDP ports. Kept as a
// separate map from tcp_ports — see file header comment.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u8);
    __uint(max_entries, 1024);
} udp_ports SEC(".maps");

SEC("xdp")
int xdp_sock_prog(struct xdp_md *ctx)
{
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    __u32 local_ip = smoltcp_ip();
    if (local_ip == 0)
        return XDP_PASS;

    if (eth->h_proto == bpf_htons(ETH_P_ARP)) {
        // Ethernet/IPv4 ARP: redirect only when the TARGET protocol
        // address is smoltcp's IP (requests for it, and replies to its
        // own requests — a reply swaps sender/target, so both match on
        // TPA). Host-kernel ARP (TPA == host IP) is XDP_PASS-ed.
        struct arphdr *arp = (void *)(eth + 1);
        if ((void *)(arp + 1) > data_end)
            return XDP_PASS;
        if (arp->ar_hrd != bpf_htons(ARPHRD_ETHER) ||
            arp->ar_pro != bpf_htons(ETH_P_IP) ||
            arp->ar_hln != ETH_ALEN || arp->ar_pln != 4)
            return XDP_PASS;
        // payload: sender_hw[6] sender_ip[4] target_hw[6] target_ip[4]
        __u8 *p = (__u8 *)(arp + 1);
        if ((void *)(p + 2 * ETH_ALEN + 2 * 4) > data_end)
            return XDP_PASS;
        __u32 tpa;
        __builtin_memcpy(&tpa, p + ETH_ALEN + 4 + ETH_ALEN, 4);
        if (tpa != local_ip)
            return XDP_PASS;
        goto redirect;
    }

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    if (ip->daddr != local_ip)
        return XDP_PASS;

    if (ip->protocol == IPPROTO_ICMP)
        goto redirect;

    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
        if ((void *)(tcp + 1) > data_end)
            return XDP_PASS;

        __u32 dport = bpf_ntohs(tcp->dest);
        if (!bpf_map_lookup_elem(&tcp_ports, &dport))
            return XDP_PASS;

        goto redirect;
    }

    if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)ip + (ip->ihl * 4);
        if ((void *)(udp + 1) > data_end)
            return XDP_PASS;

        __u32 dport = bpf_ntohs(udp->dest);
        if (!bpf_map_lookup_elem(&udp_ports, &dport))
            return XDP_PASS;

        goto redirect;
    }

    return XDP_PASS;

redirect:;
    __u32 idx = ctx->rx_queue_index;
    if (bpf_map_lookup_elem(&xsks_map, &idx))
        return bpf_redirect_map(&xsks_map, idx, XDP_PASS);

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
