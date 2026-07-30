// XDP program for the `smoltcp-xdp` rsbeacon network backend.
//
// Selectively redirects ingress ARP, ICMP packets, TCP packets whose
// destination port is registered in `tcp_ports`, and UDP packets whose
// destination port is registered in `udp_ports`, into the beacon's
// AF_XDP socket via `xsks_map`; everything else gets XDP_PASS so the
// host kernel's normal network stack (and any other traffic sharing
// this interface, e.g. SSH) is completely unaffected.
//
// ARP redirect: design decision D6 (see design.md) has `smoltcp::iface
// ::Interface` resolve neighbor MACs itself via its own ARP requests
// sent over the AF_XDP-backed `XdpDevice`, rather than pre-seeding a
// resolved gateway MAC the way xdplganger's gVisor bridge needed to.
// That only works end-to-end if ingress ARP replies (and ARP requests
// targeting smoltcp's own address) actually reach smoltcp's neighbor
// cache — found missing in testing (task 8.x): without this branch,
// every ARP reply is XDP_PASS-ed to the host kernel's own ARP table
// instead, so smoltcp's neighbor cache never populates and NO outbound
// traffic (TCP connect, UDP send, or even an ICMP echo reply, which
// itself must resolve the request's source IP back to a destination
// MAC) ever actually gets transmitted. Same "always redirect, no
// per-flow tracking" treatment as ICMP, for the same reason: ARP has no
// port to gate on, and is inherently a control-plane protocol the
// userspace stack must see in full to function at all. Trade-off: the
// host kernel loses ARP visibility on this interface once smoltcp-xdp
// is active (existing kernel neighbor-cache entries, e.g. for an
// already-connected SSH session, remain valid and unaffected; only
// *new* kernel-side ARP resolutions on this interface would be
// impacted) — acceptable for rscaller's disposable-beacon-VM threat
// model, and no worse than ICMP's existing unconditional redirect.
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

struct {
    __uint(type, BPF_MAP_TYPE_XSKMAP);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 64);
} xsks_map SEC(".maps");

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

    if (eth->h_proto == bpf_htons(ETH_P_ARP))
        goto redirect;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
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
