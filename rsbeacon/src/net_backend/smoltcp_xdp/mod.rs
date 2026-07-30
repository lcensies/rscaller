//! The `smoltcp-xdp` network backend: services intercepted socket syscalls
//! through a userspace `smoltcp` TCP/IP stack bridged to an AF_XDP socket,
//! instead of the beacon host's kernel network stack.
//!
//! See `openspec/changes/add-beacon-smoltcp-xdp-netstack/design.md` for the
//! full architecture (decisions D1-D6).

pub mod addr_detect;
pub mod backend;
pub mod bpf;
pub mod bridge;
pub mod init;
pub mod sockaddr;
pub mod xdp_abi;
pub mod umem;
pub mod xdp_socket;
