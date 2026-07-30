//! Minimal `struct sockaddr_in` parsing/encoding for the smoltcp-xdp
//! backend's socket syscall handlers.
//!
//! kmod copies pointer-argument bytes to the beacon verbatim, unparsed
//! (see `kmod/syscalls.c`'s `rscaller_patch_ptr_params`, e.g. the `bind`/
//! `connect` cases: a flat `copy_from_user(pb->data, ptr, 4096)`), so a
//! `SyscallBuf::data` for a `sockaddr*` argument is exactly the raw
//! `struct sockaddr_in` bytes the client's libc/kernel produced —
//! `sin_family` in host byte order, `sin_port`/`sin_addr` already in
//! network (big-endian) byte order, precisely as a real `bind`/`connect`
//! call lays them out. Only IPv4 (`AF_INET`) is supported (see design
//! Non-Goals: no IPv6 in v1).
//!
//! kmod's capture is a fixed 4096-byte window regardless of the actual
//! `addrlen` argument, so `data` may be (and usually is) much longer than
//! 16 bytes — only the `sockaddr_in` prefix is meaningful.

use smoltcp::wire::Ipv4Address;

pub const AF_INET: u16 = libc::AF_INET as u16;
pub const SOCKADDR_IN_LEN: usize = 16;

/// Parses a `struct sockaddr_in` from the start of `data`.
pub fn parse_sockaddr_in(data: &[u8]) -> Option<(Ipv4Address, u16)> {
    if data.len() < SOCKADDR_IN_LEN {
        return None;
    }
    let family = u16::from_ne_bytes([data[0], data[1]]);
    if family != AF_INET {
        return None;
    }
    let port = u16::from_be_bytes([data[2], data[3]]);
    let addr = Ipv4Address::new(data[4], data[5], data[6], data[7]);
    Some((addr, port))
}

/// Encodes a `struct sockaddr_in` (16 bytes, zero-padded `sin_zero`) for
/// handing back to a caller (e.g. `accept4`'s peer-address out-param).
pub fn encode_sockaddr_in(addr: Ipv4Address, port: u16) -> [u8; SOCKADDR_IN_LEN] {
    let mut buf = [0u8; SOCKADDR_IN_LEN];
    buf[0..2].copy_from_slice(&AF_INET.to_ne_bytes());
    buf[2..4].copy_from_slice(&port.to_be_bytes());
    buf[4..8].copy_from_slice(&addr.octets());
    buf
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_addr_and_port() {
        let encoded = encode_sockaddr_in(Ipv4Address::new(10, 0, 0, 1), 8080);
        let (addr, port) = parse_sockaddr_in(&encoded).unwrap();
        assert_eq!(addr, Ipv4Address::new(10, 0, 0, 1));
        assert_eq!(port, 8080);
    }

    #[test]
    fn rejects_non_af_inet_family() {
        let mut buf = [0u8; SOCKADDR_IN_LEN];
        buf[0..2].copy_from_slice(&(libc::AF_INET6 as u16).to_ne_bytes());
        assert!(parse_sockaddr_in(&buf).is_none());
    }

    #[test]
    fn rejects_short_buffers() {
        assert!(parse_sockaddr_in(&[0u8; 4]).is_none());
    }

    #[test]
    fn tolerates_oversized_kmod_buffer() {
        // kmod copies a fixed 4096-byte window regardless of the real
        // addrlen; only the sockaddr_in prefix matters.
        let mut buf = vec![0u8; 4096];
        buf[0..SOCKADDR_IN_LEN]
            .copy_from_slice(&encode_sockaddr_in(Ipv4Address::new(1, 2, 3, 4), 53));
        let (addr, port) = parse_sockaddr_in(&buf).unwrap();
        assert_eq!(addr, Ipv4Address::new(1, 2, 3, 4));
        assert_eq!(port, 53);
    }
}
