# Network Routing Policy

## Overview

Network routing policy controls how `connect()` and `sendto()` syscalls are handled: should they use the **local kernel** (real network interface) or be **relayed through rsbeacon** (remote network backend)?

This document defines the policy model, syntax, use cases, and default behavior.

---

## Problem

Early network forwarding was binary: either **forward everything to rsbeacon** or **whitelist specific subnets**. This fails for real-world sandboxing:

```
Scenario: Sliver beacon on attack machine, relayed through compromised host.

Problem:
- Beacon needs to REACH target network (192.168.1.0/24) via beacon.
- Beacon needs to CALLBACK to C2 server (10.0.0.1:443) via local network.
- Beacon needs to DOWNLOAD resources (apt, yum, pip) via local internet.

Old model:
  --filter-net "192.168.1.0/24"  # Only whitelist targets → C2 callback breaks
  --filter-net-deny "10.0.0.1"  # Add exception → messy, unclear defaults
```

**Solution:** Ordered routing table. Each rule specifies a destination subnet and the **direction** (LOCAL or REMOTE).

---

## Model

### Route Entry

```
Route {
  subnet: "192.168.1.0/24"
  port: 443 (optional, 0 = any)
  direction: LOCAL | REMOTE
}
```

### Matching

For a syscall `connect(fd, 192.168.1.100:443)`:

1. Parse destination IP and port from `sockaddr_in`.
2. Iterate routes in order.
3. First route where:
   - Subnet matches (CIDR), AND
   - Port matches (if specified, otherwise any port), AND
   - IP/port check passes
   
   → apply that direction (LOCAL or REMOTE).

4. If no route matches → **default to LOCAL** (safe: local network by default, opt-in to remote).

### Semantics

- **LOCAL:** Syscall continues on real kernel, using tracee's actual network interface.
- **REMOTE:** Syscall is forwarded to rsbeacon, which executes it in rsbeacon's network stack (smoltcp-xdp or other backend).

---

## Use Cases

### 1. Red Team: Beacon + C2 + Targets

**Setup:** Sliver beacon on attack machine (you, trusted), sandboxed via rscaller.

```yaml
net_routes:
  # C2 server: use real network
  - subnet: "10.0.0.1/32"
    port: 443
    direction: LOCAL
  
  # Internet: use real network (for downloading tools, payloads)
  - subnet: "0.0.0.0/0"
    direction: LOCAL
    
  # BUT: target network through beacon (compromised host)
  # This rule is NEVER reached because 0.0.0.0/0 catches everything.
  # So we need explicit REMOTE rules BEFORE the default.
```

**Corrected:**

```yaml
net_routes:
  # C2 server: use real network (most specific first)
  - subnet: "10.0.0.1/32"
    port: 443
    direction: LOCAL
  
  # Target network: relay through beacon
  - subnet: "192.168.1.0/24"
    direction: REMOTE
  
  # Everything else: use real network
  - subnet: "0.0.0.0/0"
    direction: LOCAL
```

**Result:**
- `connect(192.168.1.100:445)` → REMOTE (beacon relays)
- `connect(10.0.0.1:443)` → LOCAL (C2 callback works)
- `connect(archive.ubuntu.com:443)` → LOCAL (DNS resolves locally, download via real network)
- `connect(unknown.ip:80)` → LOCAL (default safe)

---

### 2. Internal Pivoting: Multi-segment Access

**Setup:** Compromise internal host, relay from there to other segments via beacon.

```yaml
net_routes:
  # Local container/DNS/NTP
  - subnet: "10.0.0.0/8"
    direction: LOCAL
  
  # Your C2 server (on VPN or reachable via local network)
  - subnet: "198.51.100.007/32"
    port: 443
    direction: LOCAL
  
  # Target segment 1: relay through beacon
  - subnet: "192.168.0.0/16"
    direction: REMOTE
  
  # Target segment 2: relay through beacon
  - subnet: "172.16.0.0/12"
    direction: REMOTE
  
  # Everything else: local (safer than blind relay)
  - subnet: "0.0.0.0/0"
    direction: LOCAL
```

---

### 3. Sandboxed Container: Selective Remote Access

**Setup:** Container needs package repos (local), but restricted to one target subnet.

```yaml
net_routes:
  # Local container networking
  - subnet: "10.0.0.0/8"
    direction: LOCAL
  
  # Public DNS (8.8.8.8, 1.1.1.1)
  - subnet: "8.8.8.0/24"
    port: 53
    direction: LOCAL
  - subnet: "1.1.1.0/24"
    port: 53
    direction: LOCAL
  
  # Package repos (apt.ubuntu.com, pypi.org, etc.)
  # Resolved locally, so LOCAL direction works
  - subnet: "0.0.0.0/0"
    port: 80
    direction: LOCAL
  - subnet: "0.0.0.0/0"
    port: 443
    direction: LOCAL
  
  # EXCEPT: this one subnet is restricted, relay through beacon
  - subnet: "192.168.99.0/24"
    direction: REMOTE
```

---

## Syntax

### YAML Profile

```yaml
name: shadow-routed
description: "Shadow profile with network routing policy"
mounts:
  - remote: /proc
    local: /proc
    type: bind
forward:
  - name: network-routed
    syscalls: [socket, connect, bind, sendto]
    filter:
      net_routes:
        - subnet: "10.0.0.1/32"
          port: 443
          direction: LOCAL
        
        - subnet: "192.168.1.0/24"
          direction: REMOTE
        
        - subnet: "0.0.0.0/0"
          direction: LOCAL
  
  - name: socket-fd-ops
    syscalls: [read, write, close, poll, ppoll, fcntl, ioctl]
    filter:
      fd_range: virtual
```

### CLI Arguments

```bash
rsc exec \
  --mount-profile shadow \
  --beacon 192.168.1.100:9999 \
  --route "10.0.0.1:443=local" \
  --route "192.168.1.0/24=remote" \
  --route "0.0.0.0/0=local" \
  -- ./beacon
```

**Format:** `--route "<subnet>[:port]=<direction>"`

- Subnet: CIDR (e.g., "192.168.1.0/24", "10.0.0.1/32")
- Port: optional, specific port (e.g., "10.0.0.1:443"), omit for any port
- Direction: "local" or "remote"

Routes are applied in order of specification. First match wins.

---

## Default Behavior

**No routes specified** → **everything LOCAL** (safest default).

```bash
rsc exec --beacon 192.168.1.100:9999 -- ./process
# All connects use real kernel, nothing goes through beacon
```

**Why:**
- Fail-safe: process has network, but nothing unexpected is relayed.
- Forces explicit opt-in to remote forwarding (audit trail).
- Matches Unix principle: deny by default.

**To enable beacon forwarding:**

```bash
# Explicit: only this subnet through beacon
rsc exec --beacon 192.168.1.100:9999 --route "192.168.1.0/24=remote" -- ./process

# Or: everything through beacon (set default, then exclude)
rsc exec --beacon 192.168.1.100:9999 \
  --route "0.0.0.0/0=remote" \
  --route "10.0.0.1/32=local" \
  -- ./process
```

---

## Matching Order & Edge Cases

### Overlapping Subnets

**Routes are checked in order; first match wins.**

```yaml
net_routes:
  - subnet: "192.168.1.0/24"
    direction: REMOTE
  
  - subnet: "192.168.1.100/32"  # More specific
    direction: LOCAL
```

For `connect(192.168.1.100:445)`:
- Check route 1: yes, matches /24 → REMOTE
- Route 2 never checked

**Lesson:** Put specific routes BEFORE general ones.

**Correct:**

```yaml
net_routes:
  - subnet: "192.168.1.100/32"  # Specific first
    direction: LOCAL
  
  - subnet: "192.168.1.0/24"    # General after
    direction: REMOTE
```

### Port-Specific Rules

Port is optional. Omit for "any port".

```yaml
net_routes:
  # DNS: port 53 only
  - subnet: "8.8.8.8/32"
    port: 53
    direction: LOCAL
  
  # Same IP, port 443: not matched by DNS rule above
  - subnet: "8.8.8.8/32"
    port: 443
    direction: REMOTE
  
  # Same IP, port 22: not matched by DNS or 443 rule
  - subnet: "8.8.8.8/32"
    direction: LOCAL
```

**Matching logic:** If a route specifies a port, it only matches that port. If omitted, it matches any port.

### Default Route (0.0.0.0/0)

```yaml
net_routes:
  - subnet: "0.0.0.0/0"
    direction: LOCAL
```

Matches everything. Should typically be **last** to catch unmatched addresses.

---

## Interaction with Other Filters

### fd_range filter (still applies)

Even if a `connect()` matches a routing policy rule and says "LOCAL", it still needs:
- Valid virtual fd (if it's a beacon-owned socket)
- OR the syscall is declined by seccomp anyway

Example:
```yaml
forward:
  - name: network
    syscalls: [socket, connect]
    filter:
      net_routes:
        - subnet: "0.0.0.0/0"
          direction: LOCAL
```

**Result:** `socket()` and `connect()` are only trapped if args pass the seccomp filter (AF_INET, etc.). Non-AF_INET sockets fall through to kernel automatically (no routing needed).

### No conflict; routing is applied after syscall is trapped.

---

## Implementation Notes

### Parsing Routes

```rust
fn parse_route(route_str: &str) -> Result<(u32, u32, Option<u16>, RouteDirection)> {
    // Parse "10.0.0.1:443=local" or "192.168.1.0/24=remote"
    let (subnet_port, direction_str) = route_str
        .rsplit_once('=')
        .ok_or_else(|| anyhow!("route missing '=': {}", route_str))?;
    
    let direction = match direction_str.to_lowercase().as_str() {
        "local" => RouteDirection::Local,
        "remote" => RouteDirection::Remote,
        _ => bail!("invalid direction '{}', expected 'local' or 'remote'", direction_str),
    };
    
    let (subnet, port) = if let Some((s, p)) = subnet_port.rsplit_once(':') {
        let port = p.parse::<u16>()?;
        (s, Some(port))
    } else {
        (subnet_port, None)
    };
    
    let (addr, mask) = parse_cidr(subnet)?;
    Ok((addr, mask, port, direction))
}
```

### Lookup

```rust
pub fn lookup(&self, addr_be: u32, port: u16) -> RouteDirection {
    for (route_addr, route_mask, route_port, direction) in &self.routes {
        // Subnet match
        if (addr_be & route_mask) != (route_addr & route_mask) {
            continue;
        }
        // Port match (if specified)
        if let Some(rp) = route_port {
            if port != *rp {
                continue;
            }
        }
        return direction.clone();
    }
    RouteDirection::Local  // Default
}
```

### Syscall Integration (relay.rs)

```rust
if let Some(ref policy) = self.net_routing_policy {
    let direction = policy.lookup(addr_be, port_be);
    if direction == RouteDirection::Local {
        debug!(id, nr, addr = %addr_be, port = port_be, "routing: local");
        self.controller.continue_syscall(id).await?;
        return Ok(());
    }
    // Otherwise fall through to beacon forwarding
}
```

---

## Examples

### Example 1: Beacon + C2

```bash
rsc exec \
  --mount-profile relay \
  --beacon 192.168.1.100:9999 \
  --route "10.0.0.1:443=local" \
  --route "0.0.0.0/0=local" \
  -- ./sliver-beacon
```

**Behavior:**
- `connect(192.168.1.100:445)` → LOCAL (default, continues locally)
- `connect(10.0.0.1:443)` → LOCAL (explicit route)
- `connect(archive.ubuntu.com:443)` → LOCAL (default)

**Problem:** No traffic goes through beacon!

**Fix:** Put target subnets BEFORE default:

```bash
rsc exec \
  --mount-profile relay \
  --beacon 192.168.1.100:9999 \
  --route "192.168.1.0/24=remote" \
  --route "10.0.0.1:443=local" \
  --route "0.0.0.0/0=local" \
  -- ./sliver-beacon
```

**Behavior:**
- `connect(192.168.1.100:445)` → REMOTE (target subnet)
- `connect(10.0.0.1:443)` → LOCAL (C2 callback)
- `connect(archive.ubuntu.com:443)` → LOCAL (default)

✅ Works correctly.

---

### Example 2: YAML Profile

File: `rsc/profiles/shadow-routed.yaml`

```yaml
name: shadow-routed
description: "Shadow with routing: targets remote, C2+internet local"
mounts:
  - remote: /proc
    local: /proc
    type: bind
  - remote: /sys
    local: /sys
    type: bind
    optional: true
  - remote: /etc/hosts
    local: /etc/hosts
    type: bind
    optional: true
  - remote: /etc/resolv.conf
    local: /etc/resolv.conf
    type: bind
    optional: true

forward:
  - name: network-routed
    syscalls:
      - socket
      - connect
      - bind
      - listen
      - accept4
      - sendto
      - recvfrom
      - sendmsg
      - recvmsg
      - getsockopt
      - setsockopt
    filter:
      net_routes:
        # C2 server (highest priority)
        - subnet: "10.0.0.1/32"
          port: 443
          direction: LOCAL
        
        # Internal DNS/NTP
        - subnet: "10.0.0.0/8"
          direction: LOCAL
        
        # Target segment 1 (through beacon)
        - subnet: "192.168.1.0/24"
          direction: REMOTE
        
        # Target segment 2 (through beacon)
        - subnet: "10.0.0.0/8"
          direction: REMOTE
        
        # Default: everything else local
        - subnet: "0.0.0.0/0"
          direction: LOCAL
  
  - name: socket-fd-ops
    syscalls:
      - read
      - write
      - close
      - poll
      - ppoll
      - fcntl
      - ioctl
    filter:
      fd_range: virtual
```

---

## Future Extensions

### Port Range

```yaml
- subnet: "192.168.1.0/24"
  ports: "80,443,8080-8090"
  direction: REMOTE
```

### Protocol-Specific (TCP vs UDP)

```yaml
- subnet: "192.168.1.0/24"
  protocol: TCP
  direction: REMOTE

- subnet: "192.168.1.0/24"
  protocol: UDP
  direction: LOCAL
```

### Time-Based Rules

```yaml
- subnet: "192.168.1.0/24"
  direction: REMOTE
  after: "2026-08-01T00:00:00Z"
  before: "2026-08-02T00:00:00Z"
```

---

## Testing

Test cases:
1. No routes → all LOCAL (default safe).
2. Single route matching → correct direction.
3. Overlapping routes → first-match wins.
4. Port-specific + wildcard → port-specific checked first.
5. 0.0.0.0/0 catches unmatched.
6. Malformed routes rejected at parse time.

---

## References

- `rsc/src/mount_config.rs`: ForwardFilter parsing.
- `rsclient/src/relay.rs`: Routing policy lookup in dispatch loop.
- `rsc/src/exec.rs`: CLI argument parsing for `--route`.
