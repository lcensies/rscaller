# rscaller docs

| Doc | Contents |
|---|---|
| [ARCHITECTURE.md](ARCHITECTURE.md) | Crate layout, controller backends (seccomp/kmod), data flow, wire protocol |
| [network_syscalls.md](network_syscalls.md) | Per-syscall handling matrix: profile → rsclient → meta → beacon → smoltcp; known gaps |
| [qemu-relay.md](qemu-relay.md) | QEMU relay mode: relay profiles, guest image contract, host requirements |
| [design/CAPTURE.md](design/CAPTURE.md) | Why the capture mechanism is what it is: kmod → seccomp-unotify → FUSE/ADDFD trade-offs |
| [design/NETWORK_ROUTING.md](design/NETWORK_ROUTING.md) | Network routing policy model, profile inheritance, `--route` CLI |

Top-level [README](../README.md): build/deploy/run, mount profiles, PoC and test workflows.
[AGENTS.md](../AGENTS.md): kernel-compat notes, VM topology, hard-won pitfalls (contributor-facing).
