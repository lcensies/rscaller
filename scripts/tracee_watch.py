#!/usr/bin/env python3
"""
tracee_watch.py — pretty-print tracee exec events streamed from a remote Docker container.

Usage:
    python3 scripts/tracee_watch.py [beacon_vm] [container]

Defaults:
    beacon_vm  = dev-vm-2
    container  = tracee-ghost
"""

import json
import shlex
import subprocess
import sys
from datetime import datetime, timezone


# ── ANSI colours ──────────────────────────────────────────────────────────────
RESET  = "\033[0m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
RED    = "\033[31m"
GREEN  = "\033[32m"
YELLOW = "\033[33m"
CYAN   = "\033[36m"
WHITE  = "\033[37m"


def _arg(args: list, name: str):
    for a in args:
        if a.get("name") == name:
            return a.get("value")
    return None


def format_event(ev: dict) -> str:
    ts_ns  = ev.get("timestamp", 0)
    ts     = datetime.fromtimestamp(ts_ns / 1e9, tz=timezone.utc).strftime("%H:%M:%S.%f")[:12]
    event  = ev.get("eventName", "?")
    proc   = ev.get("processName", "?")
    pid    = ev.get("hostProcessId", ev.get("processId", "?"))
    ppid   = ev.get("hostParentProcessId", ev.get("parentProcessId", "?"))
    uid    = ev.get("userId", "?")
    args   = ev.get("args", [])

    pathname = _arg(args, "pathname") or ""
    argv     = _arg(args, "argv") or []

    if argv:
        cmd = " ".join(shlex.quote(str(a)) for a in argv[:6])
    elif pathname:
        cmd = pathname
    else:
        cmd = "?"

    uid_str = f"{GREEN}root{RESET}" if uid == 0 else f"{DIM}{uid}{RESET}"

    return (
        f"{DIM}{ts}{RESET}  "
        f"{CYAN}pid={pid:<6}{RESET} "
        f"{DIM}ppid={ppid:<6}{RESET} "
        f"uid={uid_str:<4}  "
        f"{BOLD}{proc:<16}{RESET}  "
        f"{YELLOW}{event:<10}{RESET}  "
        f"{cmd}"
    )


def start_tracee(beacon_vm: str, container: str, image: str) -> None:
    """Start the tracee Docker container on the remote beacon VM."""
    volumes = " ".join([
        "-v /etc/os-release:/etc/os-release-host:ro",
        "-v /boot:/boot:ro",
        "-v /lib/modules:/lib/modules:ro",
        "-v /usr/src:/usr/src:ro",
        "-v /sys/kernel/security:/sys/kernel/security:ro",
        "-v /tmp/tracee:/tmp/tracee",
    ])
    cmd = (
        f"sudo docker rm -f {container} 2>/dev/null || true; "
        f"sudo docker run -d --name {container} "
        f"--privileged --pid=host --cgroupns=host "
        f"{volumes} "
        f"{image} "
        f"-e execve,execveat "
        f"-o json"
    )
    result = subprocess.run(
        ["ssh", beacon_vm, cmd],
        capture_output=True, text=True
    )
    if result.returncode != 0:
        print(f"[tracee-watch] failed to start container: {result.stderr}", file=sys.stderr)
        sys.exit(1)
    print(f"[tracee-watch] container started, waiting 4s for eBPF probes to load…", flush=True)
    import time; time.sleep(4)


def stream(beacon_vm: str, container: str) -> None:
    """Stream and pretty-print exec events from the container logs."""
    print(
        f"{BOLD}{'TIME':12}  {'PID':<10} {'PPID':<10} {'UID':<9}  "
        f"{'PROCESS':<16}  {'EVENT':<10}  COMMAND{RESET}",
        flush=True,
    )
    print("-" * 100, flush=True)

    cmd = ["ssh", beacon_vm, f"sudo docker logs -f --tail=0 {container}"]
    with subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True) as proc:
        for line in proc.stdout or []:
            line = line.strip()
            if not line:
                continue
            try:
                ev = json.loads(line)
                print(format_event(ev), flush=True)
            except json.JSONDecodeError:
                print(f"{DIM}[raw] {line}{RESET}", flush=True)
            except Exception as e:
                print(f"{RED}[err] {e}: {line[:80]}{RESET}", flush=True)


def main() -> None:
    beacon_vm = sys.argv[1] if len(sys.argv) > 1 else "dev-vm-2"
    container = sys.argv[2] if len(sys.argv) > 2 else "tracee-ghost"
    image     = sys.argv[3] if len(sys.argv) > 3 else "aquasec/tracee:latest"

    # Check if container already running; start if not.
    check = subprocess.run(
        ["ssh", beacon_vm, f"sudo docker inspect --format '{{{{.State.Running}}}}' {container} 2>/dev/null"],
        capture_output=True, text=True
    )
    if check.stdout.strip() != "true":
        print(f"[tracee-watch] container '{container}' not running on {beacon_vm}, starting…", flush=True)
        start_tracee(beacon_vm, container, image)
    else:
        print(f"[tracee-watch] attaching to existing '{container}' on {beacon_vm}", flush=True)

    try:
        stream(beacon_vm, container)
    except KeyboardInterrupt:
        print(f"\n{DIM}[tracee-watch] stopped{RESET}")


if __name__ == "__main__":
    main()
