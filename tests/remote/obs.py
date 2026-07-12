"""
obs.py — thin observability helpers for rscaller integration tests.

Only one abstraction: Tracee, which runs tracee via Docker on a remote host,
collects JSON events, and lets you query them.

Usage:
    from obs import Tracee
    from conftest import run

    t = Tracee(run_fn=lambda cmd: run(host, cmd), events=["execve", "execveat"])
    t.start()
    # ... do work ...
    events = t.stop()   # list[dict], one per tracee JSON event

    matches = t.execve_matches(events, pattern="ip")
    assert not matches, f"unexpected execve on victim: {matches}"
"""
from __future__ import annotations

import json
import time
from typing import Callable


# Docker image used everywhere; pin to a digest for reproducibility if needed.
TRACEE_IMAGE = "aquasec/tracee:latest"
CONTAINER_NAME = "tracee-obs"

# Mounts required by tracee to access kernel BTF / modules / security FS.
_TRACEE_VOLUMES = " ".join([
    "-v /etc/os-release:/etc/os-release-host:ro",
    "-v /boot:/boot:ro",
    "-v /lib/modules:/lib/modules:ro",
    "-v /usr/src:/usr/src:ro",
    "-v /sys/kernel/security:/sys/kernel/security:ro",
    "-v /tmp/tracee:/tmp/tracee",
])


class Tracee:
    """
    Wrapper around tracee running in Docker on a remote host.

    Args:
        run_fn:  callable(cmd: str) → result with .ok / .stdout / .stderr
        events:  list of tracee event names to capture (default: execve, execveat)
        name:    Docker container name (must be unique per host)
    """

    def __init__(
        self,
        run_fn: Callable,
        events: list[str] | None = None,
        name: str = CONTAINER_NAME,
    ):
        self._run = run_fn
        self._events = ",".join(events or ["execve", "execveat"])
        self._name = name

    def ensure_image(self) -> None:
        r = self._run(f"sudo docker inspect {TRACEE_IMAGE} >/dev/null 2>&1 || "
                      f"sudo docker pull {TRACEE_IMAGE} 2>&1 | tail -3")
        if not r.ok:
            raise RuntimeError(f"Could not pull tracee image: {r.stderr}")

    def start(self, settle_secs: float = 2.0) -> None:
        """Start tracee container; wait briefly for eBPF probes to load."""
        self._run(f"sudo docker rm -f {self._name} 2>/dev/null || true")
        cmd = (
            f"sudo docker run -d --name {self._name} "
            f"--privileged --pid=host --cgroupns=host "
            f"{_TRACEE_VOLUMES} "
            f"{TRACEE_IMAGE} "
            f"-e {self._events} "
            f"-o json"
        )
        r = self._run(cmd)
        if not r.ok:
            raise RuntimeError(f"Failed to start tracee container: {r.stderr}")
        time.sleep(settle_secs)

    def stop(self) -> list[dict]:
        """Stop tracee container and return all captured events as a list of dicts."""
        # Capture stdout+stderr: tracee emits JSON on stdout but startup noise on stderr.
        r = self._run(f"sudo docker logs {self._name} 2>&1")
        raw = r.stdout if r.ok else ""
        self._run(f"sudo docker rm -f {self._name} 2>/dev/null || true")
        return _parse_events(raw)

    # ── Event predicates ──────────────────────────────────────────────────────

    @staticmethod
    def execve_matches(events: list[dict], pattern: str) -> list[dict]:
        """
        Return events where the executed binary or process name contains `pattern`.

        Checks:
          - processName field
          - the 'pathname' / 'filename' argument (first arg to execve)
        """
        pattern = pattern.lower()
        matched = []
        for e in events:
            if pattern in e.get("processName", "").lower():
                matched.append(e)
                continue
            for arg in e.get("args", []):
                if arg.get("name") in ("pathname", "filename"):
                    if pattern in str(arg.get("value", "")).lower():
                        matched.append(e)
                        break
        return matched

    @staticmethod
    def format_event(e: dict) -> str:
        # timestamp is a nanosecond integer in tracee JSON; convert before slicing.
        ts = str(e.get("timestamp", ""))[:19]
        name = e.get("eventName", e.get("syscall", "?"))
        proc = e.get("processName", "?")
        pid = e.get("processId", "?")
        exe = next(
            (str(a.get("value", ""))[:80]
             for a in e.get("args", [])
             if a.get("name") in ("pathname", "filename")),
            "",
        )
        return f"{ts}  {name:<12}  proc={proc}({pid})  exe={exe}"


# ── Internals ─────────────────────────────────────────────────────────────────

def _parse_events(raw: str) -> list[dict]:
    events = []
    for line in raw.splitlines():
        line = line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError:
            pass
    return events
