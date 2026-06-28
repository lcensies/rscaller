#!/usr/bin/env bash
# rscaller-specific observability helpers.
# Sources shared test_lib.sh and overrides print_events for exec events.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/test_lib.sh"

# Override: print only time, eventName, processName, parent, exe path
print_events() {
    local since_ns="$1"; shift
    local label="$*"
    local lines
    lines=$(loki_fetch_events "$since_ns" "$@")
    [[ -z "$lines" ]] && return 0
    echo -e "${YELLOW}  ── Tracee exec events for '${label}' ──${NC}"
    echo "$lines" | python3 -c "
import sys, json
for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    try:
        e = json.loads(line)
        ts       = e.get('timestamp', '')[:19]          # trim nanoseconds
        evt      = e.get('eventName', e.get('syscall', '?'))
        proc     = e.get('processName', '?')
        pid      = e.get('processId', '?')
        ppid     = e.get('parentProcessId', '?')
        # exe path lives in args list as 'pathname' or first arg value
        exe = ''
        for a in e.get('args', []):
            if a.get('name') in ('pathname', 'filename', 'argv'):
                exe = str(a.get('value', ''))[:60]
                break
        print(f'    {ts}  {evt:<10}  proc={proc}({pid})  parent={ppid}  exe={exe}')
    except Exception:
        print('    ' + line[:120])
" 2>/dev/null || echo "$lines" | head -20
    echo -e "${YELLOW}  ────────────────────────────────────────────────────${NC}"
}
