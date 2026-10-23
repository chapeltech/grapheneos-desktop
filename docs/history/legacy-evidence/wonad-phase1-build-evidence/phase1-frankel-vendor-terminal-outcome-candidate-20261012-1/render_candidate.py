#!/usr/bin/env python3
"""Print proposed full tool bytes; never edit the repository or execute its lifecycle."""
import hashlib
from pathlib import Path

SOURCE = Path('/u/elric/tree/wonad/android/tools/run_frankel_vendor.py')
SHA = 'fa249edee74eb0c48e1a340cebad1496c25df659f69af0f6d237d8147a7bbe0b'
payload = SOURCE.read_bytes()
if hashlib.sha256(payload).hexdigest() != SHA:
    raise ValueError('current vendor runner preimage changed')
source = payload.decode()
def once(old, new):
    global source
    if source.count(old) != 1: raise ValueError('exact single preimage absent')
    source = source.replace(old, new)

once('''                state.get("Dead") is False and state.get("Pid") == 0 and
                state.get("OOMKilled") is False and isinstance(state.get("ExitCode"), int) and
                state.get("StartedAt") not in (None, "0001-01-01T00:00:00Z") and
                state.get("FinishedAt") not in (None, "0001-01-01T00:00:00Z"),''',
'''                state.get("Dead") is False and type(state.get("Pid")) is int and
                state.get("Pid") == 0 and type(state.get("OOMKilled")) is bool and
                type(state.get("ExitCode")) is int and
                isinstance(state.get("StartedAt"), str) and
                state["StartedAt"] not in ("", "0001-01-01T00:00:00Z") and
                isinstance(state.get("FinishedAt"), str) and
                state["FinishedAt"] not in ("", "0001-01-01T00:00:00Z"),''')

once('def source_cleanup_is_safe(create_attempted, container_identity, authoritatively_stopped):',
'''def require_successful_stopped_build(primary_exit, stopped, stopped_inspect):
    """Build success is separate from exact terminal-state authority to clean caches."""
    require(stopped is True and isinstance(stopped_inspect, dict) and
            type(primary_exit) is int and primary_exit == 0 and
            type(stopped_inspect.get("exit_code")) is int and
            stopped_inspect["exit_code"] == 0 and
            stopped_inspect.get("oom_killed") is False,
            "Vendor generation requires proven stopped zero exit without OOM")


def source_cleanup_is_safe(create_attempted, container_identity, authoritatively_stopped):''')
once('''            if status == "generated":
                try:
                    generated = verify_generated_vendor(config)''',
'''            if status == "generated":
                try:
                    require_successful_stopped_build(primary_exit, stopped, stopped_inspect_ref)
                    generated = verify_generated_vendor(config)''')
print(source, end='')
