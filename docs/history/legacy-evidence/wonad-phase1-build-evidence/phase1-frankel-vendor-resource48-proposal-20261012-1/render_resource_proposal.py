#!/usr/bin/env python3
"""Print a prospective resource-only successor; never write or launch anything."""
import difflib
import hashlib
from pathlib import Path
import sys

BASE = Path('/u/elric/tree/wonad-phase1-build-evidence/phase1-frankel-vendor-terminal-outcome-candidate-20261012-1/candidate/run_frankel_vendor.py')
BASE_SHA = '3c26be80b3f5bb0bbc747811e9d4f40780800897211ad559632193e96bbb5d05'

OLD_MEMORY = '''# The measured generation-7 Soong graph saturated 32 GiB and spent substantial
# time reclaiming. Keep a fixed larger cap/no extra swap; the admission floor
# rises with the hard limit. Upstream clears the graph builder's environment,
# so exporting GOMEMLIMIT would not establish a heap bound for that process.
MEMORY = 40 * 1024**3
'''
NEW_MEMORY = '''# The retained generation-8 builder was OOM-killed under the fixed 40 GiB
# cap. This proposed 48 GiB/no-extra-swap profile is not a measured peak or a
# success guarantee. Admission observes >=48 GiB physical RAM and >=42 GiB
# currently available RAM; it does not reserve either. Upstream clears the
# graph builder's environment, so GOMEMLIMIT is not a runtime heap bound here.
MEMORY = 48 * 1024**3
MIN_MEM_AVAILABLE = 42 * 1024**3
'''
OLD_RESOURCE = '''    available = None
    for line in Path("/proc/meminfo").read_text().splitlines():
        if line.startswith("MemAvailable:"):
            fields = line.split()
            require(len(fields) == 3 and fields[2] == "kB", "Invalid MemAvailable unit")
            available = int(fields[1]) * 1024
    require(available is not None and available >= MEMORY,
            f"Vendor preparation needs >=40 GiB MemAvailable; observed {available}")
'''
NEW_RESOURCE = '''    lines = Path("/proc/meminfo").read_text(encoding="ascii").splitlines()
    memory = {}
    for name in ("MemTotal", "MemAvailable"):
        rows = [line for line in lines if line.startswith(name + ":")]
        require(len(rows) == 1, f"Host memory lacks unique {name} observation")
        match = re.fullmatch(name + r":\\s+([0-9]+)\\s+kB", rows[0], re.ASCII)
        require(match is not None, f"Invalid {name} decimal/unit observation")
        value = int(match.group(1)) * 1024
        require(value > 0, f"Invalid non-positive {name} observation")
        memory[name] = value
    total, available = memory["MemTotal"], memory["MemAvailable"]
    require(available <= total, "Host MemAvailable exceeds physical MemTotal")
    require(total >= MEMORY,
            f"Vendor preparation needs >=48 GiB physical MemTotal; observed {total}")
    require(available >= MIN_MEM_AVAILABLE,
            f"Vendor preparation needs >=42 GiB MemAvailable; observed {available}")
'''
OLD_RETURN = '    return {"mem_available_bytes": available, "source_and_work_free_bytes": free,\n'
NEW_RETURN = '    return {"mem_total_bytes": total, "mem_available_bytes": available,\n            "source_and_work_free_bytes": free,\n'

def candidate_bytes():
    original = BASE.read_bytes()
    if hashlib.sha256(original).hexdigest() != BASE_SHA:
        raise ValueError('Frozen terminal candidate changed')
    source = original.decode('utf-8')
    for old, new in ((OLD_MEMORY, NEW_MEMORY), (OLD_RESOURCE, NEW_RESOURCE),
                     (OLD_RETURN, NEW_RETURN)):
        if source.count(old) != 1:
            raise ValueError('Exact resource-only source anchor changed')
        source = source.replace(old, new, 1)
    compile(source, '/u/elric/tree/wonad/android/tools/run_frankel_vendor.py', 'exec')
    return source.encode('utf-8')

def main():
    candidate = candidate_bytes()
    if sys.argv[1:] == ['--patch']:
        before = BASE.read_text().splitlines(keepends=True)
        after = candidate.decode('utf-8').splitlines(keepends=True)
        sys.stdout.write(''.join(difflib.unified_diff(before, after,
            fromfile='terminal-candidate/android/tools/run_frankel_vendor.py',
            tofile='resource48-proposal/android/tools/run_frankel_vendor.py')))
    elif not sys.argv[1:]:
        sys.stdout.buffer.write(candidate)
    else:
        raise ValueError('Only stdout rendering or --patch is supported')

if __name__ == '__main__':
    main()
