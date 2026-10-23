#!/usr/bin/env python3
"""Read-only successor renderer; preserve frozen v2, stock callers and source7 bytes."""
import difflib
import hashlib
import json
import runpy
from pathlib import Path

V2 = Path('/u/elric/tree/wonad-phase1-build-evidence/phase1-recents-authoritative-focus-routing-proposal-20261012-2')
freeze = V2 / 'freeze-review.json'
if hashlib.sha256(freeze.read_bytes()).hexdigest() != 'b341e7f566d92555d43db581e476a0fa707b3fd8cd3c970a4483128d1c125f90':
    raise ValueError('preserved v2 freeze changed')
inventory = {row['path']: row for row in json.loads(freeze.read_text())['files']}
for name in ['tests/render_wiring_patch.py', 'wiring/platform-wiring.patch']:
    data = (V2 / name).read_bytes()
    if len(data) != inventory[name]['bytes'] or hashlib.sha256(data).hexdigest() != inventory[name]['sha256']:
        raise ValueError('preserved v2 renderer/patch changed')
value = runpy.run_path(str(V2 / 'tests/render_wiring_patch.py'))
once = value['once']
snapshots = dict(value['snapshots'])
path = 'packages/apps/Launcher3/quickstep/src/com/android/quickstep/OverviewCommandHelper.kt'
old, new = snapshots[path]

def method(source, signature):
    start = source.index(signature)
    opening = source.index('{', start)
    end, depth = opening + 1, 1
    while depth:
        if source[end] == '{': depth += 1
        elif source[end] == '}': depth -= 1
        end += 1
    return source[start:end]

new = once(new, '                    if (continuation.isActive) continuation.resume(Unit)',
    '                    if (!command.hasExecutionGuard() || continuation.isActive)\n                        continuation.resume(Unit)')
new = once(new, '        fun isExecutionAllowed(): Boolean = try { executionGuard?.invoke() ?: true }',
    '        fun hasExecutionGuard(): Boolean = executionGuard != null\n        fun isExecutionAllowed(): Boolean = try { executionGuard?.invoke() ?: true }')
guarded = ('        recentsView.keyboardFocusTaskView.requestFocus(command) ||\n'
           '            recentsView.nextTaskView.requestFocus(command) ||\n'
           '            recentsView.firstTaskView.requestFocus(command) ||\n'
           '            recentsView.requestFocus(command)')
stock = ('        recentsView.keyboardFocusTaskView.requestFocus() ||\n'
         '            recentsView.nextTaskView.requestFocus() ||\n'
         '            recentsView.firstTaskView.requestFocus() ||\n'
         '            recentsView.requestFocus()')
assert stock in old
new = once(new, guarded, '        if (command.hasExecutionGuard()) {\n' +
    '\n'.join('    ' + line for line in guarded.splitlines()) + '\n        } else {\n' +
    '\n'.join('    ' + line for line in stock.splitlines()) + '\n        }')
guarded_extension = method(new, '    private fun View?.requestFocus(command: CommandInfo): Boolean')
stock_extension = method(old, '    private fun View?.requestFocus(): Boolean')
checked_extension = once(guarded_extension, '        post {', '        return post {')
checked_extension = once(checked_extension, '\n        return true\n    }', '\n    }')
new = once(new, guarded_extension, stock_extension + '\n\n' + checked_extension)
snapshots[path] = old, new
patches = []
for path, (old, new) in snapshots.items():
    patches.extend(difflib.unified_diff(old.splitlines(True), new.splitlines(True),
        fromfile='a/' + path, tofile='b/' + path))
if __name__ == '__main__': print(''.join(patches), end='')
