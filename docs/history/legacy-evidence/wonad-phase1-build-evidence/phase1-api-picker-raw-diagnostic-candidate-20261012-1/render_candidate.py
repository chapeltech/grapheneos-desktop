#!/usr/bin/env python3
"""Read pinned current source and print prospective snapshot. No repository writes."""
import hashlib
from pathlib import Path

SOURCE = Path('/u/elric/tree/wonad/android/tools/conformance_smoke.py')
SHA = 'd193c2641d3ceebb7bc498308181a4d0b02b0d0701544e343ad059b4917b3dd5'
raw = SOURCE.read_bytes()
if hashlib.sha256(raw).hexdigest() != SHA:
    raise ValueError('current conformance_smoke preimage changed')
source = raw.decode()
source = source.replace('import argparse\n', 'import argparse\nimport base64\nimport hashlib\nimport math\n', 1)
start = source.index('def cancel_focused_transfer_picker(')
end = source.index('\n\nclass Device:', start)
source = source[:start] + Path(__file__).with_name('picker_diagnostic_impl.fragment').read_text().rstrip() + source[end:]
needle = '    def call(self, *args: str, timeout: int = 30) -> str:\n'
if source.count(needle) != 1:
    raise ValueError('Device.call single preimage absent')
source = source.replace(needle, needle + '        journal = getattr(self, "_picker_diagnostics", None)\n        if journal is not None:\n            return journal.call(self.prefix + list(args), timeout)\n', 1)
print(source, end='')
