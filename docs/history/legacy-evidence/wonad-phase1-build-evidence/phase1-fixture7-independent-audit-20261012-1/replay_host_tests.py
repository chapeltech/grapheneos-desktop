#!/usr/bin/python3
"""Replay unchanged24 fixture7 tests with only historical OUT freshness mocked."""
import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

DRIVER = Path('/u/elric/tree/wonad-phase1-build-evidence/phase1-keyboard-capture-fixture7-build-driver-20261012-1')
sys.dont_write_bytecode = True
sys.path.insert(0,str(DRIVER))
import build_fixture7 as V
import test_build_fixture7 as T

with tempfile.TemporaryDirectory(prefix='wonad-fixture7-host-replay-') as directory:
    # Existing actual fixture7 output is never deleted/reused. The only
    # substitution is a new, absent OUT in the proposal test's host-only seam.
    with mock.patch.object(V,'OUT',Path(directory)/'fresh-fixture7-output'):
        result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromModule(T))
raise SystemExit(0 if result.wasSuccessful() else 1)
