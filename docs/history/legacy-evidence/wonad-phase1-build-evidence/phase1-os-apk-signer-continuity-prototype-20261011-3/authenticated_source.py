#!/usr/bin/env python3
"""Load one exact Python source snapshot without reopening its pathname."""

from __future__ import annotations

import hashlib
from pathlib import Path
from types import ModuleType


class AuthenticatedSourceError(RuntimeError):
    pass


def load_authenticated_module(
    path: Path, expected_sha256: str, module_name: str
) -> ModuleType:
    """Hash, compile, and execute the same captured bytes in an isolated module.

    `SourceFileLoader.exec_module` reopens a pathname after a caller hashes it.
    This helper instead retains the one read result, authenticates that byte
    string, compiles that exact byte string, and never inserts the result into
    `sys.modules`.  `__file__` and `__package__` are supplied for reviewed
    source that resolves adjacent evidence paths or has ordinary imports.
    """
    if not isinstance(path, Path):
        raise AuthenticatedSourceError("source path must be a pathlib.Path")
    if type(expected_sha256) is not str or len(expected_sha256) != 64:
        raise AuthenticatedSourceError("expected SHA-256 must be a 64-character string")
    if type(module_name) is not str or not module_name:
        raise AuthenticatedSourceError("module name must be a non-empty string")

    source = path.read_bytes()
    observed = hashlib.sha256(source).hexdigest()
    if observed != expected_sha256:
        raise AuthenticatedSourceError(
            f"authenticated source identity changed: expected {expected_sha256}, "
            f"observed {observed}"
        )

    filename = str(path)
    code = compile(source, filename, "exec", dont_inherit=True)
    module = ModuleType(module_name)
    module.__file__ = filename
    module.__package__ = module_name.rpartition(".")[0]
    module.__loader__ = None
    module.__spec__ = None
    exec(code, module.__dict__)
    return module
