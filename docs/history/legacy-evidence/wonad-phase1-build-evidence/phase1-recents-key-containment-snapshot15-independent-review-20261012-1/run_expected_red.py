#!/usr/bin/env python3
"""Compile and reproduce the bounded snapshot-15 stale-authority RED."""

from __future__ import annotations

import os
from pathlib import Path
import subprocess
import tempfile


HERE = Path(__file__).resolve().parent
SNAPSHOT = Path(
    "/u/elric/tree/wonad-phase1-build-evidence/"
    "phase1-recents-key-containment-kotlin-prototype-20261012-snapshot-15-review"
)
STAGE = Path("/u/elric/tree/wonad-grapheneos-2026100600-phase1-custom-7")
KOTLIN = STAGE / "external/kotlinc/bin/kotlinc"
JAVA_HOME = STAGE / "prebuilts/jdk/jdk21/linux-x86"
JAVA = JAVA_HOME / "bin/java"
REQUIRED = (
    "retired-marker-suppresses-fresh-stock-unhandled",
    "retired-marker-authorizes-fresh-stock-fallback",
)


def run(argv: list[str]) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env.update({
        "JAVA_HOME": str(JAVA_HOME),
        "PATH": f"{JAVA_HOME / 'bin'}:{env.get('PATH', '')}",
        "PYTHONDONTWRITEBYTECODE": "1",
    })
    return subprocess.run(
        argv,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=90,
        check=False,
    )


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="wonad-snapshot15-red-") as raw:
        jar = Path(raw) / "adapter-red.jar"
        stubs = sorted((SNAPSHOT / "tests/stubs").rglob("*.kt"))
        compile_result = run([
            str(KOTLIN),
            "-J-Xmx256m",
            "-include-runtime",
            str(SNAPSHOT / "candidate/WonadPolicyKeyContainment.kt"),
            str(SNAPSHOT / "candidate/WonadPolicyKeyAdapter.kt"),
            *(str(path) for path in stubs),
            str(HERE / "Snapshot15AdapterRedTest.kt"),
            "-d",
            str(jar),
        ])
        if compile_result.returncode != 0:
            raise SystemExit(
                f"compile failed ({compile_result.returncode})\n"
                f"{compile_result.stdout}")

        result = run([
            str(JAVA),
            "-Xmx128m",
            "-cp",
            str(jar),
            "org.wonad.server.input.Snapshot15AdapterRedTestKt",
        ])
        if result.returncode == 0:
            raise SystemExit(
                "expected RED unexpectedly passed\n" + result.stdout)
        missing = [token for token in REQUIRED if token not in result.stdout]
        if missing:
            raise SystemExit(
                f"expected RED output missing {missing}\n{result.stdout}")

    print(result.stdout, end="")
    print("SNAPSHOT15_EXPECTED_RED_REPRODUCED cases=2")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
