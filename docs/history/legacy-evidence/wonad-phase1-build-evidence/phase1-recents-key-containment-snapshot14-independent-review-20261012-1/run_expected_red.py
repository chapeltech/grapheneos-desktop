#!/usr/bin/env python3
"""Compile and reproduce bounded expected REDs against immutable snapshot 14."""

from __future__ import annotations

import os
from pathlib import Path
import subprocess
import tempfile


HERE = Path(__file__).resolve().parent
SNAPSHOT = Path(
    "/u/elric/tree/wonad-phase1-build-evidence/"
    "phase1-recents-key-containment-kotlin-prototype-20261012-snapshot-14-review"
)
STAGE = Path("/u/elric/tree/wonad-grapheneos-2026100600-phase1-custom-7")
KOTLIN = STAGE / "external/kotlinc/bin/kotlinc"
JAVA_HOME = STAGE / "prebuilts/jdk/jdk21/linux-x86"
JAVA = JAVA_HOME / "bin/java"


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


def compile_jar(output: Path, *sources: Path) -> None:
    result = run([
        str(KOTLIN),
        "-J-Xmx256m",
        "-include-runtime",
        *(str(path) for path in sources),
        "-d",
        str(output),
    ])
    if result.returncode != 0:
        raise SystemExit(f"compile failed ({result.returncode})\n{result.stdout}")


def expected_red(jar: Path, main: str, required: tuple[str, ...]) -> str:
    result = run([str(JAVA), "-Xmx128m", "-cp", str(jar), main])
    if result.returncode == 0:
        raise SystemExit(f"expected RED unexpectedly passed: {main}\n{result.stdout}")
    missing = [token for token in required if token not in result.stdout]
    if missing:
        raise SystemExit(
            f"expected RED output missing {missing}: {main}\n{result.stdout}")
    return result.stdout


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="wonad-snapshot14-red-") as raw:
        temp = Path(raw)
        helper_jar = temp / "helper-red.jar"
        compile_jar(
            helper_jar,
            SNAPSHOT / "candidate/WonadPolicyKeyContainment.kt",
            HERE / "Snapshot14HelperRedTest.kt",
        )
        helper = expected_red(
            helper_jar,
            "org.wonad.server.input.Snapshot14HelperRedTestKt",
            (
                "ordinary-stock-down-claimed-up",
                "system-stock-down-claimed-up",
                "barrier-down-cleared-up",
                "drain-overflow-current-event",
            ),
        )

        adapter_jar = temp / "adapter-red.jar"
        stubs = sorted((SNAPSHOT / "tests/stubs").rglob("*.kt"))
        compile_jar(
            adapter_jar,
            SNAPSHOT / "candidate/WonadPolicyKeyContainment.kt",
            SNAPSHOT / "candidate/WonadPolicyKeyAdapter.kt",
            *stubs,
            HERE / "Snapshot14AdapterRedTest.kt",
        )
        adapter = expected_red(
            adapter_jar,
            "org.wonad.server.input.Snapshot14AdapterRedTestKt",
            (
                "focus-null-down-focused-up",
                "handled-history-saturates-foreign-unhandled",
                "no-fallback-history-saturates-foreign-unhandled",
            ),
        )

    print(helper, end="")
    print(adapter, end="")
    print("SNAPSHOT14_EXPECTED_RED_REPRODUCED cases=7")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
