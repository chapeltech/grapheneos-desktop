#!/usr/bin/python3
"""Check compiled target-files resources, not just source overlay declarations."""
from pathlib import Path
from tempfile import TemporaryDirectory
from zipfile import ZipFile
import re
import shutil
import subprocess
import sys

from source import PINS


def check(archive, work):
    expectations = {"Updater.apk": ("url", PINS["update_url"]),
        "framework-res.apk": ("config_externalDesktopControllerPackage", None),
        "SystemUI.apk": ("config_externalDesktopControllerCerts", None)}
    with ZipFile(archive) as z:
        for apk, (name, expected) in expectations.items():
            files = [n for n in z.namelist() if n.endswith("/"+apk) and n.split("/")[0] in
                     ("SYSTEM", "SYSTEM_EXT", "PRODUCT")]
            if len(files) != 1:
                raise ValueError("missing or ambiguous " + apk)
            local = work / apk
            with z.open(files[0]) as src, local.open("wb") as dst:
                shutil.copyfileobj(src, dst)
            dump = subprocess.check_output(["aapt2","dump","resources",local],text=True)
            blocks = re.split(r"(?m)^\s*resource 0x",dump)
            selected = [b for b in blocks if b and
                        re.search(r"(?:string|array)/"+name+r"(?:\s|$)",b.splitlines()[0])]
            if expected is None:
                if selected:
                    raise ValueError("legacy controller trust resource in release: " + name)
            elif len(selected) != 1 or expected not in selected[0]:
                raise ValueError("release resource mismatch: " + name)


if __name__ == "__main__":
    with TemporaryDirectory() as tmp:
        check(sys.argv[1],Path(tmp))
