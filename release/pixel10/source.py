#!/usr/bin/python3
"""Select only commits whose parent matches the corresponding signed manifest project."""
import json
from pathlib import Path
import subprocess
import sys
import xml.etree.ElementTree as ET

HERE = Path(__file__).resolve().parent
PINS = json.loads((HERE / "pins.json").read_text())


def git(directory, *args):
    return subprocess.check_output(["git", "-C", directory, *args], text=True).strip()


def prepare(root):
    manifest = root / ".repo/manifests"
    tag = PINS["release"]
    git(manifest, "-c", "gpg.ssh.allowedSignersFile=" + str(HERE.parents[1] /
        "android/platform/allowed_signers"), "verify-tag", tag)
    if (git(manifest, "rev-parse", "HEAD") != PINS["manifest"] or
            git(manifest, "rev-parse", "refs/tags/" + tag) != PINS["manifest_tag"] or
            git(manifest, "rev-parse", tag + "^{commit}") != PINS["manifest"]):
        raise ValueError("release manifest differs from reviewed tag")
    projects = ET.fromstring(git(manifest, "show", "HEAD:default.xml"))
    for path, (name, commit) in PINS["forks"].items():
        project = projects.find(f"project[@path='{path}']")
        base = project.attrib["revision"]
        dest = root / path
        if git(dest, "rev-parse", "HEAD") != base or git(dest, "status", "--porcelain"):
            raise ValueError(f"{path} is not the pristine upstream project")
        git(dest, "fetch", "--no-tags", "--depth=2", "https://github.com/chapeltech/" + name, commit)
        if git(dest, "rev-parse", commit + "^") != base:
            raise ValueError(f"{path} not based on selected release")
        git(dest, "checkout", "--detach", commit)


def configure(root, controller_pin):
    import re
    if not re.fullmatch(r"[0-9a-f]{64}", controller_pin):
        raise ValueError("expected the offline controller's public SHA-256 pin")
    # Dedicated frankel-only source tree. Product-specific values do not live in the forks.
    changes = [
        ("packages/apps/Updater/res/values/config.xml",
         "https://releases.grapheneos.org/", PINS["update_url"]),
        ("frameworks/base/core/res/res/values/config_external_desktop.xml",
         'translatable="false"></string>', 'translatable="false">org.wonad.desktop</string>'),
        ("frameworks/base/packages/SystemUI/res/values/config_external_desktop.xml",
         'translatable="false" />', f'translatable="false"><item>{controller_pin}</item></string-array>')]
    for name, old, new in changes:
        path = root / name
        data = path.read_text()
        if data.count(old) != 1:
            raise ValueError(f"review changed resource: {name}")
        path.write_text(data.replace(old, new))


if __name__ == "__main__":
    root = Path.cwd()
    prepare(root)
    configure(root, sys.argv[1])
