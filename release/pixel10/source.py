#!/usr/bin/python3
"""Select downstream platform changes on the authenticated release manifest."""
import json
from pathlib import Path
import subprocess
import xml.etree.ElementTree as ET

HERE = Path(__file__).resolve().parent
PINS = json.loads((HERE / "pins.json").read_text())


def git(directory, *args):
    return subprocess.check_output(["git", "-C", directory, *args], text=True).strip()


def settings_patch(root, projects):
    """Prepare a resource-only patch against its reviewed, pristine upstream Settings."""
    path = "packages/apps/Settings"
    project = projects.find(f"project[@path='{path}']")
    revision = PINS["settings_revision"]
    dest = root / path
    if project is None or project.get("revision") != revision:
        raise ValueError("Settings patch needs review for this manifest")
    if git(dest, "rev-parse", "HEAD") != revision or git(dest, "status", "--porcelain"):
        raise ValueError("Settings is not the pristine upstream project")
    args = ["--whitespace=error", str(HERE / "settings-external-desktop.patch")]
    git(dest, "apply", "--check", *args)
    return dest, args


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
    settings, patch = settings_patch(root, projects)
    for path, (name, commit) in PINS["forks"].items():
        project = projects.find(f"project[@path='{path}']")
        base = project.attrib["revision"]
        dest = root / path
        if git(dest, "rev-parse", "HEAD") != base or git(dest, "status", "--porcelain"):
            raise ValueError(f"{path} is not the pristine upstream project")
        git(dest, "fetch", "--no-tags", "--depth=16", "https://github.com/chapeltech/" + name, commit)
        git(dest, "merge-base", "--is-ancestor", base, commit)
        git(dest, "checkout", "--detach", commit)
    git(settings, "apply", *patch)


def configure(root):
    path = root / "packages/apps/Updater/res/values/config.xml"
    upstream = "https://releases.grapheneos.org/"
    data = path.read_text()
    if data.count(upstream) != 1:
        raise ValueError("review changed Updater configuration")
    path.write_text(data.replace(upstream, PINS["update_url"]))


if __name__ == "__main__":
    root = Path.cwd()
    prepare(root)
    configure(root)
