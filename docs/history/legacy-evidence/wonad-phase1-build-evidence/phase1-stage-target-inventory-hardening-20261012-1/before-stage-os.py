#!/usr/bin/env python3
"""Stage owned Wonad sources and the narrow framework patch into the pinned OS.

The caller supplies an ordinary public signing certificate, never a private key.
Refuses foreign/edited staging files and independently changed framework files.
Does not install an APK, enable desktop authority, or alter security policy.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
TOOLS = ROOT / "android/tools"
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))
import stage_contract


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def certificate_identity(certificate, source):
    """Validate one public X.509 APK certificate and return its DER identity."""
    supplied = Path(certificate)
    if supplied.is_symlink() or not supplied.is_file():
        raise ValueError("Wonad signer certificate must be an ordinary public X.509 file")
    certificate = supplied.resolve(strict=True)
    if certificate == source or source in certificate.parents:
        raise ValueError("Wonad signer certificate must remain outside the OS source checkout")
    if any(part.lower() in {"keys", "private-keys", "private_keys", "secrets"}
           for part in certificate.parts):
        raise ValueError("Wonad public signer certificate must remain outside a key-secret tree")
    private_suffixes = {".key", ".p12", ".pfx", ".pk8", ".jks", ".keystore"}
    private_names = {"id_ed25519", "id_rsa", "avb.pem", "releasekey.key"}
    private_markers = (b"BEGIN PRIVATE KEY", b"BEGIN ENCRYPTED PRIVATE KEY",
                       b"BEGIN RSA PRIVATE KEY", b"BEGIN EC PRIVATE KEY",
                       b"BEGIN OPENSSH PRIVATE KEY")
    for sibling in certificate.parent.iterdir():
        if sibling == certificate:
            continue
        lowered = sibling.name.lower()
        if lowered in private_names or sibling.suffix.lower() in private_suffixes:
            raise ValueError("Wonad public signer certificate directory contains private signing material")
        # A .pem suffix alone is ambiguous: ordinary public certificates use it
        # too. Inspect small ordinary siblings for unencrypted or encrypted PEM
        # private-key armour without following symlinks or reading large files.
        if sibling.is_symlink() or not sibling.is_file() or sibling.stat().st_size > 1024 * 1024:
            continue
        with sibling.open("rb") as stream:
            prefix = stream.read(1024 * 1024 + 1)
        if any(marker in prefix for marker in private_markers):
            raise ValueError("Wonad public signer certificate directory contains private signing material")
    raw = certificate.read_bytes()
    if any(marker in raw for marker in private_markers):
        raise ValueError("Wonad signer input contains private key material")
    try:
        converted = subprocess.run(["openssl", "x509", "-in", str(certificate), "-outform", "DER"],
                                   check=True, capture_output=True, timeout=30)
        description = subprocess.run(["openssl", "x509", "-in", str(certificate), "-noout",
                                      "-subject", "-issuer"], check=True, capture_output=True,
                                     text=True, timeout=30).stdout.lower()
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
        raise ValueError("Wonad signer input is not a valid public X.509 certificate") from error
    der = converted.stdout
    if not 128 <= len(der) <= 64 * 1024:
        raise ValueError("Wonad signer certificate has an unexpected DER size")
    if any(marker in description for marker in ("android debug", "android test", "testkey", "debugkey")):
        raise ValueError("Known debug/test certificates cannot authorize a release client")
    for relative in ("build/make/target/product/security/testkey.x509.pem",
                     "build/make/target/product/security/platform.x509.pem",
                     "build/make/target/product/security/shared.x509.pem"):
        known = source / relative
        if known.is_file() and not known.is_symlink():
            try:
                known_der = subprocess.run(["openssl", "x509", "-in", str(known), "-outform", "DER"],
                                           check=True, capture_output=True, timeout=30).stdout
            except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
                continue
            if der == known_der:
                raise ValueError("Known AOSP test certificates cannot authorize a release client")
    return hashlib.sha256(der).hexdigest(), der


def framework_plan(frameworks, patches):
    """Accept only the pinned original tree or a complete owned patch prefix.

    Build exact expected file contents in isolation. Reverse-apply success alone
    cannot detect independent edits elsewhere in an already patched file.
    """
    names = sorted({line.removeprefix("+++ b/") for patch in patches
                    for line in patch.read_text().splitlines() if line.startswith("+++ b/")})
    if any(Path(name).is_absolute() or ".." in Path(name).parts for name in names):
        raise ValueError("Invalid framework patch target")
    tracked = set(subprocess.check_output(
        ["git", "-C", str(frameworks), "ls-tree", "-r", "--name-only", "HEAD", "--", *names],
        text=True).splitlines())
    def contents(path):
        return path.read_bytes() if path.exists() else None
    versions = []
    with tempfile.TemporaryDirectory(prefix="wonad-framework-") as directory:
        scratch = Path(directory)
        for name in names:
            dest = scratch / name
            dest.parent.mkdir(parents=True, exist_ok=True)
            if name in tracked:
                dest.write_bytes(subprocess.check_output(["git", "-C", str(frameworks), "show", "HEAD:" + name]))
        versions.append({name: contents(scratch / name) for name in names})
        for patch in patches:
            subprocess.run(["git", "-C", str(scratch), "apply", str(patch.resolve())], check=True, capture_output=True)
            versions.append({name: contents(scratch / name) for name in names})
    if any(value is None for value in versions[-1].values()):
        raise ValueError("Framework patches must create their targets and must not delete files")
    actual = {}
    for name in names:
        parts = Path(name).parts
        if any(frameworks.joinpath(*parts[:i]).is_symlink() for i in range(1, len(parts) + 1)):
            raise ValueError("Preserving symlinked framework integration files")
        actual[name] = contents(frameworks / name)
    if actual not in versions:
        raise ValueError("Preserving independently modified framework integration files")
    return [(frameworks / name, actual[name], versions[-1][name]) for name in names
            if actual[name] != versions[-1][name]]


def target_hashes(repository, patches, changes):
    """Return the exact complete post-stage bytes for every patch target."""
    names = sorted({line.removeprefix("+++ b/") for patch in patches
                    for line in patch.read_text().splitlines() if line.startswith("+++ b/")})
    changed = {path.relative_to(repository).as_posix(): after for path, _, after in changes}
    result = {}
    for name in names:
        stage_contract.safe_relative(name)
        path = repository / name
        value = changed.get(name)
        if value is None:
            if path.is_symlink() or not path.is_file():
                raise ValueError("Missing owned platform target: " + name)
            value = path.read_bytes()
        result[name] = hashlib.sha256(value).hexdigest()
    return result


def verify_targets(repository, targets, label):
    if not isinstance(targets, dict) or not targets:
        raise ValueError(f"Missing {label} target inventory")
    for name, expected in targets.items():
        stage_contract.safe_relative(name)
        if re.fullmatch(r"[0-9a-f]{64}", str(expected)) is None:
            raise ValueError(f"Invalid {label} target digest: {name}")
        path = repository / name
        if path.is_symlink() or not path.is_file() or digest(path) != expected:
            raise ValueError(f"Owned {label} target differs from its stage marker: {name}")


def verify_stage(source):
    """Revalidate every staged byte without mutating the OS checkout."""
    source = source.resolve(strict=True)
    if source == ROOT or ROOT in source.parents or not (source / ".repo").is_dir():
        raise ValueError("Use the dedicated repo-synced OS checkout outside Wonad")
    marker_path = source / "external/wonad/.wonad-stage.json"
    if marker_path.is_symlink() or not marker_path.is_file():
        raise ValueError("Staged Wonad source marker is missing or symlinked")
    marker = json.loads(marker_path.read_text())
    expected_fields = {"schema", "frameworks_revision", "launcher3_revision",
                       "emulator_goldfish_revision",
                       "signer_sha256", "signer_certificate", "files", "patches",
                       "platform_targets", "tools"}
    if not isinstance(marker, dict) or set(marker) != expected_fields or marker.get("schema") != 4:
        raise ValueError("Unexpected Wonad stage marker schema")
    lock = json.loads((ROOT / "android/grapheneos.lock.json").read_text())
    repositories = {
        "frameworks_base": (source / "frameworks/base", lock["frameworks_base"]["commit"],
                            stage_contract.FRAMEWORK_PATCH_NAMES),
        "launcher3": (source / "packages/apps/Launcher3", lock["launcher3"]["commit"],
                      stage_contract.LAUNCHER_PATCH_NAMES),
        "emulator_goldfish": (source / "device/generic/goldfish",
                              lock["emulator_goldfish"]["commit"],
                              stage_contract.EMULATOR_PATCH_NAMES),
    }
    if (marker["frameworks_revision"] != repositories["frameworks_base"][1] or
            marker["launcher3_revision"] != repositories["launcher3"][1] or
            marker["emulator_goldfish_revision"] != repositories["emulator_goldfish"][1] or
            re.fullmatch(r"[0-9a-f]{64}", str(marker["signer_sha256"])) is None):
        raise ValueError("Wonad stage marker differs from the authenticated pins")
    certificate = marker["signer_certificate"]
    if (not isinstance(certificate, dict) or set(certificate) != {"path", "sha256", "size"} or
            certificate.get("path") != "WonadReleaseCertificate.der" or
            certificate.get("sha256") != marker["signer_sha256"] or
            type(certificate.get("size")) is not int or certificate["size"] < 128):
        raise ValueError("Invalid staged Wonad signer certificate identity")
    expected_patches = {name: stage_contract.patch_ledger(names)
                        for name, (_, _, names) in repositories.items()}
    if marker["patches"] != expected_patches:
        raise ValueError("Owned patch order or digest differs from the stage marker")
    if marker["tools"] != stage_contract.tool_ledger():
        raise ValueError("Release staging tool differs from the stage marker")
    if not isinstance(marker["platform_targets"], dict) or set(marker["platform_targets"]) != set(repositories):
        raise ValueError("Incomplete owned platform target inventory")
    for name, (repository, revision, _) in repositories.items():
        actual = subprocess.check_output(["git", "-C", str(repository), "rev-parse", "HEAD"],
                                         text=True).strip()
        if actual != revision:
            raise ValueError(f"{name} revision differs from the authenticated source pin")
        verify_targets(repository, marker["platform_targets"][name], name)
    staged_root = marker_path.parent
    files = marker["files"]
    if not isinstance(files, dict) or not files:
        raise ValueError("Missing staged source inventory")
    actual_files = {str(path.relative_to(staged_root)): path for path in staged_root.rglob("*")
                    if path.is_file() and path != marker_path}
    if set(actual_files) != set(files):
        raise ValueError("Staged source inventory differs from its marker")
    for name, expected in files.items():
        stage_contract.safe_relative(name)
        path = actual_files[name]
        if path.is_symlink() or re.fullmatch(r"[0-9a-f]{64}", str(expected)) is None or digest(path) != expected:
            raise ValueError("Staged source differs from its marker: " + name)
    certificate_path = actual_files[certificate["path"]]
    if certificate_path.stat().st_size != certificate["size"]:
        raise ValueError("Staged Wonad signer certificate size differs from marker")
    return marker


def stage(source, signer_certificate):
    # Reject unreviewed public wire changes before touching either OS tree.
    # This baseline gate is source compatibility, not runtime qualification.
    contract = subprocess.run([sys.executable, str(ROOT / "android/tools/sdk_contract.py")],
                              capture_output=True, text=True, timeout=30)
    if contract.returncode != 0:
        raise ValueError("SDK contract review required: " + contract.stdout + contract.stderr)
    source = source.resolve(strict=True)
    if source == ROOT or ROOT in source.parents or not (source / ".repo").is_dir():
        raise ValueError("Use the dedicated repo-synced OS checkout outside Wonad")
    signer, certificate_der = certificate_identity(signer_certificate, source)
    frameworks = source / "frameworks/base"
    expected = json.loads((ROOT / "android/grapheneos.lock.json").read_text())["frameworks_base"]["commit"]
    revision = subprocess.check_output(["git", "-C", str(frameworks), "rev-parse", "HEAD"], text=True).strip()
    if revision != expected:
        raise ValueError("Framework revision differs from the authenticated source pin")
    patches = stage_contract.patches(stage_contract.FRAMEWORK_PATCH_NAMES)
    framework_patch_ledger = stage_contract.patch_ledger(stage_contract.FRAMEWORK_PATCH_NAMES)
    launcher_patch_ledger = stage_contract.patch_ledger(stage_contract.LAUNCHER_PATCH_NAMES)
    release_tool_ledger = stage_contract.tool_ledger()
    framework_changes = framework_plan(frameworks, patches)
    framework_targets = target_hashes(frameworks, patches, framework_changes)
    launcher = source / "packages/apps/Launcher3"
    launcher_expected = json.loads((ROOT / "android/grapheneos.lock.json").read_text())["launcher3"]["commit"]
    launcher_revision = subprocess.check_output(["git", "-C", str(launcher), "rev-parse", "HEAD"], text=True).strip()
    if launcher_revision != launcher_expected:
        raise ValueError("Launcher3 revision differs from the authenticated source pin")
    launcher_patches = stage_contract.patches(stage_contract.LAUNCHER_PATCH_NAMES)
    launcher_changes = framework_plan(launcher, launcher_patches)
    launcher_targets = target_hashes(launcher, launcher_patches, launcher_changes)
    emulator = source / "device/generic/goldfish"
    emulator_expected = json.loads((ROOT / "android/grapheneos.lock.json").read_text())[
        "emulator_goldfish"]["commit"]
    emulator_revision = subprocess.check_output(
        ["git", "-C", str(emulator), "rev-parse", "HEAD"], text=True).strip()
    if emulator_revision != emulator_expected:
        raise ValueError("Goldfish revision differs from the authenticated source pin")
    emulator_patches = stage_contract.patches(stage_contract.EMULATOR_PATCH_NAMES)
    emulator_changes = framework_plan(emulator, emulator_patches)
    emulator_targets = target_hashes(emulator, emulator_patches, emulator_changes)
    emulator_patch_ledger = stage_contract.patch_ledger(stage_contract.EMULATOR_PATCH_NAMES)

    files = {"Android.bp": ROOT / "android/os-integration/Android.bp", "LICENSE": ROOT / "LICENSE"}
    for relative, suffix in (("broker-rust/src", ".rs"), ("broker-jni/src", ".rs"), ("input-jni/src", ".rs"),
                             ("input-core/src/main/kotlin", ".kt"), ("input-integration/src", ".kt"),
                             ("broker-core/src/main/kotlin", ".kt"), ("os-integration/src", ".kt"),
                             ("os-integration/resources", ".xml"),
                             ("desktop-sdk/src/main/kotlin", ".kt"), ("desktop-sdk/src/main/aidl", ".aidl")):
        for path in (ROOT / "android" / relative).rglob("*" + suffix):
            if path.is_symlink():
                raise ValueError("Refusing symlinked integration source: " + str(path))
            files[str(path.relative_to(ROOT / "android"))] = path
    target = source / "external/wonad"
    if (source / "external").is_symlink():
        raise ValueError("Refusing symlinked external source directory")
    marker = target / ".wonad-stage.json"
    previous = {}
    if target.exists():
        if target.is_symlink() or marker.is_symlink() or not marker.is_file():
            raise ValueError("Refusing to adopt an existing unowned external/wonad directory")
        if any(p.is_symlink() for p in target.rglob("*")):
            raise ValueError("Preserving symlinked staged broker sources")
        previous = json.loads(marker.read_text())["files"]
        actual = {str(p.relative_to(target)): p for p in target.rglob("*") if p.is_file() and p != marker}
        if set(actual) != set(previous) or any(p.is_symlink() or digest(p) != previous[name] for name, p in actual.items()):
            raise ValueError("Preserving independently changed staged broker sources")
        if set(previous) - (set(files) | {"WonadSigning.kt", "WonadReleaseCertificate.der",
                                         "generated-res/values/wonad_signer.xml"}):
            raise ValueError("Staged sources were removed upstream; archive the owned staging directory first")
    target.mkdir(exist_ok=True)
    for name, path in files.items():
        dest = target / name
        dest.parent.mkdir(parents=True, exist_ok=True)
        if not dest.exists() or digest(dest) != digest(path):
            shutil.copyfile(path, dest)
    signing = (
        'package org.wonad.desktop.broker\n\n'
        '// Public signer pin for this development build; no trust-on-first-use.\n'
        'internal object WonadSigning { const val SHA256 = "' + signer + '" }\n')
    signing_path = target / "WonadSigning.kt"
    if not signing_path.exists() or signing_path.read_text() != signing:
        signing_path.write_text(signing)
    certificate_path = target / "WonadReleaseCertificate.der"
    if not certificate_path.exists() or certificate_path.read_bytes() != certificate_der:
        certificate_path.write_bytes(certificate_der)
    signer_resource = (
        '<?xml version="1.0" encoding="utf-8"?>\n'
        '<resources>\n'
        '    <!-- Public DER certificate digest; this is an install-time permission pin, not a secret. -->\n'
        '    <string name="wonad_client_signer_sha256" translatable="false">' + signer + '</string>\n'
        '</resources>\n')
    signer_resource_path = target / "generated-res/values/wonad_signer.xml"
    signer_resource_path.parent.mkdir(parents=True, exist_ok=True)
    if not signer_resource_path.exists() or signer_resource_path.read_text() != signer_resource:
        signer_resource_path.write_text(signer_resource)
    hashes = {name: digest(target / name) for name in
              [*files, "WonadSigning.kt", "WonadReleaseCertificate.der",
               "generated-res/values/wonad_signer.xml"]}
    manifest = json.dumps({"schema": 4, "frameworks_revision": expected,
                           "launcher3_revision": launcher_expected,
                           "emulator_goldfish_revision": emulator_expected,
                           "signer_sha256": signer,
                           "signer_certificate": {
                               "path": "WonadReleaseCertificate.der", "sha256": signer,
                               "size": len(certificate_der),
                           }, "files": hashes,
                           "patches": {
                               "frameworks_base": framework_patch_ledger,
                               "launcher3": launcher_patch_ledger,
                               "emulator_goldfish": emulator_patch_ledger,
                           },
                           "platform_targets": {
                               "frameworks_base": framework_targets,
                               "launcher3": launcher_targets,
                               "emulator_goldfish": emulator_targets,
                           },
                           "tools": release_tool_ledger}, indent=2, sort_keys=True) + "\n"
    changes = framework_changes + launcher_changes + emulator_changes
    if any((path.read_bytes() if path.exists() else None) != before for path, before, after in changes):
        raise ValueError("Platform source changed during staging; preserving newer edits")
    for path, before, after in changes:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(after)
    verify_targets(frameworks, framework_targets, "frameworks_base")
    verify_targets(launcher, launcher_targets, "launcher3")
    verify_targets(emulator, emulator_targets, "emulator_goldfish")
    if (framework_patch_ledger != stage_contract.patch_ledger(stage_contract.FRAMEWORK_PATCH_NAMES) or
            launcher_patch_ledger != stage_contract.patch_ledger(stage_contract.LAUNCHER_PATCH_NAMES) or
            emulator_patch_ledger != stage_contract.patch_ledger(stage_contract.EMULATOR_PATCH_NAMES) or
            release_tool_ledger != stage_contract.tool_ledger()):
        raise ValueError("Owned patch or release tool changed during staging")
    if not marker.exists() or marker.read_text() != manifest:
        marker.write_text(manifest)
    print(f"Staged {len(hashes)} owned sources under {target}; authority stays disabled by default")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--signer-certificate", type=Path)
    parser.add_argument("--verify-only", action="store_true")
    args = parser.parse_args()
    if args.verify_only:
        if args.signer_certificate is not None:
            parser.error("--signer-certificate is not used with --verify-only")
        verify_stage(args.source)
        print("PASS: exact owned Wonad stage, patches, targets and tools verified")
    else:
        if args.signer_certificate is None:
            parser.error("--signer-certificate is required unless --verify-only is used")
        stage(args.source, args.signer_certificate)


if __name__ == "__main__":
    main()
