#!/usr/bin/env python3
"""Bundle exact native-v3 inputs for testing; never produce a qualification.

Reuse a pinned local SDK/graphics image and copy pristine product images, not
emulator userdata. The resulting candidate must still pass native backend,
normal-startup and authenticated X11 qualification before release promotion.
"""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(ROOT / "android/demo"))
sys.path.insert(0, str(ROOT / "android/tools"))
from build import (IMAGE_FILES, digest, inspect_image, promotion_base, runtime_files,
                   source_archive, stage_emulator)
from emulator_identity import capture_runtime
from entrypoint import EMULATOR_CLIENT_COMPOSITION_ABI
import x86_build_comparison as x86_comparison
import phase1_emulator_client_packet as packet_tool

OS_PATHS = {
    "com.android.systemui": "system_ext/priv-app/SystemUI/SystemUI.apk",
    "os_broker_native": "system_ext/lib64/libwonad_broker_jni.so",
    "os_input_native": "system/lib64/libwonad_input_jni.so",
    "os_services": "system/framework/services.jar",
    "os_framework": "system/framework/framework.jar",
}
APKSIGNER = packet_tool.APKSIGNER
APKSIGNER_JAR = packet_tool.BUILD_TOOLS + "lib/apksigner.jar"
PHASE1_BASE_IMAGE = "sha256:0bf80454dbaa59bacd955d3e0140d8c91c4dcbd4d6e3e941274cdf10cb374b3f"
PHASE1_BASE_MANIFEST_SHA256 = "7aa1f429dc6be79bc19fc248e679ef270fc147a8988009ebcdbfece9a1af6bfe"
PHASE1_BASE_LABELS = {
    "org.opencontainers.image.description":
        "Unqualified emulator-only native-v3 OS/APK candidate; not a release",
    "org.opencontainers.image.title": "Wonad native-v3 test candidate",
    "org.opencontainers.image.version": "2026092500",
    "org.wonad.candidate": "true",
    "org.wonad.qualification": "test-image-not-release",
    "org.wonad.runtime-patch": "run-local-core-limit",
    "org.wonad.styx.desktop-provider": "ordinary-apk",
    "org.wonad.styx.scope": "live-external-document-tasks",
}
PHASE1_CANDIDATE_LABELS = {
    **PHASE1_BASE_LABELS,
    "org.opencontainers.image.version": "2026100600",
}
REVIEWED_BASE_WONAD_FILES = {
    "/opt/wonad/README-live-x11.md",
    "/opt/wonad/authentication-sources.json",
    "/opt/wonad/corresponding-sources.tar.gz",
    "/opt/wonad/emulator_identity.py",
    "/opt/wonad/entrypoint.py",
    "/opt/wonad/grsh-test-fixture.py",
    "/opt/wonad/live-x11-entrypoint.py",
    "/opt/wonad/notices/LICENSE",
    "/opt/wonad/notices/NOTICE.xml.gz",
    "/opt/wonad/notices/sources.tar.gz",
    "/opt/wonad/run-local.py",
    "/opt/wonad/session.py",
    "/opt/wonad/styx-desktop.apk",
    "/opt/wonad/styx-tools/README.md",
    "/opt/wonad/styx-tools/bundle.json",
    "/opt/wonad/styx-tools/probe-emulator.py",
    "/opt/wonad/styx-tools/remote-apps.py",
    "/opt/wonad/styx-tools/run-android-gate.py",
    "/opt/wonad/styx-tools/run-remote-gate.py",
    "/opt/wonad/styx-tools/run-x11-tests.py",
    "/opt/wonad/styx/corresponding-sources.tar.gz",
    "/opt/wonad/styx/remote-clients.tar.gz",
    "/opt/wonad/styx/styx-probe.apk",
    "/opt/wonad/wonad.apk",
    "/opt/wonad/x11-connect.py",
    "/opt/wonad/x11-test-entrypoint.py",
}
REVIEWED_BASE_FILES = REVIEWED_BASE_WONAD_FILES | {
    "/product/" + name for name in IMAGE_FILES
}
PHASE1_EVIDENCE_NAMES = {
    "comparison": "x86-baseline-custom-comparison.json",
    "baseline_receipt": "x86-baseline-receipt.json",
    "custom_receipt": "x86-custom-receipt.json",
    "client_packet_receipt": "client-packet-receipt.json",
}
PHASE1_SIGNER_TRANSCRIPTS = {
    "systemui": "systemui-apksigner-verification.txt",
    "fault": "fault-apksigner-verification.txt",
}


def validate_base_manifest(manifest, *, reviewed_phase1_predecessor=False):
    """Validate an immutable native candidate's self-reported file inventory.

    The exact 37-file allowlist belongs only to the reviewed Phase-1 SDK
    predecessor.  A freshly packaged strict candidate legitimately adds the
    four authenticated build documents and two signer transcripts, and is a
    supported input to the separate derived conformance builder.
    """
    if not isinstance(manifest, dict) or manifest.get("schema") != 1 or \
            manifest.get("architecture") != "amd64" or not isinstance(manifest.get("files"), dict) or \
            not 1 <= len(manifest["files"]) <= 20000:
        raise ValueError("Invalid immutable base bundle manifest")
    for name, checksum in manifest["files"].items():
        path = PurePosixPath(name) if isinstance(name, str) else PurePosixPath(".")
        if not isinstance(name, str) or not path.is_absolute() or ".." in path.parts or \
                not (name.startswith("/product/") or name.startswith("/opt/wonad/")) or \
                not isinstance(checksum, str) or not re.fullmatch(r"[0-9a-f]{64}", checksum):
            raise ValueError("Invalid immutable base file inventory")
    if reviewed_phase1_predecessor and set(manifest["files"]) != REVIEWED_BASE_FILES:
        raise ValueError("Immutable base differs from the reviewed inherited file inventory")
    return manifest


def manifest_digest(manifest):
    return hashlib.sha256(json.dumps(manifest, sort_keys=True,
                                     separators=(",", ":")).encode()).hexdigest()


def verified_base_manifest(image):
    """Run the immutable base's own offline checksum verifier before inheritance."""
    output = subprocess.check_output([
        "docker", "run", "--rm", "--network", "none", "--read-only",
        "--tmpfs", "/tmp:rw,nosuid,size=64m", "--env", "TMPDIR=/tmp",
        "--entrypoint", "python3", image, "/opt/wonad/entrypoint.py", "verify",
    ], text=True, timeout=120)
    banner, separator, document = output.partition("\n")
    if banner != "Verifying bundled OS and Wonad APK…" or not separator:
        raise ValueError("Immutable base did not run its expected bundle verifier")
    try:
        manifest = json.loads(document)
    except json.JSONDecodeError as error:
        raise ValueError("Immutable base returned an invalid bundle manifest") from error
    return validate_base_manifest(manifest)


def base_runtime(image, emulator_directory=None):
    mounts = []
    before = None
    if emulator_directory is not None:
        if not emulator_directory.is_dir() or emulator_directory.is_symlink():
            raise ValueError("A complete real emulator SDK directory is required")
        selected = emulator_directory.resolve(strict=True)
        if any(char in str(selected) for char in (":", "\n", "\r")):
            raise ValueError("Invalid SDK mount path")
        before = runtime_files(selected)
        mounts = ["--volume", str(selected) + ":/opt/android/emulator:ro,z"]
    def command(*arguments):
        return subprocess.check_output([
            "docker", "run", "--rm", "--network", "none", "--read-only",
            "--tmpfs", "/tmp:rw,nosuid,size=64m", "--env", "TMPDIR=/tmp",
            *mounts, "--entrypoint", arguments[0], image, *arguments[1:]], text=True, timeout=120)
    runtime = capture_runtime(command)
    if before is not None and (runtime["files"] != before or runtime_files(selected) != before):
        raise ValueError("Selected SDK differs from its actual container runtime or changed during observation")
    return runtime


def checked_file(path):
    if not path.is_file() or path.is_symlink() or path.stat().st_size <= 0:
        raise ValueError("Missing, empty or symlinked candidate input: " + str(path))
    return digest(path)


def exact_flat_mapping(actual, expected):
    """Compare a JSON object without Python's bool/int equality shortcut."""
    return type(actual) is dict and actual.keys() == expected.keys() and all(
        type(actual[name]) is type(value) and actual[name] == value
        for name, value in expected.items()
    )


def validate_phase1_base_image(image, inspect, manifest):
    """Bind strict packaging to the reviewed unqualified SDK/runtime parent."""
    validate_base_manifest(manifest, reviewed_phase1_predecessor=True)
    if image != PHASE1_BASE_IMAGE or inspect.get("Id") != PHASE1_BASE_IMAGE or \
            manifest_digest(manifest) != PHASE1_BASE_MANIFEST_SHA256:
        raise ValueError("Strict Phase-1 packaging requires the reviewed immutable base image/manifest")
    labels = inspect.get("Config", {}).get("Labels")
    if not exact_flat_mapping(labels, PHASE1_BASE_LABELS):
        raise ValueError("Strict Phase-1 base labels differ from the reviewed unqualified label set")


def validate_phase1_candidate_image(inspect):
    labels = inspect.get("Config", {}).get("Labels")
    if not exact_flat_mapping(labels, PHASE1_CANDIDATE_LABELS):
        raise ValueError("Candidate labels differ from the explicit unqualified Phase-1 label set")


def require_candidate_tag_absent(tag):
    if subprocess.check_output([
        "docker", "image", "ls", "-q", "--filter", "reference=" + tag,
    ], text=True).strip():
        raise ValueError("Preserving existing candidate image tag")


def publish_candidate(candidate, tag):
    # Docker has no compare-and-swap tag operation.  This second check closes
    # the long build window, but an external writer can still race this final
    # check; callers must keep the local candidate namespace quiescent.
    require_candidate_tag_absent(tag)
    subprocess.run(["docker", "tag", candidate, tag], check=True)


def _apk_verification_command(image):
    script = (
        "sha256sum '" + APKSIGNER + "' '" + APKSIGNER_JAR + "'; "
        "cat > /tmp/input.apk; sha256sum /tmp/input.apk; "
        "exec '" + APKSIGNER + "' verify --verbose --print-certs /tmp/input.apk"
    )
    return [
        "docker", "run", "--rm", "-i", "--network", "none", "--read-only",
        "--tmpfs", "/tmp:rw,nosuid,nodev,size=128m", "--entrypoint", "/bin/sh",
        image, "-ec", script,
    ]


def _verify_apk_signer(apk, expected, image, tools, label):
    observed = phase1_file_ref(apk)
    if observed != expected:
        raise ValueError(label + " differs from its authenticated receipt")
    with apk.open("rb") as source:
        result = subprocess.run(
            _apk_verification_command(image), stdin=source, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, text=True, timeout=180)
    if result.returncode != 0:
        raise ValueError("Immutable apksigner rejected " + label + ":\n" + result.stdout)
    if phase1_file_ref(apk) != expected:
        raise ValueError(label + " changed during immutable signer verification")
    rows = re.findall(r"^([0-9a-f]{64})  (\S+)$", result.stdout, re.MULTILINE)
    values = {name: value for value, name in rows}
    if len(rows) != 3 or len(values) != 3 or \
            values.get(APKSIGNER) != tools.get(APKSIGNER) or \
            values.get(APKSIGNER_JAR) != tools.get(APKSIGNER_JAR) or \
            values.get("/tmp/input.apk") != expected["sha256"]:
        raise ValueError("Immutable APK verifier or " + label + " bytes changed")
    try:
        signer = packet_tool.parse_signer(result.stdout)["certificate_der_sha256"]
    except ValueError as error:
        raise ValueError("Cannot authenticate " + label + " signer: " + str(error)) from error
    return signer, result.stdout


def verify_packet_systemui_signers(product, packet, receipt, custom):
    """Cryptographically bind finished SystemUI to the packet's fault identity."""
    systemui = exact_phase1_file(
        product / OS_PATHS["com.android.systemui"], "finished custom SystemUI APK")
    fault = exact_phase1_file(packet / packet_tool.FINAL_FILES["fault"],
                              "Phase-1 packet fault APK")
    systemui_row = custom.get("artifacts", {}).get("os_artifacts", {}).get(
        "com.android.systemui", {})
    systemui_expected = {
        "sha256": systemui_row.get("sha256"), "size": systemui_row.get("size"),
    }
    fault_row = receipt.get("artifacts", {}).get("fault", {})
    fault_expected = {"sha256": fault_row.get("sha256"), "size": fault_row.get("bytes")}
    if systemui_row.get("state") != "present" or \
            not x86_comparison.SHA256.fullmatch(str(systemui_expected["sha256"])) or \
            type(systemui_expected["size"]) is not int or systemui_expected["size"] <= 0 or \
            not x86_comparison.SHA256.fullmatch(str(fault_expected["sha256"])) or \
            type(fault_expected["size"]) is not int or fault_expected["size"] <= 0:
        raise ValueError("Build/packet receipts lack exact SystemUI/fault artifact identities")

    packet_tools = receipt.get("tools", {})
    image = packet_tools.get("image_id")
    tools = packet_tools.get("tools", {})
    if not isinstance(image, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", image) or \
            not isinstance(tools, dict) or \
            not x86_comparison.SHA256.fullmatch(str(tools.get(APKSIGNER, ""))) or \
            not x86_comparison.SHA256.fullmatch(str(tools.get(APKSIGNER_JAR, ""))) or \
            inspect_image(image).get("Id") != image:
        raise ValueError("Packet lacks its immutable authenticated apksigner runtime")

    systemui_signer, systemui_transcript = _verify_apk_signer(
        systemui, systemui_expected, image, tools, "finished custom SystemUI APK")
    fault_signer, fault_transcript = _verify_apk_signer(
        fault, fault_expected, image, tools, "Phase-1 packet fault APK")
    if inspect_image(image).get("Id") != image:
        raise ValueError("Packet apksigner image changed during signer verification")
    platform_signer = receipt.get("signers", {}).get(
        "systemui_platform_development", {}).get("certificate_der_sha256")
    declared_fault_signer = fault_row.get("certificate_der_sha256")
    if not x86_comparison.SHA256.fullmatch(str(platform_signer)) or \
            systemui_signer != fault_signer or systemui_signer != platform_signer or \
            systemui_signer != declared_fault_signer:
        raise ValueError("Finished SystemUI signer differs from the packet fault/platform signer")

    transcripts = {"systemui": systemui_transcript, "fault": fault_transcript}
    rows = {}
    for role, expected in (("systemui", systemui_expected), ("fault", fault_expected)):
        raw = transcripts[role].encode()
        rows[role] = {
            "apk": expected,
            "transcript": {
                "bundle_path": "/opt/wonad/build-evidence/" + PHASE1_SIGNER_TRANSCRIPTS[role],
                "sha256": hashlib.sha256(raw).hexdigest(), "size": len(raw),
            },
        }
    return {
        "schema": 1,
        "scope": "authenticated-packet-tools-exact-systemui-fault-signer-match",
        "runtime_qualified": False,
        "verifier": {
            "image_id": image,
            "apksigner": {"path": APKSIGNER, "sha256": tools[APKSIGNER]},
            "apksigner_jar": {"path": APKSIGNER_JAR, "sha256": tools[APKSIGNER_JAR]},
        },
        "signer_der_sha256": systemui_signer,
        "systemui": rows["systemui"], "fault": rows["fault"],
        "_transcripts": transcripts,
    }


def phase1_evidence_inputs(comparison, comparison_sha256, baseline_receipt,
                           baseline_receipt_sha256, custom_receipt,
                           custom_receipt_sha256, client_packet,
                           client_packet_receipt_sha256):
    """Create the exact strict-mode input object without resolving aliases."""
    return {
        "comparison": Path(comparison),
        "comparison_sha256": comparison_sha256,
        "baseline_receipt": Path(baseline_receipt),
        "baseline_receipt_sha256": baseline_receipt_sha256,
        "custom_receipt": Path(custom_receipt),
        "custom_receipt_sha256": custom_receipt_sha256,
        "client_packet": Path(client_packet),
        "client_packet_receipt_sha256": client_packet_receipt_sha256,
    }


def exact_phase1_directory(path, label):
    try:
        return x86_comparison.exact_path(Path(path), label, directory=True)
    except x86_comparison.ComparisonError as error:
        raise ValueError(str(error)) from error


def exact_phase1_file(path, label):
    try:
        return x86_comparison.exact_path(Path(path), label)
    except x86_comparison.ComparisonError as error:
        raise ValueError(str(error)) from error


def phase1_file_ref(path):
    try:
        return x86_comparison.ordinary_ref(path)
    except x86_comparison.ComparisonError as error:
        raise ValueError(str(error)) from error


def authenticate_phase1_build_evidence(product, apk, inputs):
    """Verify OS/client receipts and bind them to one product, APK, and signer."""
    expected = {
        "comparison", "comparison_sha256", "baseline_receipt",
        "baseline_receipt_sha256", "custom_receipt", "custom_receipt_sha256",
        "client_packet", "client_packet_receipt_sha256",
    }
    if not isinstance(inputs, dict) or set(inputs) != expected:
        raise ValueError("Strict Phase-1 mode requires the complete comparison/receipt input set")
    product = exact_phase1_directory(Path(product), "selected Phase-1 product")
    apk = exact_phase1_file(Path(apk), "selected Phase-1 Wonad APK")
    packet = exact_phase1_directory(
        Path(inputs["client_packet"]), "selected Phase-1 client packet")
    evidence_paths = {
        name: exact_phase1_file(Path(inputs[name]), "Phase-1 " + name.replace("_", " "))
        for name in ("comparison", "baseline_receipt", "custom_receipt")
    }
    evidence_paths["client_packet_receipt"] = exact_phase1_file(
        packet / "receipt.json", "Phase-1 client packet receipt")
    for name in ("comparison_sha256", "baseline_receipt_sha256", "custom_receipt_sha256",
                 "client_packet_receipt_sha256"):
        if not isinstance(inputs[name], str) or not x86_comparison.SHA256.fullmatch(inputs[name]):
            raise ValueError("Strict Phase-1 evidence requires an exact lowercase " + name)
    names = list(evidence_paths)
    for index, first in enumerate(names):
        for second in names[index + 1:]:
            if evidence_paths[first].samefile(evidence_paths[second]):
                raise ValueError("Phase-1 comparison and receipt files must be distinct, non-aliasing files")
    try:
        document, baseline, custom = x86_comparison.verify_comparison(
            evidence_paths["comparison"], inputs["comparison_sha256"],
            evidence_paths["baseline_receipt"], inputs["baseline_receipt_sha256"],
            evidence_paths["custom_receipt"], inputs["custom_receipt_sha256"])
    except x86_comparison.ComparisonError as error:
        raise ValueError("Phase-1 x86 build evidence failed authentication: " + str(error)) from error
    if baseline.get("role") != "baseline" or custom.get("role") != "custom":
        raise ValueError("Phase-1 receipts have the wrong baseline/custom roles")
    if document.get("result") != "passed_exact_clean_baseline_custom_delta":
        raise ValueError("Phase-1 comparison did not pass the exact clean baseline/custom delta")

    try:
        packet_receipt = packet_tool.load(evidence_paths["client_packet_receipt"])
        packet_tool.validate_receipt(
            packet, packet_receipt, inputs["client_packet_receipt_sha256"], live_tools=False)
    except (ValueError, OSError) as error:
        raise ValueError("Phase-1 client packet failed authentication: " + str(error)) from error
    packet_apk = exact_phase1_file(packet / "wonad.apk", "Phase-1 client packet Wonad APK")
    packet_wonad = packet_receipt.get("artifacts", {}).get("wonad", {})
    apk_ref = phase1_file_ref(apk)
    if not apk.samefile(packet_apk) or packet_wonad.get("sha256") != apk_ref["sha256"] or \
            packet_wonad.get("bytes") != apk_ref["size"]:
        raise ValueError("Selected Wonad APK is not the exact authenticated client-packet APK")

    custom_locations = custom.get("locations", {})
    custom_product = exact_phase1_directory(
        Path(str(custom_locations.get("product", ""))), "custom receipt product")
    custom_out = exact_phase1_directory(
        Path(str(custom_locations.get("out_dir", ""))), "custom receipt OUT_DIR")
    custom_source = exact_phase1_directory(
        Path(str(custom_locations.get("source", ""))), "custom receipt source")
    if str(product) != custom_locations.get("product") or not product.samefile(custom_product):
        raise ValueError("Selected product is not the exact authenticated custom receipt product")
    if custom_product != custom_out / x86_comparison.PROJECT:
        raise ValueError("Authenticated custom product is not under its exact receipted OUT_DIR")
    if x86_comparison.filesystem_trees_overlap(custom_source, custom_out):
        raise ValueError("Authenticated custom source and OUT_DIR alias or overlap")
    staged_signer = custom.get("source", {}).get("stage", {}).get(
        "development_certificate", {}).get("der_sha256")
    packet_signer = packet_wonad.get("certificate_der_sha256")
    if not isinstance(staged_signer, str) or not x86_comparison.SHA256.fullmatch(staged_signer) or \
            packet_signer != staged_signer:
        raise ValueError("Authenticated client APK signer differs from the custom OS staged signer")
    signer_evidence = verify_packet_systemui_signers(product, packet, packet_receipt, custom)

    protected_trees = []
    for receipt in (baseline, custom):
        locations = receipt.get("locations", {})
        for name in ("source", "out_dir"):
            protected_trees.append(exact_phase1_directory(
                Path(str(locations.get(name, ""))), f"{receipt.get('role')} receipt {name}"))
    for evidence in evidence_paths.values():
        if any(x86_comparison.within_filesystem(evidence, tree) for tree in protected_trees):
            raise ValueError("Phase-1 evidence files must remain outside both build trees")

    references = {name: phase1_file_ref(path) for name, path in evidence_paths.items()}
    return {
        "paths": evidence_paths,
        "references": references,
        "expected_sha256": {
            "comparison": inputs["comparison_sha256"],
            "baseline_receipt": inputs["baseline_receipt_sha256"],
            "custom_receipt": inputs["custom_receipt_sha256"],
            "client_packet_receipt": inputs["client_packet_receipt_sha256"],
        },
        "comparison": document,
        "baseline": baseline,
        "custom": custom,
        "product": str(product),
        "client_packet": {
            "directory": str(packet),
            "receipt": packet_receipt,
            "apk": apk_ref,
            "staged_signer_der_sha256": staged_signer,
            "systemui_fault_signer": signer_evidence,
        },
    }


def phase1_manifest_evidence(authenticated):
    comparison = authenticated["comparison"]
    baseline = authenticated["baseline"]
    custom = authenticated["custom"]
    rows = {}
    for name in PHASE1_EVIDENCE_NAMES:
        rows[name] = {
            "bundle_path": "/opt/wonad/build-evidence/" + PHASE1_EVIDENCE_NAMES[name],
            "expected_sha256": authenticated["expected_sha256"][name],
            "file": authenticated["references"][name],
        }
    rows["comparison"].update({
        "schema": comparison["schema"], "kind": comparison["kind"],
        "result": comparison["result"],
    })
    rows["baseline_receipt"].update({
        "role": baseline["role"], "fingerprint": baseline["fingerprint"],
        "container_id": baseline["container"]["id"],
    })
    rows["custom_receipt"].update({
        "role": custom["role"], "fingerprint": custom["fingerprint"],
        "container_id": custom["container"]["id"],
    })
    packet = authenticated["client_packet"]["receipt"]
    packet_apk = packet["artifacts"]["wonad"]
    signer_evidence = authenticated["client_packet"]["systemui_fault_signer"]
    signer_manifest = {key: value for key, value in signer_evidence.items()
                       if key != "_transcripts"}
    rows["client_packet_receipt"].update({
        "schema": packet["schema"],
        "kind": packet["kind"],
        "status": packet["status"],
        "development_only": packet["development_only"],
        "runtime_qualified": packet["runtime_qualified"],
        "packet_directory": authenticated["client_packet"]["directory"],
        "wonad_apk": {
            "bundle_path": "/opt/wonad/wonad.apk",
            "sha256": packet_apk["sha256"],
            "size": packet_apk["bytes"],
            "certificate_der_sha256": packet_apk["certificate_der_sha256"],
        },
        "staged_signer_der_sha256":
            authenticated["client_packet"]["staged_signer_der_sha256"],
        "systemui_fault_signer": signer_manifest,
    })
    return {
        "schema": 1,
        "scope": "authenticated-x86-clean-baseline-custom-build-evidence",
        "comparison": rows["comparison"],
        "baseline_receipt": rows["baseline_receipt"],
        "custom_receipt": rows["custom_receipt"],
        "client_packet": rows["client_packet_receipt"],
        "shared_fingerprint": comparison["shared"]["fingerprint"],
        "source_pin_sha256": comparison["shared"]["source_pin_sha256"],
        "selected_custom_build": {
            "source": custom["locations"]["source"],
            "out_dir": custom["locations"]["out_dir"],
            "product": custom["locations"]["product"],
        },
        "qualification_claimed": False,
    }


def copy_phase1_build_evidence(output, authenticated):
    directory = output / "build-evidence"
    directory.mkdir(mode=0o700)
    files = {}
    for name, destination_name in PHASE1_EVIDENCE_NAMES.items():
        source = authenticated["paths"][name]
        destination = directory / destination_name
        shutil.copyfile(source, destination)
        reference = phase1_file_ref(destination)
        if reference != authenticated["references"][name] or \
                phase1_file_ref(source) != authenticated["references"][name]:
            raise ValueError("Phase-1 build evidence changed while staging: " + name)
        files["/opt/wonad/build-evidence/" + destination_name] = reference["sha256"]
    signer_evidence = authenticated["client_packet"]["systemui_fault_signer"]
    for role, destination_name in PHASE1_SIGNER_TRANSCRIPTS.items():
        destination = directory / destination_name
        raw = signer_evidence["_transcripts"][role].encode()
        with destination.open("xb") as stream:
            stream.write(raw)
        reference = phase1_file_ref(destination)
        expected = signer_evidence[role]["transcript"]
        if reference != {"sha256": expected["sha256"], "size": expected["size"]}:
            raise ValueError("Phase-1 signer transcript changed while staging: " + role)
        files[expected["bundle_path"]] = reference["sha256"]
    return files


def recheck_phase1_build_evidence(authenticated):
    for name, path in authenticated["paths"].items():
        if phase1_file_ref(path) != authenticated["references"][name]:
            raise ValueError("Phase-1 build evidence changed during candidate staging: " + name)
    packet = Path(authenticated["client_packet"]["directory"])
    try:
        receipt = packet_tool.load(packet / "receipt.json")
        packet_tool.validate_receipt(
            packet, receipt, authenticated["expected_sha256"]["client_packet_receipt"],
            live_tools=False)
    except (ValueError, OSError) as error:
        raise ValueError("Phase-1 client packet changed during candidate staging: " + str(error)) from error
    if receipt != authenticated["client_packet"]["receipt"] or \
            phase1_file_ref(packet / "wonad.apk") != authenticated["client_packet"]["apk"]:
        raise ValueError("Phase-1 client packet or Wonad APK changed during candidate staging")


def stage(product, apk, output, image, runtime, base_manifest,
          phase1_evidence=None, require_phase1=False):
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", image):
        raise ValueError("Use an immutable local SDK base image ID")
    base_manifest = validate_base_manifest(base_manifest)
    if not exact_flat_mapping(base_manifest.get("emulator_client_composition"),
                              EMULATOR_CLIENT_COMPOSITION_ABI):
        raise ValueError("Immutable base lacks the exact current emulator client-composition ABI marker")
    if require_phase1 and phase1_evidence is None:
        raise ValueError("Strict Phase-1 candidate mode requires authenticated build evidence")
    if phase1_evidence is not None and not require_phase1:
        raise ValueError("Phase-1 evidence is accepted only in explicit strict mode")
    authenticated = authenticate_phase1_build_evidence(product, apk, phase1_evidence) \
        if require_phase1 else None
    inputs = {name: checked_file(product / name) for name in IMAGE_FILES}
    artifacts = {name: checked_file(product / relative) for name, relative in OS_PATHS.items()}
    apk_hash = checked_file(apk)
    notice_hash = checked_file(product / "system/etc/NOTICE.xml.gz")
    fingerprint = (product / "build_fingerprint-sdk_phone64_x86_64.txt").read_text().strip()
    if not re.fullmatch(r"Android/sdk_phone64_x86_64/emu64x:[^\s]+/wonad\.[0-9]+:userdebug/[^\s]+", fingerprint):
        raise ValueError("Expected the pinned custom x86-64 emulator product")
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    # Every inherited file was checked by the immutable base's verifier.  The
    # Dockerfile then removes both namespaces and restores only the reviewed
    # StyX/grsh support allowlist plus these fresh replacements.  Build evidence
    # describes this candidate, never an inherited predecessor.
    files = {name: checksum for name, checksum in base_manifest["files"].items()
             if not name.startswith("/opt/wonad/build-evidence/")}
    if authenticated is not None:
        files.update(copy_phase1_build_evidence(output, authenticated))
    else:
        (output / "build-evidence").mkdir(mode=0o700)
    for name, checksum in inputs.items():
        destination = output / "product" / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        subprocess.run(["cp", "--reflink=auto", "--sparse=always", str(product / name), str(destination)], check=True)
        if digest(destination) != checksum or checked_file(product / name) != checksum:
            raise ValueError("Candidate product changed while staging: " + name)
        files["/product/" + name] = checksum
    shutil.copyfile(apk, output / "wonad.apk")
    if digest(output / "wonad.apk") != apk_hash or checked_file(apk) != apk_hash:
        raise ValueError("Candidate APK changed while staging")
    files["/opt/wonad/wonad.apk"] = apk_hash
    artifacts["org.wonad.desktop"] = apk_hash
    for name, source in {
        "session.py": ROOT / "android/demo/session.py",
        "emulator_identity.py": ROOT / "android/demo/emulator_identity.py",
        "entrypoint.py": HERE / "entrypoint.py",
        "run-local.py": HERE / "run-local.py",
    }.items():
        checksum = checked_file(source)
        shutil.copyfile(source, output / name)
        if digest(output / name) != checksum or checked_file(source) != checksum:
            raise ValueError("Candidate runtime wrapper changed while staging: " + name)
        files["/opt/wonad/" + name] = checksum
    shutil.copyfile(HERE / "Dockerfile.native-candidate", output / "Dockerfile")
    shutil.copyfile(ROOT / "LICENSE", output / "LICENSE")
    shutil.copyfile(product / "system/etc/NOTICE.xml.gz", output / "NOTICE.xml.gz")
    source_archive(output / "sources.tar.gz")
    for name in ("sources.tar.gz", "NOTICE.xml.gz", "LICENSE"):
        files["/opt/wonad/notices/" + name] = checked_file(output / name)
    if digest(output / "NOTICE.xml.gz") != notice_hash or any(
        checked_file(product / relative) != artifacts[name] for name, relative in OS_PATHS.items()
    ):
        raise ValueError("Candidate OS artifacts changed while staging")
    if authenticated is not None:
        recheck_phase1_build_evidence(authenticated)
    base_manifest_sha256 = manifest_digest(base_manifest)
    manifest = dict(schema=1, architecture="amd64", api=3,
        scope="unqualified_native_v3_exact_bundle_candidate", fingerprint=fingerprint,
        files=files, os_artifacts=artifacts, candidate_base_image=image,
        candidate_base_manifest_sha256=base_manifest_sha256,
        emulator_runtime=runtime, emulator_files_sha256=runtime["sha256"],
        emulator_client_composition=dict(EMULATOR_CLIENT_COMPOSITION_ABI),
        emulator_client_composition_provenance=dict(schema=1,
            scope="unqualified_candidate_exact_base_and_bundled_entrypoint_marker",
            base_image=image, base_manifest_sha256=base_manifest_sha256,
            inherited_marker_exactly_matches_bundled_entrypoint=True,
            os_contract_qualification="not_claimed", runtime_qualification_claimed=False),
        native_emulator_backend_qualification="not_passed", native_multi_monitor_acceptance="not_passed",
        full_shell_acceptance="not_passed", hardware="emulator_only", unofficial=True,
        software_keyboard_ui="deferred", pixel10_hardware="not_tested", grapheneos_hardening="not_verified")
    if authenticated is not None:
        manifest["phase1_build_evidence"] = phase1_manifest_evidence(authenticated)
    (output / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    return manifest


def build_candidate(product, apk, output, image, tag, emulator_directory=None,
                    phase1_evidence=None, require_phase1=False):
    if require_phase1 and phase1_evidence is None:
        raise ValueError("Strict Phase-1 candidate mode requires authenticated build evidence")
    if phase1_evidence is not None and not require_phase1:
        raise ValueError("Phase-1 evidence is accepted only in explicit strict mode")
    if not re.fullmatch(r"wonad:native-v3-candidate-[a-z0-9][a-z0-9._-]*", tag):
        raise ValueError("Only explicitly unqualified wonad:native-v3-candidate-* tags are allowed")
    require_candidate_tag_absent(tag)
    base, reference = promotion_base(image)
    inherited = verified_base_manifest(image)
    if require_phase1:
        validate_phase1_base_image(image, base, inherited)
    runtime = base_runtime(image, emulator_directory)
    manifest = stage(product, apk, output, image, runtime, inherited,
                     phase1_evidence=phase1_evidence, require_phase1=require_phase1)
    if emulator_directory is not None:
        stage_emulator(emulator_directory, output, expected=runtime)
    identifier = output / "built-image.id"
    subprocess.run(["docker", "build", "--platform", "linux/amd64", "--iidfile", str(identifier),
                    "--build-arg", "CANDIDATE_BASE=" + reference, str(output)], check=True)
    candidate = identifier.read_text().strip()
    actual = inspect_image(candidate)
    layers = base["RootFS"]["Layers"]
    if actual["RootFS"]["Layers"][:len(layers)] != layers or base_runtime(candidate) != runtime:
        raise ValueError("Candidate changed the pinned SDK/graphics base; tag was not published")
    if require_phase1:
        validate_phase1_candidate_image(actual)
    verification = json.loads(subprocess.check_output([
        "docker", "run", "--rm", "--network", "none", "--read-only", "--entrypoint", "python3",
        candidate, "/opt/wonad/entrypoint.py", "verify"], text=True).split("\n", 1)[1])
    if verification != manifest:
        raise ValueError("Candidate bundle verification differs; tag was not published")
    publish_candidate(candidate, tag)
    return candidate


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("product", "apk", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--base-image", required=True, help="Immutable local image ID with the tested SDK/graphics")
    parser.add_argument("--emulator-directory", type=Path,
                        help="Explicit new immutable SDK; complete replacement in the NEW unqualified image only")
    parser.add_argument("--phase1-build-evidence", action="store_true",
                        help="require and embed authenticated clean-baseline/custom x86 evidence")
    parser.add_argument("--phase1-comparison", type=Path)
    parser.add_argument("--phase1-comparison-sha256")
    parser.add_argument("--phase1-baseline-receipt", type=Path)
    parser.add_argument("--phase1-baseline-receipt-sha256")
    parser.add_argument("--phase1-custom-receipt", type=Path)
    parser.add_argument("--phase1-custom-receipt-sha256")
    parser.add_argument("--phase1-client-packet", type=Path)
    parser.add_argument("--phase1-client-packet-receipt-sha256")
    parser.add_argument("--tag", required=True)
    args = parser.parse_args()
    phase1_values = (
        args.phase1_comparison, args.phase1_comparison_sha256,
        args.phase1_baseline_receipt, args.phase1_baseline_receipt_sha256,
        args.phase1_custom_receipt, args.phase1_custom_receipt_sha256,
        args.phase1_client_packet, args.phase1_client_packet_receipt_sha256,
    )
    if args.phase1_build_evidence != all(value is not None for value in phase1_values) or \
            (not args.phase1_build_evidence and any(value is not None for value in phase1_values)):
        parser.error("--phase1-build-evidence requires all eight OS/client evidence path and SHA-256 options")
    product = exact_phase1_directory(args.product, "selected Phase-1 product") \
        if args.phase1_build_evidence else args.product.resolve(strict=True)
    apk = exact_phase1_file(args.apk, "selected Phase-1 Wonad APK") \
        if args.phase1_build_evidence else args.apk.resolve(strict=True)
    output = args.output.resolve()
    if not output.is_relative_to(ROOT / "android/out") or output == ROOT / "android/out":
        parser.error("Use a fresh staging directory under android/out")
    # Keep the original path until base_runtime checks it: resolving here
    # would silently turn a forbidden SDK-directory symlink into a real path.
    sdk = args.emulator_directory
    if args.phase1_build_evidence:
        evidence = phase1_evidence_inputs(
            args.phase1_comparison, args.phase1_comparison_sha256,
            args.phase1_baseline_receipt, args.phase1_baseline_receipt_sha256,
            args.phase1_custom_receipt, args.phase1_custom_receipt_sha256,
            args.phase1_client_packet, args.phase1_client_packet_receipt_sha256)
        print(build_candidate(product, apk, output, args.base_image, args.tag, sdk,
                              phase1_evidence=evidence, require_phase1=True))
    else:
        print(build_candidate(product, apk, output, args.base_image, args.tag, sdk))


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        print(str(error), file=sys.stderr)
        raise SystemExit(1)
