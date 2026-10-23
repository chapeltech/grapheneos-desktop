"""Separate authenticated OS source binding for the two broker-dispatch cases.

Host TEST/instrumentation sources are not sources of the installed SystemUI.
Use the admitted bundle's archive and build-receipt hashes, not caller-provided
source hashes or the current host controller. No source is extracted over a
checkout; only two unique regular members are copied into fresh evidence files.
"""
import ast
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import tarfile
from types import FunctionType, SimpleNamespace

from native_backend_acceptance import require
import x86_build_comparison as comparison

MANIFEST = "/opt/wonad/manifest.json"
ARCHIVE = "/opt/wonad/notices/sources.tar.gz"
RECEIPT = "/opt/wonad/build-evidence/x86-custom-receipt.json"
INPUTS = {
    MANIFEST: "broker-dispatch-os-bundle-manifest.json",
    ARCHIVE: "broker-dispatch-os-sources.tar.gz",
    RECEIPT: "broker-dispatch-os-custom-receipt.json",
}
MEMBERS = {
    "android/os-integration/src/org/wonad/desktop/broker/NativeDesktopController.kt":
        "broker-dispatch-os-NativeDesktopController.kt",
    "android/broker-core/src/main/kotlin/org/wonad/desktop/broker/BrokerDispatch.kt":
        "broker-dispatch-os-BrokerDispatch.kt",
}
DEFINITIONS = ("android/container/build.py", "android/container/build-native-candidate.py")
LOCK_MEMBER = "android/grapheneos.lock.json"
LOCK_FILE = "broker-dispatch-os-archived-grapheneos.lock.json"
STAGE_CONTRACT_MEMBER = "android/tools/stage_contract.py"
SYSTEMUI = "/system_ext/priv-app/SystemUI/SystemUI.apk"
SCOPE = "authenticated_compiled_systemui_broker_dispatch_os_sources_not_host_checkout"


def raw_file(directory, name):
    path = directory / name
    require(path.resolve(strict=True) == path.absolute() and path.is_file() and not path.is_symlink(),
            "OS source evidence is not a canonical regular file: " + name)
    raw, record = comparison.stable_bytes(path)
    require(record["size"] <= 64 * 1024 ** 2, "OS source evidence exceeds bounded size")
    return raw


def archive_members(raw, names=MEMBERS):
    result = {}
    try:
        with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as archive:
            inventory = archive.getmembers()
            # Do not accept aliases which normalize to a required member.
            for entry in inventory:
                name = PurePosixPath(entry.name)
                require(not name.is_absolute() and ".." not in name.parts and
                        name.as_posix() == entry.name, "Noncanonical OS source archive member")
            for name in names:
                entries = [entry for entry in inventory if entry.name == name]
                require(len(entries) == 1 and entries[0].isreg() and
                        0 < entries[0].size <= 2 * 1024 ** 2,
                        "Missing, duplicate or nonregular OS source member: " + name)
                stream = archive.extractfile(entries[0])
                require(stream is not None, "Unreadable OS source member")
                content = stream.read()
                require(len(content) == entries[0].size, "Incomplete OS source member")
                result[name] = content
    except (tarfile.TarError, OSError) as error:
        raise ValueError("Invalid OS corresponding-source archive") from error
    return result


def archived_literal(content, name, kind):
    """Read archived artifact definitions without executing archived tools."""
    try:
        tree = ast.parse(content)
        assignments = [node for node in tree.body if isinstance(node, ast.Assign) and
                       any(isinstance(target, ast.Name) and target.id == name for target in node.targets)]
        require(len(assignments) == 1, "Missing/duplicate archived artifact definition: " + name)
        value = ast.literal_eval(assignments[0].value)
    except (SyntaxError, ValueError, TypeError) as error:
        raise ValueError("Invalid archived literal artifact definition: " + name) from error
    require(type(value) is kind, "Archived artifact definition has wrong type: " + name)
    return value


def historical_stage_view(archive_raw, marker):
    """Authenticated old declarations/patch bytes, never archived tool execution."""
    raw = archive_members(archive_raw, (STAGE_CONTRACT_MEMBER,))[STAGE_CONTRACT_MEMBER]
    require(hashlib.sha256(raw).hexdigest() == marker.get("tools", {}).get(STAGE_CONTRACT_MEMBER),
            "Archived stage-contract bytes differ from authenticated original marker")
    contract = comparison.stage_contract
    families = {
        "frameworks_base": ("frameworks/base", "FRAMEWORK_PATCH_NAMES", "frameworks_revision"),
        "launcher3": ("packages/apps/Launcher3", "LAUNCHER_PATCH_NAMES", "launcher3_revision"),
        "emulator_goldfish": ("device/generic/goldfish", "EMULATOR_PATCH_NAMES", "emulator_goldfish_revision"),
    }
    declarations = [node for node in ast.parse(raw).body if isinstance(node, ast.Assign) and
                    any(isinstance(target, ast.Name) and target.id == "NATIVE_PATCH_NAMES"
                        for target in node.targets)]
    # The original authenticated schema4 contract predates the native registry.
    # An absent declaration means that exact historical contract had no native
    # lane, not that a supplied marker may silently omit a required lane.
    require((not declarations or archived_literal(raw, "NATIVE_PATCH_NAMES", tuple) == ()) and
            type(marker.get("schema")) is int and marker["schema"] == 4 and
            set(marker) == {"schema", "signer_sha256", "signer_certificate", "files", "patches",
                            "platform_targets", "tools", "frameworks_revision", "launcher3_revision",
                            "emulator_goldfish_revision"},
            "Historical source binding admits only reviewed original schema4 patch families")
    lanes = {}
    for label, (project, declaration, revision) in families.items():
        names = archived_literal(raw, declaration, tuple)
        require(names and len(names) == len(set(names)) and set(names) <= set(getattr(contract, declaration)),
                "Unreviewed historical stage patch declaration")
        lanes[label] = (project, names, revision)
    names = tuple(dict.fromkeys(name for _, family, _ in lanes.values() for name in family))
    patches = archive_members(archive_raw, ("android/platform/patches/" + name for name in names))
    ledger = {label: [dict(name=name, sha256=hashlib.sha256(
        patches["android/platform/patches/" + name]).hexdigest()) for name in family]
        for label, (_, family, _) in lanes.items()}
    require(marker.get("patches") == ledger, "Historical archived patch bytes differ from original stage ledger")
    def memory_patches(selected):
        return [SimpleNamespace(name=name, read_text=lambda name=name:
                patches["android/platform/patches/" + name].decode("utf-8")) for name in selected]
    original = contract.patch_target_names
    targets = FunctionType(original.__code__, dict(original.__globals__, patches=memory_patches),
                           original.__name__, original.__defaults__, original.__closure__)
    original = contract.marker_owned_targets
    owned = FunctionType(original.__code__, dict(original.__globals__,
        platform_lanes=lambda: lanes, patch_target_names=targets, NATIVE_PATCH_NAMES=(),
        require_stage_schema=lambda value: require(value is marker,
            "Historical stage view used with a different marker")),
        original.__name__, original.__defaults__, original.__closure__)
    return SimpleNamespace(**dict(vars(contract), marker_owned_targets=owned,
                                 NATIVE_PATCH_NAMES=(), stage_schema=lambda: 4))


def historical_source_receipt(raw, expected_sha, archive_raw, archived_lock):
    """Authenticated original schema4 source/artifacts, NOT current full-build recapture.

    Current comparison.verify deliberately rejects changed artifact-definition
    tools. Preserve that current validator; independently require the original
    admitted receipt's definition bytes from its admitted archive and use the
    existing stage/source/artifact validators for this narrow historical scope.
    """
    require(hashlib.sha256(raw).hexdigest() == expected_sha,
            "Historical source receipt differs from admitted expected receipt")
    receipt = comparison.parse_json(raw, "original authenticated OS source receipt")
    require(isinstance(receipt, dict) and set(receipt) == {
        "schema", "kind", "role", "scope", "build_contract", "locations", "builder",
        "source", "artifact_definitions", "fingerprint", "artifacts", "build_log",
        "build_engine", "container", "launch_evidence", "verification_tools", "generator",
    } and type(receipt["schema"]) is int and receipt["schema"] == 4 and
        receipt["kind"] == "wonad-x86-build-comparison-input" and receipt["role"] == "custom" and
        receipt["scope"] == "build-comparison-only-not-runtime-qualification" and
        receipt["build_contract"] == comparison.BUILD_CONTRACT,
        "Unsupported authenticated historical OS source receipt/schema")
    tools = archive_members(archive_raw, (*DEFINITIONS, LOCK_MEMBER))
    lock_raw = raw_file(archived_lock.parent, archived_lock.name)
    lock_ref = dict(sha256=hashlib.sha256(lock_raw).hexdigest(), size=len(lock_raw))
    require(lock_raw == tools[LOCK_MEMBER] and receipt["source"]["pin"]["lock"] == lock_ref,
            "Historical source lock differs from authenticated archive/receipt pin")
    require(receipt["source"]["stage"]["marker"].get("tools", {}).get(LOCK_MEMBER) == lock_ref["sha256"],
            "Historical archived lock differs from original stage-tool lock binding")
    lock_document = comparison.parse_json(lock_raw, "authenticated archived public lock")
    require(lock_document.get("device") in {"frankel", "shiba"},
            "Unreviewed device in authenticated historical x86 lock")
    # Historical emulator receipts can select Frankel or Shiba. Reuse every
    # current lock check except that one authenticated historical device
    # selection, inside an isolated function/namespace. Preserve actual bytes
    # and values; never rewrite the old lock or change current global policy.
    provenance = comparison.provenance
    original_lock_validator = provenance.validate_lock
    def historical_require(condition, message):
        if message == "GrapheneOS lock must select frankel" and lock_document["device"] == "shiba":
            return
        provenance.require(condition, message)
    isolated_lock_validator = FunctionType(original_lock_validator.__code__,
        dict(original_lock_validator.__globals__, require=historical_require),
        original_lock_validator.__name__, original_lock_validator.__defaults__, original_lock_validator.__closure__)
    historical_provenance = SimpleNamespace(**dict(vars(provenance), validate_lock=isolated_lock_validator))
    historical_stage = historical_stage_view(archive_raw, receipt["source"]["stage"]["marker"])
    original = comparison.marker_owned_targets
    historical_owned = FunctionType(original.__code__, dict(original.__globals__, stage_contract=historical_stage),
        original.__name__, original.__defaults__, original.__closure__)
    original = comparison.validate_custom_stage_inventory
    historical_inventory = FunctionType(original.__code__, dict(original.__globals__,
        marker_owned_targets=historical_owned), original.__name__, original.__defaults__, original.__closure__)
    # Reuse source-validator logic in an isolated globals dictionary too.
    # Never swap comparison.LOCK or execute/import archived Python tools.
    original = comparison.validate_source_shape
    historical_source_validator = FunctionType(original.__code__,
        dict(original.__globals__, LOCK=archived_lock, provenance=historical_provenance,
             stage_contract=historical_stage, marker_owned_targets=historical_owned,
             validate_custom_stage_inventory=historical_inventory),
        original.__name__, original.__defaults__, original.__closure__)
    historical_source_validator(receipt["source"], "custom")
    locations = receipt["locations"]
    require(isinstance(locations, dict) and set(locations) == {"source", "out_dir", "product", "build_log"} and
            all(isinstance(value, str) and Path(value).is_absolute() for value in locations.values()) and
            locations["product"] == str(Path(locations["out_dir"]) / comparison.PROJECT),
            "Invalid historical receipt locations")
    images = archived_literal(tools[DEFINITIONS[0]], "IMAGE_FILES", tuple)
    paths = archived_literal(tools[DEFINITIONS[1]], "OS_PATHS", dict)
    old_names = {"com.android.systemui", "os_broker_native", "os_input_native", "os_services", "os_framework"}
    require(images == comparison.IMAGE_FILES and set(paths) in (old_names, set(comparison.OS_PATHS)) and
            all(comparison.OS_PATHS.get(name) == value for name, value in paths.items()),
            "Unreviewed archived historical artifact shape")
    definitions = dict(image_files=list(images), os_paths=paths, definition_files={
        name: dict(sha256=hashlib.sha256(tools[name]).hexdigest(), size=len(tools[name])) for name in DEFINITIONS})
    require(receipt["artifact_definitions"] == definitions,
            "Original archived tool definition bytes differ from authenticated receipt")
    artifacts = receipt["artifacts"]
    require(isinstance(artifacts, dict) and set(artifacts) == {"images", "os_artifacts"} and
            set(artifacts["images"]) == set(images) and set(artifacts["os_artifacts"]) == set(paths),
            "Historical receipt artifact inventory differs from archived definitions")
    for name, row in artifacts["images"].items():
        comparison.validate_file_row(row)
        require(row["path"] == name, "Historical image artifact path differs")
    for name, row in artifacts["os_artifacts"].items():
        comparison.validate_file_row(row)
        require(row["path"] == paths[name] and row["state"] == "present",
                "Historical OS artifact path/state differs")
    return receipt


def derive_os_source_binding(directory, admitted_manifest, actual_systemui, image):
    """Re-derive from original files and admitted inputs; no source digest argument."""
    require(isinstance(image, str) and re.fullmatch(r"sha256:[0-9a-f]{64}", image) and
            isinstance(actual_systemui, dict) and actual_systemui.get("path") == SYSTEMUI and
            re.fullmatch(r"[0-9a-f]{64}", str(actual_systemui.get("sha256", ""))),
            "Missing actual admitted SystemUI/image identity")
    raw = {remote: raw_file(directory, name) for remote, name in INPUTS.items()}
    manifest = comparison.parse_json(raw[MANIFEST], "captured admitted bundle manifest")
    require(isinstance(admitted_manifest, dict) and manifest == admitted_manifest,
            "Captured OS-source manifest differs from admitted bundle")
    files = manifest.get("files", {})
    row = manifest.get("phase1_build_evidence", {}).get("custom_receipt", {})
    receipt_sha = row.get("expected_sha256")
    require(isinstance(files, dict) and row.get("bundle_path") == RECEIPT and row.get("role") == "custom" and
            re.fullmatch(r"[0-9a-f]{64}", str(receipt_sha)) and files.get(RECEIPT) == receipt_sha and
            row.get("file", {}).get("sha256") == receipt_sha and
            re.fullmatch(r"[0-9a-f]{64}", str(files.get(ARCHIVE, ""))),
            "Admitted bundle lacks its exact authenticated custom receipt/archive")
    hashes = {remote: hashlib.sha256(value).hexdigest() for remote, value in raw.items()}
    require(hashes[ARCHIVE] == files[ARCHIVE] and hashes[RECEIPT] == receipt_sha,
            "OS archive/receipt differs from admitted bundle hashes")
    receipt = historical_source_receipt(raw[RECEIPT], receipt_sha, raw[ARCHIVE], directory / LOCK_FILE)
    require(receipt["role"] == "custom" and receipt["fingerprint"] == manifest.get("fingerprint") ==
            row.get("fingerprint"), "OS source receipt has wrong role/fingerprint")
    compiled = receipt["artifacts"]["os_artifacts"]["com.android.systemui"]
    require(compiled["state"] == "present" and compiled["path"] == SYSTEMUI.removeprefix("/") and
            compiled["sha256"] == manifest.get("os_artifacts", {}).get("com.android.systemui") ==
            actual_systemui["sha256"], "OS source receipt does not build the actual admitted SystemUI")
    require(len(raw[RECEIPT]) == row["file"].get("size"), "OS receipt size differs from admitted bundle")
    source = receipt["source"]
    marker, generated = source["stage"]["marker"], source["generated_inputs"]
    contents = archive_members(raw[ARCHIVE])
    members = {}
    for name, content in contents.items():
        staged = name.removeprefix("android/")
        expected = marker["files"].get(staged)
        generated_row = generated.get("external/wonad/" + staged, {})
        actual = hashlib.sha256(content).hexdigest()
        require(expected == actual == generated_row.get("sha256") and
                len(content) == generated_row.get("size"),
                "Archived OS source differs from authenticated stage/compile input: " + name)
        copied = directory / MEMBERS[name]
        if copied.exists() or copied.is_symlink():
            require(raw_file(directory, MEMBERS[name]) == content, "Copied OS source differs from archive")
        members[name] = dict(path=MEMBERS[name], sha256=actual, bytes=len(content),
                             staged_path="external/wonad/" + staged)
    return dict(schema=1, scope=SCOPE, image=image, manifest=dict(path=INPUTS[MANIFEST], sha256=hashes[MANIFEST]),
                archive=dict(path=INPUTS[ARCHIVE], sha256=hashes[ARCHIVE], bundle_path=ARCHIVE),
                custom_receipt=dict(path=INPUTS[RECEIPT], sha256=receipt_sha, bundle_path=RECEIPT),
                stage_marker_sha256=source["stage"]["marker_sha256"],
                validation_scope="authenticated_historical_schema4_source_artifacts_not_current_full_build_recapture",
                original_artifact_definitions=receipt["artifact_definitions"],
                archived_lock=dict(path=LOCK_FILE, **receipt["source"]["pin"]["lock"],
                                   device=comparison.parse_json(raw_file(directory, LOCK_FILE), "archived lock")["device"],
                                   scope="authenticated_historical_lock_not_current_production_selection"),
                systemui=dict(path=SYSTEMUI, sha256=actual_systemui["sha256"]), members=members,
                host_controller_used_as_runtime_proof=False)


def source_binding_commands(trace, container, directory, binding):
    require(isinstance(trace, list) and re.fullmatch(r"[0-9a-f]{64}", str(container)),
            "Missing owned OS source trace")
    indices = []
    for remote, name in INPUTS.items():
        expected = ["docker", "cp", container + ":" + remote, str(directory / name)]
        attempts = [(index, row) for index, row in enumerate(trace) if isinstance(row, dict) and
                    isinstance(row.get("command"), list) and len(row["command"]) == 4 and
                    row["command"][:2] == ["docker", "cp"] and
                    (str(row["command"][2]).endswith(":" + remote) or Path(str(row["command"][3])).name == name)]
        require(len(attempts) == 1 and attempts[0][1]["command"] == expected and
                "error" not in attempts[0][1] and type(attempts[0][1].get("output")) is str,
                "Missing/foreign/duplicate original owned OS source copy: " + name)
        indices.append(attempts[0][0])
    expected = ["docker", "exec", container, "sha256sum", *INPUTS]
    reads = [(index, row) for index, row in enumerate(trace) if isinstance(row, dict) and
             isinstance(row.get("command"), list) and row["command"][:2] == ["docker", "exec"] and
             row["command"][3:] == expected[3:]]
    require(len(reads) == 1 and reads[0][1]["command"] == expected and "error" not in reads[0][1] and
            type(reads[0][1].get("output")) is str and indices == sorted(indices) and
            max(indices) < reads[0][0], "Missing exact owned OS source checksum read/order")
    rows = reads[0][1]["output"].splitlines()
    observed = {}
    for line in rows:
        match = re.fullmatch(r"([0-9a-f]{64})  (/.+)", line)
        require(match is not None and match[2] not in observed, "Malformed/duplicate OS source checksum")
        observed[match[2]] = match[1]
    require(observed == {remote: binding[key]["sha256"] for remote, key in
            ((MANIFEST, "manifest"), (ARCHIVE, "archive"), (RECEIPT, "custom_receipt"))},
            "Original owned OS source bytes differ from captured originals")
    return dict(copy_indices=indices, sha256_index=reads[0][0])


def capture_os_source_binding(test):
    directory = Path(test.output).absolute()
    require(directory.resolve(strict=True) == directory, "Aliased OS source evidence output")
    for name in (*INPUTS.values(), *MEMBERS.values(), LOCK_FILE):
        require(not os.path.lexists(directory / name), "Unexpected existing OS source evidence: " + name)
    for remote, name in INPUTS.items():
        test.owned()
        test.host("docker", "cp", test.identity + ":" + remote, str(directory / name))
    test.owned()
    test.host("docker", "exec", test.identity, "sha256sum", *INPUTS)
    lock_raw = archive_members(raw_file(directory, INPUTS[ARCHIVE]), (LOCK_MEMBER,))[LOCK_MEMBER]
    with (directory / LOCK_FILE).open("xb") as stream:
        stream.write(lock_raw)
    binding = derive_os_source_binding(directory, test.report["manifest"],
        test.native_evidence.initial["artifacts"]["com.android.systemui"], test.report["image_id"])
    contents = archive_members(raw_file(directory, INPUTS[ARCHIVE]))
    for name, value in contents.items():
        with (directory / MEMBERS[name]).open("xb") as stream:
            stream.write(value)
    binding["command_binding"] = source_binding_commands(test.trace, test.identity, directory, binding)
    return binding


def audit_os_source_binding(report, directory, common, checks, trace):
    from native_security_acceptance import sealed

    declared = checks.get("os_source_binding")
    require(isinstance(declared, dict), "Missing required OS source observations")
    for name in (*INPUTS.values(), *MEMBERS.values(), LOCK_FILE):
        sealed(common, directory, name)
    actual = derive_os_source_binding(directory, report.get("startup", report).get("manifest"),
        common["artifacts"]["com.android.systemui"], common["candidate_runtime"]["image_id"])
    actual["command_binding"] = source_binding_commands(trace, common["container"], directory, actual)
    require(actual == declared, "Declared runtime OS source proof differs from authenticated originals")
    return actual


def audit_dispatch_product_mode(report, directory, common, trace, binding):
    """Re-read actual isolated StartupSmoke mounts and bundled image inventory.

    No CLI flag or reference-path label admits an image. The explicit override
    retains its original read-only mount mode; bundled mode requires real
    no-product-mount observations plus before/after runtime bytes and sizes.
    """
    from native_backend_acceptance import IMAGE_NAMES
    from startup_regression_smoke import StartupSmoke

    startup = report.get("startup", report)
    cid, image = common["container"], common["candidate_runtime"]["image_id"]
    override = startup.get("product_override")
    inventory = startup.get("bundled_product_inventory")
    require((override is None) != (inventory is None), "Ambiguous/missing dispatch product mode")
    product = None
    if override is not None:
        require(isinstance(override, dict) and isinstance(override.get("path"), str) and
                Path(override["path"]).is_absolute() and override.get("files") ==
                {name: row["sha256"] for name, row in common["product_images"].items()},
                "Explicit dispatch product override differs from observed reference images")
        product = Path(override["path"])
    live = []
    for index, row in enumerate(trace):
        if row.get("command") != ["docker", "inspect", cid] or "error" in row:
            continue
        infos = comparison.parse_json(row.get("output", ""), "dispatch owned-container observation")
        require(isinstance(infos, list) and len(infos) == 1 and isinstance(infos[0], dict),
                "Malformed actual dispatch container inspection")
        info = infos[0]
        if info.get("State", {}).get("Running") is not True:
            continue
        require(info.get("Id") == cid and info.get("Image") == image and
                isinstance(info.get("Mounts"), list) and
                len({item.get("Destination") for item in info["Mounts"]}) == len(info["Mounts"]) and
                all(item.get("Type") == "tmpfs" for item in info["Mounts"] if item.get("Destination") == "/tmp"),
                "Dispatch container image/mount identity changed")
        # Reuse the exact live producer's existing isolation policy. This host
        # model returns sealed original inspect bytes; it issues no command.
        observer = SimpleNamespace(identity=cid, run=common["run"], product=product,
            state=directory / "emulator-state", host=lambda *args, raw=row["output"]: raw)
        StartupSmoke.owned(observer)
        live.append(index)
    require(len(live) >= 2, "Missing repeated actual isolated dispatch container observations")
    if override is not None:
        return "explicit_readonly_product_override"
    require(isinstance(inventory, dict) and set(inventory) == {"images", "manifest_sha256"} and
            inventory["images"] == common["product_images"] and
            inventory["manifest_sha256"] == binding["manifest"]["sha256"],
            "Bundled dispatch product inventory differs from authenticated originals")
    names = ["/product/" + name for name in IMAGE_NAMES]
    commands = {
        "hashes": ["docker", "exec", cid, "sha256sum", *names, MANIFEST],
        "sizes": ["docker", "exec", cid, "stat", "-c", "%n:%s", *names],
        "manifest": ["docker", "exec", cid, "cat", MANIFEST],
    }
    indices = {}
    for kind, command in commands.items():
        reads = [(i, row) for i, row in enumerate(trace) if row.get("command", [])[:2] == command[:2] and
                 row.get("command", [])[3:] == command[3:]]
        require(len(reads) >= 2 and all(row.get("command") == command and "error" not in row and
                isinstance(row.get("output"), str) for _, row in reads),
                "Missing/foreign/failed before-after bundled dispatch inventory: " + kind)
        indices[kind] = [i for i, _ in reads]
        for _, row in reads:
            if kind == "manifest":
                require(comparison.parse_json(row["output"], "actual bundled dispatch manifest") == startup["manifest"],
                        "Actual bundled dispatch manifest changed")
            elif kind == "hashes":
                expected = [common["product_images"][name]["sha256"] + "  /product/" + name for name in IMAGE_NAMES]
                expected.append(binding["manifest"]["sha256"] + "  " + MANIFEST)
                require(row["output"].splitlines() == expected, "Actual bundled dispatch image/manifest bytes differ")
            else:
                require(row["output"].splitlines() == ["/product/" + name + ":" +
                        str(common["product_images"][name]["bytes"]) for name in IMAGE_NAMES],
                        "Actual bundled dispatch image sizes differ")
    for name in IMAGE_NAMES:
        require(startup["manifest"].get("files", {}).get("/product/" + name) ==
                common["product_images"][name]["sha256"], "Bundled dispatch image differs from admitted manifest")
    probes = [i for i, row in enumerate(trace) if "instrumentation_args" in row]
    require(probes and live[0] < min(indices["hashes"]) < min(probes) <= max(probes) <
            max(indices["hashes"]) < live[-1] and
            min(indices["sizes"]) < min(probes) and max(probes) < max(indices["sizes"]),
            "Bundled dispatch inventory/ownership does not bracket actual probes")
    return "actual_bundled_product_with_reference_only"
