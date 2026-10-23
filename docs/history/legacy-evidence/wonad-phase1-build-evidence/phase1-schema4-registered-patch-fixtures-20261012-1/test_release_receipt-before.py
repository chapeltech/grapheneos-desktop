import hashlib
import importlib.util
import json
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch
import zipfile


ANDROID = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "release_receipt", ANDROID / "tools/release_receipt.py")
receipt = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(receipt)
LOCK = json.loads((ANDROID / "grapheneos.lock.json").read_text())
BUILD = "2026101000"
TIMESTAMP = 1791288000
CERTIFICATE = b"synthetic public certificate DER" * 10
SIGNER = hashlib.sha256(CERTIFICATE).hexdigest()


def digest(data):
    if isinstance(data, str):
        data = data.encode()
    return hashlib.sha256(data).hexdigest()


class ReleaseReceipt(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.source = Path(self.temporary.name) / "grapheneos"
        self.source.mkdir()
        (self.source / ".repo/manifests").mkdir(parents=True)
        (self.source / "frameworks/base").mkdir(parents=True)
        (self.source / "packages/apps/Launcher3").mkdir(parents=True)
        (self.source / "packages/apps/Updater/res/values").mkdir(parents=True)
        (self.source / "device/generic/goldfish/input").mkdir(parents=True)
        staged = self.source / "external/wonad"
        staged.mkdir(parents=True)
        staged_file = staged / "broker/Broker.kt"
        staged_file.parent.mkdir()
        staged_file.write_text("package fixture\n")
        staged_certificate = staged / "WonadReleaseCertificate.der"
        staged_certificate.write_bytes(CERTIFICATE)
        framework_target = self.source / "frameworks/base/services/wonad-hook.java"
        framework_target.parent.mkdir(parents=True)
        framework_target.write_text("framework fixture\n")
        launcher_target = self.source / "packages/apps/Launcher3/src/wonad-hook.kt"
        launcher_target.parent.mkdir(parents=True)
        launcher_target.write_text("launcher fixture\n")
        emulator_target = self.source / "device/generic/goldfish/input/qwerty2.kl"
        emulator_target.write_text("emulator fixture\n")
        stage_marker = {
            "schema": 4,
            "frameworks_revision": LOCK["frameworks_base"]["commit"],
            "launcher3_revision": LOCK["launcher3"]["commit"],
            "emulator_goldfish_revision": LOCK["emulator_goldfish"]["commit"],
            "signer_sha256": SIGNER,
            "signer_certificate": {"path": "WonadReleaseCertificate.der",
                                   "sha256": SIGNER, "size": len(CERTIFICATE)},
            "files": {"broker/Broker.kt": digest(staged_file.read_bytes()),
                      "WonadReleaseCertificate.der": SIGNER},
            "patches": {
                "frameworks_base": receipt.stage_contract.patch_ledger(
                    receipt.stage_contract.FRAMEWORK_PATCH_NAMES),
                "launcher3": receipt.stage_contract.patch_ledger(
                    receipt.stage_contract.LAUNCHER_PATCH_NAMES),
                "emulator_goldfish": receipt.stage_contract.patch_ledger(
                    receipt.stage_contract.EMULATOR_PATCH_NAMES),
            },
            "platform_targets": {
                "frameworks_base": {"services/wonad-hook.java": digest(framework_target.read_bytes())},
                "launcher3": {"src/wonad-hook.kt": digest(launcher_target.read_bytes())},
                "emulator_goldfish": {"input/qwerty2.kl": digest(emulator_target.read_bytes())},
            },
            "tools": receipt.stage_contract.tool_ledger(),
        }
        (staged / ".wonad-stage.json").write_text(json.dumps(stage_marker))
        config = self.source / receipt.UPDATER_CONFIG
        config.write_text('<resources><string name="url">https://updates.wonad.example/</string></resources>')
        updater_marker = {
            "schema": 1,
            "updater_revision": LOCK["updater"]["commit"],
            "update_url": "https://updates.wonad.example/releases/",
            "baseline_sha256": "b" * 64,
            "configured_sha256": digest(config.read_bytes()),
        }
        (self.source / receipt.UPDATER_MARKER).write_text(json.dumps(updater_marker))
        self.release = receipt.release_directory(self.source, BUILD)
        self.release.mkdir(parents=True)
        self.roles = receipt.artifact_roles(BUILD)
        for role, name in self.roles.items():
            path = self.release / name
            if role.startswith("channel_"):
                channel = role.removeprefix("channel_")
                path.write_text(f"{BUILD} {TIMESTAMP} frankel {channel}\n")
            elif role == "full_ota":
                with zipfile.ZipFile(path, "w") as archive:
                    archive.writestr(
                        "META-INF/com/android/metadata",
                        "post-build=wonad/frankel/frankel:17/FIXTURE/"
                        f"{BUILD}:user/release-keys\n"
                        f"post-timestamp={TIMESTAMP}\n"
                        "pre-device=frankel\n")
                    archive.writestr("payload.bin", b"fixture payload")
            else:
                path.write_bytes((role + "\n").encode())
        # GrapheneOS leaves the extracted otatools in release-frankel-*; they
        # are evidence too, not an allow-listed blind spot.
        tool = self.release / "bin/sign_target_files_apks"
        tool.parent.mkdir()
        tool.write_bytes(b"fixture release tool\n")
        (self.release / ".find-ignore").write_bytes(b"")
        self.write_phase1_evidence()
        self.revisions = {
            (self.source / ".repo/manifests").resolve(): LOCK["manifest"]["commit"],
            (self.source / "frameworks/base").resolve(): LOCK["frameworks_base"]["commit"],
            (self.source / "packages/apps/Launcher3").resolve(): LOCK["launcher3"]["commit"],
            (self.source / "packages/apps/Updater").resolve(): LOCK["updater"]["commit"],
            (self.source / "device/generic/goldfish").resolve():
                LOCK["emulator_goldfish"]["commit"],
        }

    def write_phase1_evidence(self):
        provenance = receipt.phase1_provenance
        root = self.release / receipt.PROVENANCE_DIRECTORY
        (root / "sdk").mkdir(parents=True)
        (root / "compile/source/android/conformance").mkdir(parents=True)
        signed = root / "conformance.apk"
        signed.write_bytes(b"signed conformance apk")
        certificate = root / "signer-certificate.x509"
        certificate.write_bytes(CERTIFICATE)
        sdk = root / "sdk/publication.bin"
        sdk.write_bytes(b"sdk publication")
        frozen = root / "compile/source/android/conformance/Main.kt"
        frozen.write_text("package org.wonad.desktop\n")
        unsigned = root / "compile/conformance-unsigned.apk"
        unsigned.write_bytes(b"unsigned conformance apk")
        freeze = root / "compile/source-freeze.json"
        frozen_ref = receipt.hash_file(frozen)
        freeze_files = {"android/conformance/Main.kt": {
            "sha256": frozen_ref["sha256"], "bytes": frozen_ref["size"]}}
        freeze.write_text(json.dumps({"schema": 1, "kind": "fixture", "files": freeze_files}))
        compile_receipt = root / "compile/build-receipt.json"
        compile_receipt.write_text(json.dumps({"schema": 1, "fixture": True}))

        builder_image = {
            "id": LOCK["builder"]["image_digest"], "repo_digests": [],
            "os": "linux", "architecture": "amd64", "size": 1,
            "rootfs": {"type": "layers", "layers": ["sha256:" + "1" * 64]},
            "config": {"User": "builder",
                       "Env": ["PATH=/opt/node/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"],
                       "Entrypoint": None, "Cmd": ["bash"], "WorkingDir": "/sources",
                       "Labels": None},
        }
        builder = {
            "schema": 1, "kind": "wonad-phase1-builder",
            "reference": LOCK["builder"]["reference"], "image": builder_image,
            "identity_sha256": provenance.canonical_digest(builder_image),
            "dockerfile": provenance.file_ref(receipt.ROOT / "android/platform/Dockerfile"),
            "runtime": {"node": LOCK["builder"]["node_version"],
                        "yarn": LOCK["builder"]["yarn_version"]},
        }
        projects = [
            {"path": path, "name": "fixture/" + path, "revision": LOCK[key]["commit"],
             "remote": "fixture"}
            for path, key in (("frameworks/base", "frameworks_base"),
                              ("packages/apps/Launcher3", "launcher3"),
                              ("packages/apps/Updater", "updater"),
                              ("device/generic/goldfish", "emulator_goldfish"))
        ]
        projects.append({"path": "build/make", "name": "fixture/build", "revision": "1" * 40,
                         "remote": "fixture"})
        input_row = {"sha256": "2" * 64, "size": 1, "mode": 0o644}
        git_file = {"sha256": "6" * 64, "size": 1, "mode": 0o644}
        git_config = {"file": git_file, "entries_sha256": "7" * 64}
        project_git = {
            row["path"]: {
                "config": git_config, "info_exclude": git_file,
                "gitdir": ".repo/projects/" + row["path"] + ".git",
                "object_store": ".repo/project-objects/" + row["name"] + ".git/objects",
                "gitlinks": {}, "materialized_eol": {},
                "materialized_lfs": {},
            } for row in projects
        }
        special_git = {"config": git_config, "ignored_runtime_cache": {},
                       "info_exclude": git_file, "gitlinks": {}, "materialized_eol": {},
                       "materialized_lfs": {}}
        source_record = {
            "schema": provenance.SOURCE_SCHEMA, "kind": "wonad-grapheneos-source-provenance",
            "targets": {"release": LOCK["release"], "production": provenance.PRODUCTION_TARGET,
                        "source_matched_emulator": provenance.EMULATOR_TARGET},
            "artifact_claim": "source_freeze_only_no_binary_artifacts",
            "lock": provenance.file_ref(receipt.LOCK_PATH),
            "manifest": {"commit": LOCK["manifest"]["commit"],
                         "tag_object": LOCK["manifest"]["tag_object"],
                         "default_xml": {"sha256": LOCK["manifest"]["default_xml_sha256"],
                                         "size": LOCK["manifest"]["default_xml_size"]},
                         "projects": projects, "project_count": len(projects),
                         "project_ledger_sha256": provenance.canonical_digest(projects)},
            "repo_tool": {"revision": LOCK["repo_tool"]["revision"],
                          "commit": LOCK["repo_tool"]["commit"],
                          "launcher": {"sha256": "3" * 64, "size": 1, "mode": 0o755}},
            "owned_tracked_changes": {"frameworks/base/fixture": input_row},
            "generated_inputs": {"external/wonad/fixture": input_row},
            "generated_inputs_sha256": provenance.canonical_digest(
                {"external/wonad/fixture": input_row}),
            "toolchain_projects": [projects[-1]],
            "toolchain_ledger_sha256": provenance.canonical_digest([projects[-1]]),
            "source_audit": {
                "policy": provenance.GIT_RAW_AUDIT_POLICY,
                "host_tools": provenance.expected_host_tool_ledger(),
                "manifest_git": special_git, "repo_git": special_git,
                "projects": project_git,
                "projects_sha256": provenance.canonical_digest(project_git),
            },
            "builder": builder, "generator": provenance.file_ref(provenance.Path(provenance.__file__)),
        }
        (root / "source-provenance.json").write_text(json.dumps(source_record, sort_keys=True))

        sdk_ref = provenance.file_ref(sdk, include_mode=True)
        client_record = {
            "schema": provenance.CLIENT_SCHEMA, "kind": "wonad-phase1-client-provenance",
            "qualification": "production", "coordinate": "org.wonad:desktop-sdk:3.0.1",
            "sdk_publication": {"verification": {
                                    "coordinate": "org.wonad:desktop-sdk:3.0.1",
                                    "contract_signature":
                                        "db6ac649c34d8c25ab0bdd4a46802639deb3972d376070c6c3cdd811d7962fff",
                                    "contract_members": {
                                        "API-v3.md": {
                                            "sha256": "a" * 64, "bytes": 1, "mode": 0o644},
                                        "desktop-sdk-contract-v3.json": {
                                            "sha256": "b" * 64, "bytes": 1, "mode": 0o644},
                                        "verify-desktop-sdk-contract.py": {
                                            "sha256": "c" * 64, "bytes": 1, "mode": 0o755},
                                    }},
                                "files": {"publication.bin": sdk_ref}},
            "conformance": {"package": "org.wonad.desktop",
                            "apk": provenance.file_ref(signed),
                            "unsigned_apk": provenance.file_ref(unsigned),
                            "signing": {"certificate_sha256": SIGNER,
                                        "lineage_certificate_sha256": [],
                                        "schemes": {"2": True}, "signers": 1},
                            "payload_sha256": "4" * 64},
            "public_signer": {"file": provenance.file_ref(certificate),
                              "der_sha256": SIGNER, "der_size": len(CERTIFICATE),
                              "subject": "CN=Wonad Production"},
            "source_receipt": provenance.file_ref(compile_receipt),
            "source_freeze": {"identity": provenance.file_ref(freeze), "files": freeze_files,
                              "files_sha256": provenance.canonical_digest(freeze_files)},
            "tools": {"generator": provenance.file_ref(provenance.Path(provenance.__file__)),
                      "sdk_verifier": provenance.file_ref(receipt.ROOT /
                          "android/tools/verify_sdk_publication.py"),
                      "apksigner": {"invoked_as": "fixture",
                                    "resolved": {"sha256": "5" * 64, "size": 1}},
                      "host_tools": provenance.expected_host_tool_ledger()},
        }
        (root / "client-provenance.json").write_text(json.dumps(client_record, sort_keys=True))

        release_build = receipt.run_release_build
        source_reference = provenance.file_ref(root / "source-provenance.json")
        nonce = "8" * 64
        process_environment = release_build.process_environment(BUILD, str(TIMESTAMP), 1)
        inner_command = release_build.inner_command(8, nonce)
        process_command = release_build.process_command(process_environment, inner_command)
        source_path = str(self.source)
        out_path = str(Path(self.temporary.name) / "release-out")
        log_path = str(Path(self.temporary.name) / "release.log")
        container_name = f"wonad-phase1-frankel-release-{BUILD}-fixture"
        docker_cli_stat = Path("/usr/bin/docker").stat()
        locality_record = {
            "schema": 1, "kind": "wonad-build-launch-docker-locality",
            "endpoint": release_build.locality.ENDPOINT,
            "docker_cli": {"path": "/usr/bin/docker", "realpath": "/usr/bin/docker",
                           "device": docker_cli_stat.st_dev, "inode": docker_cli_stat.st_ino,
                           "mode": stat.S_IFREG | 0o755, "uid": 0, "gid": 0,
                           "file": provenance.file_ref(Path("/usr/bin/docker"))},
            "socket": {"path": "/var/run/docker.sock", "realpath": "/run/docker.sock",
                       "device": 1, "inode": 2, "mode": stat.S_IFSOCK | 0o660,
                       "uid": 0, "gid": 999},
            "context": {"selected": "default", "name": "default",
                        "endpoint": release_build.locality.ENDPOINT,
                        "skip_tls_verify": False, "tls_material": {}},
            "daemon": {"id": "fixture-daemon", "name": "fixture",
                       "server_version": "fixture", "kernel_version": "fixture",
                       "os": "linux", "architecture": "amd64", "root_dir": "/fixture",
                       "client_version": "fixture", "client_context": "default"},
            "host_boot_id": "12345678-1234-1234-1234-123456789012",
            "generator": provenance.file_ref(receipt.ROOT /
                                               "android/tools/docker_locality_proof.py"),
        }
        locality_sha256 = provenance.canonical_digest(locality_record)
        directory_mode = stat.S_IFDIR | 0o700
        identities = {
            "source": {"path": source_path, "device": 1, "inode": 1,
                       "mode": directory_mode, "uid": 1000, "gid": 1000},
            "out": {"path": out_path, "device": 1, "inode": 2,
                    "mode": directory_mode, "uid": 1000, "gid": 1000},
            "log_parent": {"path": str(Path(log_path).parent), "device": 1, "inode": 3,
                           "mode": directory_mode, "uid": 1000, "gid": 1000},
            "evidence_parent": {"path": str(root), "device": 1, "inode": 4,
                                "mode": directory_mode, "uid": 1000, "gid": 1000},
        }
        binds = [f"{source_path}:{release_build.CONTAINER_SOURCE}:rw",
                 f"{out_path}:{release_build.CONTAINER_OUT}:rw"]
        mounts = [
            {"type": "bind", "source": source_path,
             "destination": release_build.CONTAINER_SOURCE, "mode": "rw", "rw": True,
             "propagation": "rprivate"},
            {"type": "bind", "source": out_path,
             "destination": release_build.CONTAINER_OUT, "mode": "rw", "rw": True,
             "propagation": "rprivate"},
        ]
        docker_command = release_build.docker_command(
            Path(source_path), Path(out_path), container_name, nonce, locality_sha256,
            process_command)
        bind_record = {
            "schema": 1, "kind": "wonad-release-live-bind-proof",
            "scope": "running-gated-container-before-build",
            "container": {"id": "a" * 64, "name": container_name,
                          "image_id": release_build.IMAGE_ID,
                          "attempt_nonce": nonce},
            "host_boot_id": locality_record["host_boot_id"],
            "container_boot_id": locality_record["host_boot_id"],
            "gate": {"container_path": release_build.gate_path(nonce),
                     "state": "absent-container-blocked"},
            "bindings": [
                {"source": source_path, "destination": release_build.CONTAINER_SOURCE,
                 "host": {key: identities["source"][key]
                          for key in ("device", "inode", "mode", "uid", "gid")},
                 "container": {key: identities["source"][key]
                               for key in ("device", "inode", "mode", "uid", "gid")}},
                {"source": out_path, "destination": release_build.CONTAINER_OUT,
                 "host": {key: identities["out"][key]
                          for key in ("device", "inode", "mode", "uid", "gid")},
                 "container": {key: identities["out"][key]
                               for key in ("device", "inode", "mode", "uid", "gid")}},
            ],
            "generator": provenance.file_ref(receipt.ROOT /
                                               "android/tools/run_release_build.py"),
        }
        bind_path = root / "build-bind-proof.json"
        bind_path.write_text(json.dumps(bind_record, sort_keys=True))
        build_log = root / "build.log"
        build_log.write_bytes(b"fixture container build log\n")
        execution_record = {
            "schema": release_build.SCHEMA, "kind": release_build.KIND,
            "status": "succeeded",
            "contract": {"build_number": BUILD, "build_datetime": str(TIMESTAMP),
                         "jobs": 8, "highmem_jobs": 1,
                         "lunch_target": release_build.LUNCH_TARGET,
                         "targets": release_build.TARGETS,
                         "builder_reference": release_build.IMAGE_REFERENCE,
                         "builder_image_id": release_build.IMAGE_ID,
                         "builder_platform": release_build.PLATFORM,
                         "container_source": release_build.CONTAINER_SOURCE,
                         "container_out": release_build.CONTAINER_OUT,
                         "finalizer": "script/finalize.sh"},
            "lock": provenance.file_ref(receipt.LOCK_PATH),
            "builder_record": {"sha256": "9" * 64, "size": 1},
            "source_record": source_reference, "builder": builder,
            "process_environment": process_environment, "inner_command": inner_command,
            "docker_command": docker_command, "docker_locality": locality_record,
            "docker_locality_sha256": locality_sha256,
            "locations": {"source": source_path, "out": out_path, "log": log_path},
            "location_identity": identities, "attempt_nonce": nonce,
            "container": {"id": "a" * 64, "name": container_name,
                          "image_id": release_build.IMAGE_ID,
                          "image_reference": release_build.IMAGE_ID,
                          "platform": release_build.PLATFORM,
                          "created": "fixture", "started_at": "fixture",
                          "finished_at": "fixture", "status": "exited", "exit_code": 0,
                          "oom_killed": False, "user": "1000:1000",
                          "workdir": release_build.CONTAINER_SOURCE,
                          "entrypoint": ["/usr/bin/env"], "command": process_command,
                          "labels": {release_build.ATTEMPT_LABEL: nonce,
                                     release_build.LOCALITY_LABEL: locality_sha256},
                          "network_mode": "none",
                          "log_config": {
                              "type": "json-file",
                              "config": {"max-file": "1", "max-size": "1t",
                                         "mode": "blocking"},
                          },
                          "cap_drop": ["ALL"],
                          "security_opt": ["label=disable", "no-new-privileges"],
                          "restart_policy": {"Name": "no", "MaximumRetryCount": 0},
                          "binds": binds, "mounts": mounts},
            "bind_proof": provenance.file_ref(bind_path),
            "log": provenance.file_ref(build_log),
            "finalized_inputs": {
                "target_files": {"path": f"releases/{BUILD}/frankel-target_files.zip",
                                 "sha256": "c" * 64, "size": 1},
                "otatools": {"path": f"releases/{BUILD}/frankel-otatools.zip",
                             "sha256": "d" * 64, "size": 1}},
            "generator": provenance.file_ref(receipt.ROOT /
                                               "android/tools/run_release_build.py"),
        }
        release_build.validate_record_shape(execution_record)
        release_build.bind_proof_matches_execution(bind_record, execution_record)
        execution_path = root / "build-execution.json"
        execution_path.write_text(json.dumps(execution_record, sort_keys=True))
        consumption_record = {
            "schema": 1, "kind": release_build.CONSUMPTION_KIND,
            "status": "consumed-confirmed-absent", "build_number": BUILD,
            "execution": provenance.file_ref(execution_path),
            "container": {"id": "a" * 64, "name": container_name},
            "docker_locality_sha256": locality_sha256,
            "daemon_id": locality_record["daemon"]["id"],
            "host_boot_id": locality_record["host_boot_id"],
            "removal": {"operation": "docker-container-rm-by-full-id",
                        "confirmed_absent": ["full-id", "exact-name"]},
            "generator": provenance.file_ref(receipt.ROOT /
                                               "android/tools/run_release_build.py"),
        }
        release_build.validate_consumption_record(consumption_record)
        (root / "build-container-consumption.json").write_text(
            json.dumps(consumption_record, sort_keys=True))

    def revision(self, path):
        return self.revisions[path.resolve()]

    def create(self):
        with patch.object(receipt, "revision", side_effect=self.revision), \
                patch.object(receipt, "verify_release_worktree", return_value={"tracked_worktrees": "clean"}):
            return receipt.create_receipt(self.source, BUILD)

    def test_create_is_deterministic_and_offline_verifies_every_file(self):
        output = self.create()
        first = output.read_bytes()
        self.assertEqual(output, self.release / receipt.RECEIPT_NAME)
        parsed = receipt.verify_receipt(output)
        self.assertEqual(SIGNER, parsed["apk_signer_sha256"])
        self.assertEqual(TIMESTAMP, parsed["build"]["timestamp"])
        self.assertEqual(LOCK["manifest"]["commit"], parsed["source"]["manifest"]["commit"])
        self.assertEqual(SIGNER, parsed["wonad_stage"]["signer_certificate"]["sha256"])
        self.assertEqual("android/tools/verify_release_artifacts.py",
                         parsed["artifact_verifier"]["name"])
        self.assertEqual(digest(b"fixture container build log\n"),
                         parsed["phase1_provenance"]["build_execution"]["log_sha256"])
        self.assertIn("bin/sign_target_files_apks", parsed["files"])
        self.assertEqual(set(self.roles.values()), set(parsed["artifacts"].values()))
        self.create()
        self.assertEqual(first, output.read_bytes())

    def test_patch_tool_and_post_stage_target_identity_are_revalidated(self):
        marker_path = self.source / receipt.STAGE_MARKER
        original_marker = marker_path.read_text()
        marker = json.loads(original_marker)
        marker["patches"]["frameworks_base"][0]["sha256"] = "0" * 64
        marker_path.write_text(json.dumps(marker))
        with self.assertRaisesRegex(receipt.ReceiptError, "patch order or digest"):
            self.create()
        marker_path.write_text(original_marker)

        marker = json.loads(original_marker)
        marker["tools"]["android/platform/stage-os.py"] = "0" * 64
        marker_path.write_text(json.dumps(marker))
        with self.assertRaisesRegex(receipt.ReceiptError, "tool identity"):
            self.create()
        marker_path.write_text(original_marker)

        target = self.source / "frameworks/base/services/wonad-hook.java"
        target.write_text("independent post-stage edit\n")
        with self.assertRaisesRegex(receipt.ReceiptError, "target differs"):
            self.create()

    def test_offline_verifier_rejects_tampered_missing_and_extra_files(self):
        output = self.create()
        image = self.release / self.roles["images"]
        original = image.read_bytes()
        image.write_bytes(original + b"tampered")
        with self.assertRaisesRegex(receipt.ReceiptError, "tampered"):
            receipt.verify_receipt(output)
        image.write_bytes(original)

        factory = self.release / self.roles["factory"]
        factory.rename(factory.with_suffix(".held"))
        with self.assertRaisesRegex(receipt.ReceiptError, "missing.*extra"):
            receipt.verify_receipt(output)
        factory.with_suffix(".held").rename(factory)

        (self.release / "unexpected.txt").write_text("not receipted")
        with self.assertRaisesRegex(receipt.ReceiptError, "extra"):
            receipt.verify_receipt(output)

    def test_phase1_evidence_is_exact_and_arm_receipt_cannot_claim_emulator_bytes(self):
        output = self.create()
        parsed = json.loads(output.read_text())
        self.assertEqual("production", parsed["phase1_provenance"]["selected_target"])
        source_record = json.loads((self.release / receipt.SOURCE_PROVENANCE).read_text())
        self.assertEqual("source_freeze_only_no_binary_artifacts", source_record["artifact_claim"])
        self.assertEqual("source_matched_development_runtime_only",
                         source_record["targets"]["source_matched_emulator"]["artifact_scope"])
        evidence = self.release / receipt.PROVENANCE_DIRECTORY / "conformance.apk"
        evidence.write_bytes(evidence.read_bytes() + b"tampered")
        with self.assertRaisesRegex(receipt.ReceiptError, "tampered"):
            receipt.verify_receipt(output)

    def test_unbound_phase1_evidence_is_rejected_before_receipting(self):
        extra = self.release / receipt.PROVENANCE_DIRECTORY / "unbound.bin"
        extra.write_bytes(b"unbound")
        with self.assertRaisesRegex(receipt.ReceiptError, "missing or unbound"):
            self.create()

    def test_build_log_bytes_must_match_execution_evidence(self):
        build_log = self.release / receipt.BUILD_LOG
        build_log.write_bytes(build_log.read_bytes() + b"tampered\n")
        with self.assertRaisesRegex(receipt.ReceiptError, "build.log"):
            self.create()

    def test_missing_or_forged_build_execution_cannot_be_receipted(self):
        execution = self.release / receipt.BUILD_EXECUTION
        original = execution.read_text()
        execution.unlink()
        with self.assertRaisesRegex(receipt.ReceiptError, "Invalid Phase-1 provenance evidence"):
            self.create()
        execution.write_text(original)

        value = json.loads(original)
        value["container"]["image_reference"] = receipt.run_release_build.IMAGE_REFERENCE
        execution.write_text(json.dumps(value, sort_keys=True))
        with self.assertRaisesRegex(receipt.ReceiptError, "Retained container evidence"):
            self.create()

        value = json.loads(original)
        value["container"]["log_config"] = {"type": "none", "config": {}}
        execution.write_text(json.dumps(value, sort_keys=True))
        with self.assertRaisesRegex(receipt.ReceiptError, "Retained container evidence"):
            self.create()

    def test_live_bind_and_container_consumption_proofs_are_mandatory(self):
        bind_path = self.release / receipt.BUILD_BIND_PROOF
        original_bind = bind_path.read_text()
        bind = json.loads(original_bind)
        bind["bindings"][0]["container"]["inode"] += 1
        bind_path.write_text(json.dumps(bind, sort_keys=True))
        with self.assertRaisesRegex(receipt.ReceiptError, "bind device/inode identity"):
            self.create()
        bind_path.write_text(original_bind)

        consumption_path = self.release / receipt.BUILD_CONSUMPTION
        consumption = json.loads(consumption_path.read_text())
        consumption["status"] = "claimed-not-removed"
        consumption_path.write_text(json.dumps(consumption, sort_keys=True))
        with self.assertRaisesRegex(receipt.ReceiptError, "container-consumption"):
            self.create()

    def test_duplicate_receipt_fields_are_rejected(self):
        output = self.create()
        raw = output.read_text()
        raw = raw.replace('  "schema": 1,', '  "schema": 1,\n  "schema": 1,', 1)
        output.write_text(raw)
        with self.assertRaisesRegex(receipt.ReceiptError, "Duplicate JSON field: schema"):
            receipt.verify_receipt(output)

    def test_missing_install_signature_or_bad_channel_prevents_creation(self):
        (self.release / self.roles["install_signature"]).unlink()
        with self.assertRaisesRegex(receipt.ReceiptError, "Missing required.*sig"):
            self.create()
        (self.release / self.roles["install_signature"]).write_bytes(b"signature")
        (self.release / self.roles["channel_stable"]).write_text(
            f"{BUILD} {TIMESTAMP + 1} frankel stable\n")
        with self.assertRaisesRegex(receipt.ReceiptError, "stable channel metadata"):
            self.create()

    def test_ota_build_identity_and_source_pins_are_enforced(self):
        ota = self.release / self.roles["full_ota"]
        with zipfile.ZipFile(ota, "w") as archive:
            archive.writestr(
                "META-INF/com/android/metadata",
                "post-build=wonad/frankel/frankel:17/FIXTURE/wrong:user/release-keys\n"
                f"post-timestamp={TIMESTAMP}\npre-device=frankel\n")
        with self.assertRaisesRegex(receipt.ReceiptError, "requested build number"):
            self.create()

        # Restore an ordinary fixture by rebuilding setUp's OTA payload.
        with zipfile.ZipFile(ota, "w") as archive:
            archive.writestr(
                "META-INF/com/android/metadata",
                "post-build=wonad/frankel/frankel:17/FIXTURE/"
                f"{BUILD}:user/release-keys\npost-timestamp={TIMESTAMP}\npre-device=frankel\n")
        framework = (self.source / "frameworks/base").resolve()
        self.revisions[framework] = "0" * 40
        with self.assertRaisesRegex(receipt.ReceiptError, "frameworks_base revision"):
            self.create()

    def test_production_build_number_is_exactly_ten_decimal_digits(self):
        for value in ("wonad.2026101000", "202610100", "20261010000", "2026-10-10"):
            with self.subTest(value=value), self.assertRaisesRegex(
                    receipt.ReceiptError, "10 decimal digits"):
                receipt.create_receipt(self.source, value)

    def test_source_private_keys_are_never_visited_and_release_keys_are_rejected(self):
        private = self.source / "keys/frankel/releasekey.pk8"
        private.parent.mkdir(parents=True)
        private.write_bytes(b"must not be read")
        original = receipt.hash_file

        def guarded(path):
            self.assertNotIn(self.source / "keys", [path, *path.parents])
            return original(path)

        with patch.object(receipt, "revision", side_effect=self.revision), \
                patch.object(receipt, "hash_file", side_effect=guarded), \
                patch.object(receipt, "verify_release_worktree", return_value={"tracked_worktrees": "clean"}):
            receipt.create_receipt(self.source, BUILD)

        (self.release / receipt.RECEIPT_NAME).unlink()
        copied = self.release / "keys/id_ed25519"
        copied.parent.mkdir()
        copied.write_bytes(b"accidentally copied private key")
        with self.assertRaisesRegex(receipt.ReceiptError, "key-like path"):
            self.create()

    def test_duplicate_marker_fields_and_symlinked_release_content_are_rejected(self):
        marker = self.source / receipt.STAGE_MARKER
        marker.write_text('{"schema":4,"schema":4}')
        with self.assertRaisesRegex(receipt.ReceiptError, "Duplicate JSON field"):
            self.create()

        # Restore the marker, then prove an output link is never followed.
        staged = marker.parent / "broker/Broker.kt"
        certificate = marker.parent / "WonadReleaseCertificate.der"
        marker.write_text(json.dumps({
            "schema": 4,
            "frameworks_revision": LOCK["frameworks_base"]["commit"],
            "launcher3_revision": LOCK["launcher3"]["commit"],
            "emulator_goldfish_revision": LOCK["emulator_goldfish"]["commit"],
            "signer_sha256": SIGNER,
            "signer_certificate": {"path": certificate.name, "sha256": SIGNER,
                                   "size": len(CERTIFICATE)},
            "files": {"broker/Broker.kt": digest(staged.read_bytes()), certificate.name: SIGNER},
            "patches": {
                "frameworks_base": receipt.stage_contract.patch_ledger(receipt.stage_contract.FRAMEWORK_PATCH_NAMES),
                "launcher3": receipt.stage_contract.patch_ledger(receipt.stage_contract.LAUNCHER_PATCH_NAMES),
                "emulator_goldfish": receipt.stage_contract.patch_ledger(
                    receipt.stage_contract.EMULATOR_PATCH_NAMES),
            },
            "platform_targets": {
                "frameworks_base": {"services/wonad-hook.java": digest(
                    (self.source / "frameworks/base/services/wonad-hook.java").read_bytes())},
                "launcher3": {"src/wonad-hook.kt": digest(
                    (self.source / "packages/apps/Launcher3/src/wonad-hook.kt").read_bytes())},
                "emulator_goldfish": {"input/qwerty2.kl": digest(
                    (self.source / "device/generic/goldfish/input/qwerty2.kl").read_bytes())},
            },
            "tools": receipt.stage_contract.tool_ledger(),
        }))
        (self.release / "escape").symlink_to(self.source / "keys", target_is_directory=True)
        with self.assertRaisesRegex(receipt.ReceiptError, "symlink"):
            self.create()


if __name__ == "__main__":
    unittest.main()
