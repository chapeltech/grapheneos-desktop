#!/usr/bin/env python3
"""Fail-closed tests for complete Phase-1 build/client provenance."""

from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
import os
import shutil
import stat
import subprocess
import tempfile
import types
import unittest
from unittest.mock import patch
import zipfile


ANDROID = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "phase1_provenance", ANDROID / "tools/phase1_provenance.py")
assert SPEC and SPEC.loader
provenance = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(provenance)


def git(repository: Path, *args):
    return subprocess.check_output(["git", "-C", str(repository), *args], text=True).strip()


def init_git(repository: Path, files: dict[str, bytes | str]):
    repository.mkdir(parents=True)
    subprocess.run(["git", "init", "-q", str(repository)], check=True)
    subprocess.run(["git", "-C", str(repository), "config", "user.email", "test@example.invalid"], check=True)
    subprocess.run(["git", "-C", str(repository), "config", "user.name", "Phase One Test"], check=True)
    for name, payload in files.items():
        path = repository / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload if isinstance(payload, bytes) else payload.encode())
    subprocess.run(["git", "-C", str(repository), "add", "."], check=True)
    subprocess.run(["git", "-C", str(repository), "commit", "-qm", "fixture"], check=True)
    return git(repository, "rev-parse", "HEAD")


def init_repo_project(source: Path, project_path: str, project_name: str,
                      files: dict[str, bytes | str], remote="aosp"):
    repository = source / project_path
    revision = init_git(repository, files)
    git_dir = source / ".repo/projects" / (project_path + ".git")
    git_dir.parent.mkdir(parents=True, exist_ok=True)
    shutil.move(repository / ".git", git_dir)
    object_store = source / ".repo/project-objects" / (project_name + ".git") / "objects"
    object_store.parent.mkdir(parents=True, exist_ok=True)
    shutil.move(git_dir / "objects", object_store)
    (git_dir / "objects").symlink_to(os.path.relpath(object_store, git_dir), target_is_directory=True)
    (repository / ".git").symlink_to(os.path.relpath(git_dir, repository), target_is_directory=True)
    domain = {
        "aosp": "https://android.googlesource.com/",
        "grapheneos": "https://github.com/GrapheneOS/",
    }[remote]
    review = "\treview = https://android-review.googlesource.com/\n" if remote == "aosp" else ""
    (git_dir / "config").write_text(
        "[core]\n\trepositoryFormatVersion = 1\n\tfilemode = true\n"
        "[filter \"lfs\"]\n\tsmudge = git-lfs smudge --skip -- %f\n"
        "\tprocess = git-lfs filter-process --skip\n"
        f"[remote \"{remote}\"]\n\turl = {domain}{project_name}\n{review}"
        f"\tprojectname = {project_name}\n\tfetch = +refs/heads/*:refs/remotes/{remote}/*\n"
        "\tpartialclonefilter = blob:limit=10485760\n"
        "[maintenance]\n\tauto = false\n[gc]\n\tauto = 0\n"
        f"[extensions]\n\tpartialclone = {remote}\n")
    return revision


def sha(data: bytes):
    return hashlib.sha256(data).hexdigest()


def write_json(path: Path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


class SourceFixture:
    def __init__(self, base: Path):
        self.base = base
        self.source = base / "source"
        self.source.mkdir()
        (self.source / ".repo/projects").mkdir(parents=True)
        (self.source / ".repo/project-objects").mkdir(parents=True)
        projects = {
            "frameworks/base": {"owned.txt": "baseline\n"},
            "packages/apps/Launcher3": {"launcher.txt": "baseline\n"},
            "packages/apps/Updater": {"res/values/config.xml": "baseline\n"},
            "device/generic/goldfish": {
                "64bitonly/product/sdk_phone64_x86_64.mk": "baseline product\n",
                "input/qwerty2.kl": "baseline keys\n",
            },
            "vendor/adevtool": {"package.json": "{}\n", "dl/.find-ignore": ""},
            "prebuilts/clang/host/linux-x86": {"bin/clang": "compiler\n"},
            "build/make": {
                "core/main.mk": "build\n",
                "root.bp": "build root\n",
                "copied.mk": "copied build input\n",
            },
        }
        rows = []
        for path, files in projects.items():
            name = "platform/" + path
            revision = init_repo_project(self.source, path, name, files)
            rows.append((path, revision))
        default = ["<?xml version=\"1.0\"?><manifest>"]
        for path, revision in rows:
            prefix = (f'<project name="platform/{path}" path="{path}" '
                      f'remote="aosp" revision="{revision}"')
            if path == "build/make":
                default.append(prefix + '><linkfile src="root.bp" dest="Android.bp"/>'
                               '<copyfile src="copied.mk" dest="copied.mk"/></project>')
            else:
                default.append(prefix + "/>")
        default.append("</manifest>\n")
        default_bytes = "".join(default).encode()
        manifests = self.source / ".repo/manifests"
        manifest_commit = init_git(manifests, {"default.xml": default_bytes})
        repo = self.source / ".repo/repo"
        repo_commit = init_git(repo, {"repo": "#!/bin/sh\nexit 0\n"})
        (repo / "repo").chmod(0o755)
        # Executable-bit change happened after the commit; commit it so repo is clean.
        subprocess.run(["git", "-C", str(repo), "add", "repo"], check=True)
        subprocess.run(["git", "-C", str(repo), "commit", "-qm", "executable"], check=True)
        repo_commit = git(repo, "rev-parse", "HEAD")
        (self.source / ".repo/project.list").write_text("\n".join(path for path, _ in rows) + "\n")
        (self.source / "Android.bp").symlink_to("build/make/root.bp")
        shutil.copy2(self.source / "build/make/copied.mk", self.source / "copied.mk")
        (self.source / "copied.mk").chmod(
            (self.source / "copied.mk").stat().st_mode &
            ~(stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH))

        framework = self.source / "frameworks/base/owned.txt"
        launcher = self.source / "packages/apps/Launcher3/launcher.txt"
        updater = self.source / "packages/apps/Updater/res/values/config.xml"
        emulator_product = self.source / "device/generic/goldfish/64bitonly/product/sdk_phone64_x86_64.mk"
        emulator_keys = self.source / "device/generic/goldfish/input/qwerty2.kl"
        framework.write_text("wonad framework\n")
        launcher.write_text("wonad launcher\n")
        updater.write_text("wonad updater\n")
        emulator_product.write_text("wonad emulator product\n")
        emulator_keys.write_text("wonad emulator keys\n")
        staged = self.source / "external/wonad"
        staged.mkdir(parents=True)
        (staged / "Android.bp").write_text("rust_library {}\n")
        marker = {
            "schema": 4,
            "platform_targets": {
                "frameworks_base": {"owned.txt": sha(framework.read_bytes())},
                "launcher3": {"launcher.txt": sha(launcher.read_bytes())},
                "emulator_goldfish": {
                    "64bitonly/product/sdk_phone64_x86_64.mk": sha(emulator_product.read_bytes()),
                    "input/qwerty2.kl": sha(emulator_keys.read_bytes()),
                },
            },
        }
        write_json(staged / ".wonad-stage.json", marker)
        write_json(self.source / ".wonad-updater-stage.json", {"schema": 1})
        vendor = self.source / "vendor/google_devices/frankel"
        vendor.mkdir(parents=True)
        (vendor / "AndroidProducts.mk").write_text("PRODUCT_MAKEFILES := frankel\n")
        (vendor / "adevtool-version-check.mk").write_text("adevtool revision\n")
        (vendor / "proprietary.bin").write_bytes(b"vendor")

        dockerfile = provenance.file_ref(provenance.DOCKERFILE)
        image = {
            "id": "sha256:" + "a" * 64,
            "repo_digests": ["example.invalid/wonad@sha256:" + "a" * 64],
            "os": "linux", "architecture": "amd64", "size": 123,
            "rootfs": {"type": "layers", "layers": ["sha256:" + "b" * 64]},
            "config": {
                "User": "builder",
                "Env": ["PATH=/opt/node/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"],
                "Entrypoint": None, "Cmd": ["bash"], "WorkingDir": "/sources", "Labels": None,
            },
        }
        self.builder = {
            "schema": 1, "kind": "wonad-phase1-builder", "reference": "wonad:test",
            "image": image, "identity_sha256": provenance.canonical_digest(image),
            "dockerfile": dockerfile, "runtime": {"node": "v24.21.0", "yarn": "1.22.19"},
        }
        self.builder_path = base / "builder.json"
        write_json(self.builder_path, self.builder)
        self.lock = {
            "schema": 2, "device": "frankel", "release": "2026100600",
            "manifest": {
                "commit": manifest_commit, "tag_object": "c" * 40,
                "default_xml_sha256": sha(default_bytes), "default_xml_size": len(default_bytes),
            },
            "repo_tool": {"revision": "refs/tags/v-test", "commit": repo_commit},
            "emulator_goldfish": {"url": "https://example.invalid/goldfish",
                                  "commit": dict(rows)["device/generic/goldfish"]},
            "builder": {
                "reference": "wonad:test", "image_digest": image["id"], "platform": "linux/amd64",
                "dockerfile_sha256": dockerfile["sha256"], "node_version": "v24.21.0",
                "yarn_version": "1.22.19",
            },
        }
        self.lock_path = base / "lock.json"
        write_json(self.lock_path, self.lock)

    def collect(self):
        return provenance.collect_source(self.source, self.builder_path, self.lock_path, 4)


class Phase1SourceProvenanceTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="wonad-phase1-provenance-")
        self.root = Path(self.temporary.name)
        self.fixture = SourceFixture(self.root)

    def tearDown(self):
        self.temporary.cleanup()

    def row(self, path):
        manifest = self.fixture.source / ".repo/manifests/default.xml"
        return next(row for row in provenance.parse_manifest(manifest) if row["path"] == path)

    def test_complete_manifest_generated_toolchain_and_builder_ledger_is_stable(self):
        first = self.fixture.collect()
        second = self.fixture.collect()
        self.assertEqual(first, second)
        self.assertEqual(7, first["manifest"]["project_count"])
        self.assertEqual(2, len(first["toolchain_projects"]))
        self.assertIn("vendor/google_devices/frankel/proprietary.bin", first["generated_inputs"])
        self.assertIn("frameworks/base/owned.txt", first["owned_tracked_changes"])
        self.assertIn("device/generic/goldfish/input/qwerty2.kl",
                      first["owned_tracked_changes"])
        self.assertEqual(provenance.PRODUCTION_TARGET, first["targets"]["production"])
        self.assertEqual(provenance.EMULATOR_TARGET,
                         first["targets"]["source_matched_emulator"])
        self.assertEqual("source_freeze_only_no_binary_artifacts", first["artifact_claim"])
        record = self.root / "source-provenance.json"
        write_json(record, first)
        self.assertEqual(first, provenance.verify_source(
            self.fixture.source, record, self.fixture.builder_path, self.fixture.lock_path, 4))

    def test_unknown_untracked_or_ignored_source_is_rejected(self):
        surprise = self.fixture.source / "frameworks/base/Android.bp.unreviewed"
        surprise.write_text("unexpected")
        with self.assertRaisesRegex(provenance.ProvenanceError, "not owned"):
            self.fixture.collect()
        surprise.unlink()
        ignored = self.fixture.source / "vendor/adevtool/node_modules/evil/Android.bp"
        ignored.parent.mkdir(parents=True)
        ignored.write_text("evil")
        with self.assertRaisesRegex(provenance.ProvenanceError, "not owned"):
            self.fixture.collect()

    def test_manifest_linkfile_and_copyfile_are_exact_authenticated_inputs(self):
        first = self.fixture.collect()
        self.assertEqual(first, self.fixture.collect())

        manifest = self.fixture.source / ".repo/manifests/default.xml"
        payload = manifest.read_bytes()
        projects = provenance.parse_manifest(manifest)
        states = [provenance.project_state(self.fixture.source, row) for row in projects]
        ledger = provenance.manifest_checkout_materializations(
            self.fixture.source, payload, projects, states)
        self.assertEqual({"Android.bp", "copied.mk"}, set(ledger))

        untracked = self.fixture.source / "build/make/untracked.bp"
        untracked.write_text("untracked\n")
        untracked_payload = payload.replace(b'src="root.bp"', b'src="untracked.bp"')
        with self.assertRaisesRegex(provenance.ProvenanceError, "source is not tracked"):
            provenance.manifest_checkout_materializations(
                self.fixture.source, untracked_payload, projects, states)
        untracked.unlink()

        colliding_payload = payload.replace(
            b'dest="Android.bp"', b'dest="build/make/core/main.mk"')
        with self.assertRaisesRegex(provenance.ProvenanceError, "collides with a tracked path"):
            provenance.manifest_checkout_materializations(
                self.fixture.source, colliding_payload, projects, states)
        ancestor_payload = payload.replace(b'dest="Android.bp"', b'dest="build"')
        with self.assertRaisesRegex(provenance.ProvenanceError, "collides with a tracked path"):
            provenance.manifest_checkout_materializations(
                self.fixture.source, ancestor_payload, projects, states)
        project_root_payload = payload.replace(b'src="root.bp"', b'src="."')
        with self.assertRaisesRegex(provenance.ProvenanceError, "Project-root"):
            provenance.manifest_checkout_materializations(
                self.fixture.source, project_root_payload, projects, states)

        link = self.fixture.source / "Android.bp"
        link.unlink()
        link.symlink_to("build/make/copied.mk")
        with self.assertRaisesRegex(provenance.ProvenanceError, "linkfile target differs"):
            self.fixture.collect()
        link.unlink()
        link.symlink_to("build/make/root.bp")

        copied = self.fixture.source / "copied.mk"
        copied.chmod(0o644)
        with self.assertRaisesRegex(provenance.ProvenanceError, "copyfile differs"):
            self.fixture.collect()
        copied.chmod(0o644)
        copied.write_text("tampered\n")
        copied.chmod(0o444)
        with self.assertRaisesRegex(provenance.ProvenanceError, "copyfile differs"):
            self.fixture.collect()

    def test_manifest_copyfile_cannot_alias_its_authenticated_source_inode(self):
        manifest = self.fixture.source / ".repo/manifests/default.xml"
        projects = provenance.parse_manifest(manifest)
        states = [provenance.project_state(self.fixture.source, row) for row in projects]
        source = self.fixture.source / "build/make/copied.mk"
        destination = self.fixture.source / "copied.mk"
        destination.unlink()
        os.link(source, destination)
        with self.assertRaisesRegex(provenance.ProvenanceError, "aliases its source inode"):
            provenance.manifest_checkout_materializations(
                self.fixture.source, manifest.read_bytes(), projects, states)

    def test_manifest_materialization_source_permissions_are_canonical(self):
        manifest = self.fixture.source / ".repo/manifests/default.xml"
        projects = provenance.parse_manifest(manifest)
        states = [provenance.project_state(self.fixture.source, row) for row in projects]
        source = self.fixture.source / "build/make/copied.mk"
        destination = self.fixture.source / "copied.mk"
        source.chmod(0o400)
        destination.chmod(0o400)
        with self.assertRaisesRegex(provenance.ProvenanceError, "non-canonical permissions"):
            provenance.manifest_checkout_materializations(
                self.fixture.source, manifest.read_bytes(), projects, states)

    def test_manifest_copyfile_destination_inode_is_private(self):
        manifest = self.fixture.source / ".repo/manifests/default.xml"
        projects = provenance.parse_manifest(manifest)
        states = [provenance.project_state(self.fixture.source, row) for row in projects]
        os.link(self.fixture.source / "copied.mk", self.fixture.source / "copy-alias.mk")
        with self.assertRaisesRegex(provenance.ProvenanceError, "private inode"):
            provenance.manifest_checkout_materializations(
                self.fixture.source, manifest.read_bytes(), projects, states)

    def test_unowned_tracked_change_and_missing_owned_change_are_rejected(self):
        path = self.fixture.source / "build/make/core/main.mk"
        path.write_text("changed\n")
        with self.assertRaisesRegex(provenance.ProvenanceError, "Tracked worktree changes differ"):
            self.fixture.collect()
        path.write_text("build\n")
        subprocess.run(["git", "-C", str(self.fixture.source / "frameworks/base"),
                        "checkout", "--", "owned.txt"], check=True)
        with self.assertRaisesRegex(provenance.ProvenanceError, "Tracked worktree changes differ"):
            self.fixture.collect()

    def test_manifest_bytes_project_head_and_repo_tool_are_authenticated(self):
        manifest = self.fixture.source / ".repo/manifests/default.xml"
        manifest.write_bytes(manifest.read_bytes() + b"<!-- drift -->")
        with self.assertRaisesRegex(provenance.ProvenanceError, "default.xml differs"):
            self.fixture.collect()
        subprocess.run(["git", "-C", str(manifest.parent), "checkout", "--", "default.xml"], check=True)
        project = self.fixture.source / "build/make"
        (project / "core/main.mk").write_text("new revision\n")
        subprocess.run(["git", "-C", str(project), "commit", "-qam", "drift"], check=True)
        with self.assertRaisesRegex(provenance.ProvenanceError, "HEAD differs"):
            self.fixture.collect()

    def test_generated_vendor_change_is_detected_by_record_verification(self):
        record = self.root / "source-provenance.json"
        write_json(record, self.fixture.collect())
        (self.fixture.source / "vendor/google_devices/frankel/proprietary.bin").write_bytes(b"changed")
        with self.assertRaisesRegex(provenance.ProvenanceError, "differs from the immutable record"):
            provenance.verify_source(self.fixture.source, record, self.fixture.builder_path,
                                     self.fixture.lock_path, 4)

    def test_post_build_recheck_ignores_only_output_and_release_trees(self):
        record = self.root / "source-provenance.json"
        original = self.fixture.collect()
        write_json(record, original)
        (self.fixture.source / "out/target/product/frankel").mkdir(parents=True)
        (self.fixture.source / "out/target/product/frankel/system.img").write_bytes(b"output")
        (self.fixture.source / "releases/2026101001").mkdir(parents=True)
        (self.fixture.source / "releases/2026101001/frankel-target_files.zip").write_bytes(b"release")
        self.assertEqual(original, provenance.verify_source(
            self.fixture.source, record, self.fixture.builder_path,
            self.fixture.lock_path, 4, allow_build_outputs=True))
        (self.fixture.source / "build/make/surprise.bp").write_text("unexpected")
        with self.assertRaisesRegex(provenance.ProvenanceError, "not owned"):
            provenance.verify_source(self.fixture.source, record, self.fixture.builder_path,
                                     self.fixture.lock_path, 4, allow_build_outputs=True)

    def test_symlink_private_key_and_build_output_fail_closed(self):
        vendor = self.fixture.source / "vendor/google_devices/frankel"
        (vendor / "alias").symlink_to("proprietary.bin")
        with self.assertRaisesRegex(provenance.ProvenanceError, "not an ordinary"):
            self.fixture.collect()
        (vendor / "alias").unlink()
        (vendor / "releasekey.pk8").write_bytes(b"private")
        with self.assertRaisesRegex(provenance.ProvenanceError, "key-like"):
            self.fixture.collect()
        (vendor / "releasekey.pk8").unlink()
        (self.fixture.source / "out").mkdir()
        (self.fixture.source / "out/Android.bp").write_text("bad")
        with self.assertRaisesRegex(provenance.ProvenanceError, "forbidden build/output"):
            self.fixture.collect()

    def test_builder_image_and_canonical_config_are_fail_closed(self):
        lock = provenance.validate_lock(provenance.load_json(self.fixture.lock_path))
        self.assertEqual(self.fixture.builder,
                         provenance.validate_builder(self.fixture.builder, lock))
        changed = json.loads(json.dumps(self.fixture.builder))
        changed["image"]["config"]["User"] = "root"
        changed["identity_sha256"] = provenance.canonical_digest(changed["image"])
        with self.assertRaisesRegex(provenance.ProvenanceError, "execution config"):
            provenance.validate_builder(changed, lock)

    def test_vendor_download_and_dependency_caches_are_removed_without_touching_source(self):
        adevtool = self.fixture.source / "vendor/adevtool"
        (adevtool / "node_modules/pkg").mkdir(parents=True)
        (adevtool / "node_modules/pkg/index.js").write_text("cache")
        (adevtool / "dl/archive.zip").write_bytes(b"download")
        (adevtool / ".cache").mkdir()
        (adevtool / ".cache/state").write_text("cache")
        output = self.fixture.source / "out_adevtool_deps/module"
        output.mkdir(parents=True)
        (output / "generated").write_text("output")
        removed = provenance.clean_vendor_cache(self.fixture.source)
        self.assertTrue(removed)
        self.assertFalse((adevtool / "node_modules").exists())
        self.assertFalse((adevtool / "dl/archive.zip").exists())
        self.assertFalse((adevtool / ".cache").exists())
        self.assertFalse((self.fixture.source / "out_adevtool_deps").exists())
        self.assertTrue((adevtool / "dl/.find-ignore").is_file())
        self.assertEqual("{}\n", (adevtool / "package.json").read_text())
        self.fixture.collect()

    def test_vendor_cache_cleanup_refuses_a_top_level_symlink(self):
        outside = self.root / "outside"
        outside.mkdir()
        sentinel = outside / "keep"
        sentinel.write_text("keep")
        (self.fixture.source / "vendor/adevtool/node_modules").symlink_to(
            outside, target_is_directory=True)
        with self.assertRaisesRegex(provenance.ProvenanceError, "symlinked"):
            provenance.clean_vendor_cache(self.fixture.source)
        self.assertEqual("keep", sentinel.read_text())

    def test_path_git_dir_and_global_config_injection_cannot_redirect_git(self):
        fake_bin = self.root / "fake-bin"
        fake_bin.mkdir()
        marker = self.root / "fake-git-ran"
        fake_git = fake_bin / "git"
        fake_git.write_text("#!/bin/sh\ntouch '" + str(marker) + "'\nexit 91\n")
        fake_git.chmod(0o755)
        attacker = self.root / "attacker.git"
        init_git(attacker, {"wrong": "wrong\n"})
        hostile_home = self.root / "hostile-home"
        hostile_home.mkdir()
        (hostile_home / ".gitconfig").write_text(
            "[core]\n\tworktree = /nonexistent\n[filter \"evil\"]\n\tclean = /bin/false\n")
        environment = {
            "PATH": str(fake_bin), "HOME": str(hostile_home),
            "GIT_CONFIG_GLOBAL": str(hostile_home / ".gitconfig"),
            "GIT_DIR": str(attacker / ".git"), "GIT_WORK_TREE": str(attacker),
            "GIT_INDEX_FILE": str(attacker / ".git/index"),
            "GIT_OBJECT_DIRECTORY": str(attacker / ".git/objects"),
        }
        with patch.dict(os.environ, environment):
            path, dirty, tracked = provenance.project_state(
                self.fixture.source, self.row("build/make"))
        self.assertEqual("build/make", path)
        self.assertEqual([], dirty)
        self.assertEqual(["copied.mk", "core/main.mk", "root.bp"], tracked)
        self.assertFalse(marker.exists())

    def test_assume_unchanged_and_skip_worktree_bits_are_rejected(self):
        repository = self.fixture.source / "build/make"
        row = self.row("build/make")
        for enable, disable in (("--skip-worktree", "--no-skip-worktree"),
                                ("--assume-unchanged", "--no-assume-unchanged")):
            with self.subTest(index_flag=enable):
                subprocess.run(["git", "-C", str(repository), "update-index", enable,
                                "core/main.mk"], check=True)
                try:
                    with self.assertRaisesRegex(provenance.ProvenanceError,
                                                "assume-unchanged/skip-worktree"):
                        provenance.project_state(self.fixture.source, row)
                finally:
                    subprocess.run(["git", "-C", str(repository), "update-index", disable,
                                    "core/main.mk"], check=True)

    def test_raw_byte_audit_ignores_a_hostile_clean_filter(self):
        source = self.root / "filter-source"
        (source / ".repo/projects").mkdir(parents=True)
        (source / ".repo/project-objects").mkdir(parents=True)
        revision = init_repo_project(source, "external/filter", "platform/external/filter", {
            ".gitattributes": "*.txt filter=evil\n", "value.txt": "committed\n",
        })
        row = {"path": "external/filter", "name": "platform/external/filter",
               "remote": "aosp", "revision": revision}
        cleaner = self.root / "cleaner"
        cleaner.write_text("#!/bin/sh\nprintf 'committed\\n'\n")
        cleaner.chmod(0o755)
        hostile = self.root / "hostile-filter.config"
        hostile.write_text(f"[filter \"evil\"]\n\tclean = {cleaner}\n")
        (source / "external/filter/value.txt").write_text("different but filter-clean\n")
        with patch.dict(os.environ, {"GIT_CONFIG_GLOBAL": str(hostile),
                                     "HOME": str(self.root), "PATH": str(cleaner.parent)}):
            _, dirty, _ = provenance.project_state(source, row)
        self.assertEqual(["value.txt"], dirty)

    def test_unreviewed_local_filter_sparse_config_grafts_and_replacements_fail_closed(self):
        repository = self.fixture.source / "build/make"
        git_dir = (repository / ".git").resolve()
        row = self.row("build/make")
        mutations = {
            "filter": lambda: subprocess.run(
                ["git", "-C", str(repository), "config", "filter.evil.clean", "/bin/cat"],
                check=True),
            "sparse": lambda: subprocess.run(
                ["git", "-C", str(repository), "config", "core.sparseCheckout", "true"],
                check=True),
            "grafts": lambda: (git_dir / "info/grafts").write_text("0" * 40 + "\n"),
            "replacement": lambda: (git_dir / "refs/replace").mkdir(parents=True),
        }
        for label, mutate in mutations.items():
            with self.subTest(metadata=label):
                config = (git_dir / "config").read_bytes()
                mutate()
                try:
                    with self.assertRaises(provenance.ProvenanceError):
                        provenance.project_state(self.fixture.source, row)
                finally:
                    (git_dir / "config").write_bytes(config)
                    (git_dir / "info/grafts").unlink(missing_ok=True)
                    replace = git_dir / "refs/replace"
                    if replace.is_dir():
                        replace.rmdir()

    def test_authenticated_lfs_materialization_is_clean_but_wrong_payload_is_dirty(self):
        source = self.root / "lfs-source"
        (source / ".repo/projects").mkdir(parents=True)
        (source / ".repo/project-objects").mkdir(parents=True)
        payload = b"materialized binary payload\n"
        pointer = ("version https://git-lfs.github.com/spec/v1\n"
                   f"oid sha256:{sha(payload)}\nsize {len(payload)}\n")
        revision = init_repo_project(source, "external/lfs", "platform/external/lfs", {
            ".gitattributes": "payload.bin filter=lfs diff=lfs merge=lfs -text\n",
            "payload.bin": pointer,
        })
        row = {"path": "external/lfs", "name": "platform/external/lfs",
               "remote": "aosp", "revision": revision}
        materialized = source / "external/lfs/payload.bin"
        materialized.write_bytes(payload)
        _, dirty, _, audit = provenance.project_state(source, row, include_audit=True)
        self.assertEqual([], dirty)
        self.assertEqual({"payload.bin": {"sha256": sha(payload), "size": len(payload)}},
                         audit["materialized_lfs"])

        original_worktree_blob = provenance._worktree_blob
        raced = False

        def replace_after_recognition(path, expected_mode):
            nonlocal raced
            result = original_worktree_blob(path, expected_mode)
            if path == materialized and not raced:
                raced = True
                materialized.write_bytes(b"changed after LFS recognition\n")
            return result

        with patch.object(provenance, "_worktree_blob",
                          side_effect=replace_after_recognition):
            with self.assertRaisesRegex(
                    provenance.ProvenanceError,
                    "materialized LFS path changed during source audit"):
                provenance.project_state(source, row, include_audit=True)

        materialized.write_bytes(b"wrong payload\n")
        self.assertEqual(["payload.bin"], provenance.project_state(source, row)[1])

    def test_authenticated_crlf_materialization_is_exact_and_receipted(self):
        source = self.root / "eol-source"
        (source / ".repo/projects").mkdir(parents=True)
        (source / ".repo/project-objects").mkdir(parents=True)
        blob = b"one\ntwo\n"
        revision = init_repo_project(source, "external/eol", "platform/external/eol", {
            ".gitattributes": "*.txt text=auto eol=crlf\n",
            "value.txt": blob,
        })
        row = {"path": "external/eol", "name": "platform/external/eol",
               "remote": "aosp", "revision": revision}
        materialized = source / "external/eol/value.txt"
        worktree = blob.replace(b"\n", b"\r\n")
        materialized.write_bytes(worktree)

        _, dirty, _, audit = provenance.project_state(source, row, include_audit=True)
        self.assertEqual([], dirty)
        expected_oid = git(source / "external/eol", "rev-parse", "HEAD:value.txt")
        self.assertEqual({
            "value.txt": {
                "mode": "100644",
                "attributes": {
                    "text": "auto",
                    **provenance.EOL_MATERIALIZATION_INERT_ATTRIBUTES,
                },
                "object": {"oid": expected_oid, "sha256": sha(blob), "size": len(blob)},
                "worktree": {"sha256": sha(worktree), "size": len(worktree)},
            },
        }, audit["materialized_eol"])

        original_worktree_blob = provenance._worktree_blob
        raced = False

        def replace_after_recognition(path, expected_mode):
            nonlocal raced
            result = original_worktree_blob(path, expected_mode)
            if path == materialized and not raced:
                raced = True
                materialized.write_bytes(b"changed after EOL recognition\r\n")
            return result

        with patch.object(provenance, "_worktree_blob",
                          side_effect=replace_after_recognition):
            with self.assertRaisesRegex(
                    provenance.ProvenanceError,
                    "materialized EOL path changed during source audit"):
                provenance.project_state(source, row, include_audit=True)

        materialized.write_bytes(b"one\r\nchanged\r\n")
        self.assertEqual(["value.txt"], provenance.project_state(source, row)[1])

    def test_crlf_materialization_rejects_filters_unsafe_blobs_and_symlinks(self):
        filtered_source = self.root / "filtered-eol-source"
        (filtered_source / ".repo/projects").mkdir(parents=True)
        (filtered_source / ".repo/project-objects").mkdir(parents=True)
        revision = init_repo_project(
            filtered_source, "external/eol", "platform/external/eol", {
                ".gitattributes": "*.txt text=auto eol=crlf filter=evil\n",
                "value.txt": "one\ntwo\n",
            })
        row = {"path": "external/eol", "name": "platform/external/eol",
               "remote": "aosp", "revision": revision}
        (filtered_source / "external/eol/value.txt").write_bytes(b"one\r\ntwo\r\n")
        with self.assertRaisesRegex(provenance.ProvenanceError, "external filter"):
            provenance.project_state(filtered_source, row)
        attributes = filtered_source / "external/eol/.gitattributes"
        attributes.write_text("*.txt -text eol=crlf\n")
        subprocess.run(["git", "-C", str(attributes.parent), "add", ".gitattributes"],
                       check=True)
        subprocess.run(["git", "-C", str(attributes.parent), "commit", "-qm",
                        "wrong text attribute"], check=True)
        row["revision"] = git(attributes.parent, "rev-parse", "HEAD")
        self.assertEqual(["value.txt"], provenance.project_state(filtered_source, row)[1])

        source = self.root / "unsafe-eol-source"
        (source / ".repo/projects").mkdir(parents=True)
        (source / ".repo/project-objects").mkdir(parents=True)
        revision = init_repo_project(source, "external/eol", "platform/external/eol", {
            ".gitattributes": "*.txt text=auto eol=crlf\n",
            "value.txt": "placeholder\n",
        })
        repository = source / "external/eol"
        # Bypass checkout filters to put an explicitly unsafe CR-containing
        # object into the authenticated tree.
        unsafe_blob = b"one\r\ntwo\n"
        oid = subprocess.check_output(
            ["git", "-C", str(repository), "hash-object", "-w", "--stdin"],
            input=unsafe_blob).decode().strip()
        subprocess.run(["git", "-C", str(repository), "update-index", "--cacheinfo",
                        f"100644,{oid},value.txt"], check=True)
        subprocess.run(["git", "-C", str(repository), "commit", "-qm", "unsafe raw blob"],
                       check=True)
        row["revision"] = git(repository, "rev-parse", "HEAD")
        target = repository / "value.txt"
        target.write_bytes(unsafe_blob.replace(b"\n", b"\r\n"))
        self.assertEqual(["value.txt"], provenance.project_state(source, row)[1])

        # A symlink to otherwise-perfect bytes is still a changed tracked
        # object; the target is never followed or accepted as EOL material.
        outside = self.root / "outside-crlf"
        outside.write_bytes(b"placeholder\r\n")
        target.unlink()
        target.symlink_to(outside)
        self.assertEqual(["value.txt"], provenance.project_state(source, row)[1])

    def test_authenticated_crlf_accepts_explicit_text_and_eol_only(self):
        for text_attribute in ("text", ""):
            with self.subTest(text_attribute=text_attribute or "unspecified"):
                source = self.root / ("eol-" + (text_attribute or "implicit"))
                (source / ".repo/projects").mkdir(parents=True)
                (source / ".repo/project-objects").mkdir(parents=True)
                rule = "*.txt %s eol=crlf\n" % text_attribute
                blob = b"one\ntwo\n"
                revision = init_repo_project(
                    source, "external/eol", "platform/external/eol", {
                        ".gitattributes": rule,
                        "value.txt": blob,
                    })
                row = {"path": "external/eol", "name": "platform/external/eol",
                       "remote": "aosp", "revision": revision}
                materialized = source / "external/eol/value.txt"
                materialized.write_bytes(blob.replace(b"\n", b"\r\n"))

                _, dirty, _, audit = provenance.project_state(
                    source, row, include_audit=True)
                self.assertEqual([], dirty)
                expected_text = "set" if text_attribute else "unspecified"
                self.assertEqual(
                    expected_text,
                    audit["materialized_eol"]["value.txt"]["attributes"]["text"])

    def test_authenticated_crlf_accepts_literal_ansi_escape_but_not_other_controls(self):
        source = self.root / "eol-ansi"
        (source / ".repo/projects").mkdir(parents=True)
        (source / ".repo/project-objects").mkdir(parents=True)
        blob = b"plain\n\x1b[31mred\x1b[0m\n"
        revision = init_repo_project(
            source, "external/eol", "platform/external/eol", {
                ".gitattributes": "*.bat text eol=crlf\n",
                "bootstrap.bat": blob,
            })
        row = {"path": "external/eol", "name": "platform/external/eol",
               "remote": "aosp", "revision": revision}
        materialized = source / "external/eol/bootstrap.bat"
        materialized.write_bytes(blob.replace(b"\n", b"\r\n"))
        self.assertEqual([], provenance.project_state(source, row)[1])
        self.assertTrue(provenance._safe_eol_text(blob))
        self.assertFalse(provenance._safe_eol_text(b"bell\x07\n"))

    def test_raw_worktree_hash_detects_replacement_race(self):
        path = self.root / "raced.txt"
        path.write_bytes(b"one\r\ntwo\r\n")
        real_read = os.read
        raced = False

        def replace_after_read(descriptor, amount):
            nonlocal raced
            block = real_read(descriptor, amount)
            if block and not raced:
                raced = True
                path.unlink()
                path.write_bytes(b"one\r\ntwo\r\n")
            return block

        with patch.object(provenance.os, "read", side_effect=replace_after_read), \
                self.assertRaisesRegex(provenance.ProvenanceError,
                                       "changed during raw-byte audit"):
            provenance._worktree_blob(path, "100644")

    def test_source_schema_rejects_malformed_eol_evidence(self):
        record = self.fixture.collect()
        metadata = record["source_audit"]["projects"]["build/make"]
        self.assertEqual({}, metadata["materialized_eol"])
        metadata["materialized_eol"]["core/main.mk"] = {
            "mode": "100644", "attributes": {"text": "auto", "eol": "crlf"},
            "object": {"oid": "1" * 40, "sha256": "2" * 64, "size": 6},
            "worktree": {"sha256": "3" * 64, "size": 7},
        }
        record["source_audit"]["projects_sha256"] = provenance.canonical_digest(
            record["source_audit"]["projects"])
        with self.assertRaisesRegex(provenance.ProvenanceError,
                                    "Invalid materialized EOL row"):
            provenance.validate_source_record_shape(record)

    def test_source_schema_binds_and_validates_gitlink_representation(self):
        record = self.fixture.collect()
        metadata = record["source_audit"]["projects"]["build/make"]
        metadata["gitlinks"]["nested"] = {
            "mode": "160000", "oid": "1" * 40, "state": "absent",
        }
        record["source_audit"]["projects_sha256"] = provenance.canonical_digest(
            record["source_audit"]["projects"])
        self.assertIs(provenance.validate_source_record_shape(record), record)
        metadata["gitlinks"]["nested"]["state"] = "materialized"
        record["source_audit"]["projects_sha256"] = provenance.canonical_digest(
            record["source_audit"]["projects"])
        with self.assertRaisesRegex(provenance.ProvenanceError, "Invalid gitlink row"):
            provenance.validate_source_record_shape(record)

    def test_authenticated_gitlinks_must_remain_unpopulated(self):
        source = self.root / "gitlink-source"
        (source / ".repo/projects").mkdir(parents=True)
        (source / ".repo/project-objects").mkdir(parents=True)
        revision = init_repo_project(source, "external/parent", "platform/external/parent",
                                     {"README": "parent\n"})
        gitlink_revision = revision
        repository = source / "external/parent"
        subprocess.run(["git", "-C", str(repository), "update-index", "--add", "--cacheinfo",
                        "160000," + revision + ",nested"], check=True)
        subprocess.run(["git", "-C", str(repository), "commit", "-qm", "gitlink"], check=True)
        revision = git(repository, "rev-parse", "HEAD")
        row = {"path": "external/parent", "name": "platform/external/parent",
               "remote": "aosp", "revision": revision}
        nested = repository / "nested"
        nested.mkdir()
        _, dirty, _, audit = provenance.project_state(source, row, include_audit=True)
        self.assertEqual([], dirty)
        self.assertEqual({
            "nested": {"mode": "160000", "oid": gitlink_revision,
                       "state": "empty-directory"},
        }, audit["gitlinks"])
        nested.rmdir()
        _, dirty, _, audit = provenance.project_state(source, row, include_audit=True)
        self.assertEqual([], dirty)
        self.assertEqual("absent", audit["gitlinks"]["nested"]["state"])
        for first, second in (("absent", "empty-directory"),
                              ("empty-directory", "absent")):
            with self.subTest(race=f"{first}-to-{second}"), \
                 patch.object(provenance, "_require_unpopulated_gitlink",
                              side_effect=[first, second]), \
                 self.assertRaisesRegex(provenance.ProvenanceError,
                                        "gitlink representation changed"):
                provenance.project_state(source, row)
        nested.mkdir()
        displaced = repository / "nested-displaced"
        real_listdir = os.listdir
        replaced = False

        def replace_empty_gitlink(value):
            nonlocal replaced
            result = real_listdir(value)
            if not replaced:
                replaced = True
                nested.rename(displaced)
                nested.mkdir()
            return result

        with patch.object(provenance.os, "listdir", side_effect=replace_empty_gitlink), \
             self.assertRaisesRegex(provenance.ProvenanceError,
                                    "changed during audit"):
            provenance.project_state(source, row)
        nested.rmdir()
        displaced.rename(nested)
        (nested / "Android.bp").write_text("untrusted build input\n")
        with self.assertRaisesRegex(provenance.ProvenanceError, "materialized"):
            provenance.project_state(source, row)
        (nested / "Android.bp").unlink()
        nested.rmdir()
        nested.symlink_to(repository / "README")
        with self.assertRaisesRegex(provenance.ProvenanceError, "absent or an empty directory"):
            provenance.project_state(source, row)

    def test_clean_repository_audit_receipts_empty_gitlink_and_rejects_content(self):
        repository = self.root / "clean-repository-gitlink"
        gitlink_revision = init_git(repository, {"README": "parent\n"})
        subprocess.run(["git", "-C", str(repository), "update-index", "--add",
                        "--cacheinfo", "160000," + gitlink_revision + ",nested"],
                       check=True)
        subprocess.run(["git", "-C", str(repository), "commit", "-qm", "gitlink"],
                       check=True)
        revision = git(repository, "rev-parse", "HEAD")
        nested = repository / "nested"
        nested.mkdir()

        audit = provenance.clean_repository_audit(
            repository, revision, "clean repository fixture")
        self.assertEqual({
            "nested": {
                "mode": "160000", "oid": gitlink_revision,
                "state": "empty-directory",
            },
        }, audit["gitlinks"])

        (nested / "Android.bp").write_text("untrusted build input\n")
        with self.assertRaisesRegex(provenance.ProvenanceError, "materialized"):
            provenance.clean_repository_audit(
                repository, revision, "clean repository fixture")


def make_apk(path: Path, *, changed=False, signed=False):
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("AndroidManifest.xml", b"manifest")
        archive.writestr("classes.dex", b"changed" if changed else b"classes")
        archive.writestr("resources.arsc", b"resources")
        if signed:
            archive.writestr("META-INF/MANIFEST.MF", b"signature manifest")
            archive.writestr("META-INF/WONAD.RSA", b"signature")


class ClientFixture:
    def __init__(self, base: Path):
        self.base = base
        self.output = base / "compile"
        frozen = self.output / "source/android"
        (frozen / "conformance/src").mkdir(parents=True)
        (frozen / "desktop-sdk").mkdir(parents=True)
        (frozen / "conformance/src/Main.kt").write_text("package org.wonad.desktop\n")
        (frozen / "desktop-sdk/API-v3.md").write_text("API 3\n")
        files = {}
        for path in sorted(frozen.rglob("*")):
            if path.is_file():
                ref = provenance.file_ref(path)
                files[str(path.relative_to(self.output / "source"))] = {
                    "sha256": ref["sha256"], "bytes": ref["size"]}
        freeze = {"schema": 1, "kind": "fresh_current_native_api3_desktop_source_v1", "files": files}
        self.output.mkdir(exist_ok=True)
        write_json(self.output / "source-freeze.json", freeze)
        make_apk(self.output / "conformance-unsigned.apk")
        self.signed = base / "conformance.apk"
        make_apk(self.signed, signed=True)
        self.sdk = base / "sdk"
        self.sdk.mkdir()
        (self.sdk / "publication.bin").write_bytes(b"sdk")
        sdk_files = {}
        for path in self.sdk.rglob("*"):
            if path.is_file():
                ref = provenance.file_ref(path, include_mode=True)
                sdk_files[str(path.relative_to(self.sdk))] = {"sha256": ref["sha256"], "bytes": ref["size"]}
        self.sdk_result = {"coordinate": "org.wonad:desktop-sdk:3.0.1",
                           "contract_signature": "db6ac649c34d8c25ab0bdd4a46802639deb3972d376070c6c3cdd811d7962fff",
                           "contract_members": {
                               "API-v3.md": {"sha256": "a" * 64, "bytes": 1, "mode": 0o644},
                               "desktop-sdk-contract-v3.json": {"sha256": "b" * 64, "bytes": 1, "mode": 0o644},
                               "verify-desktop-sdk-contract.py": {"sha256": "c" * 64, "bytes": 1, "mode": 0o755}}}
        unsigned = provenance.file_ref(self.output / "conformance-unsigned.apk")
        freeze_ref = provenance.file_ref(self.output / "source-freeze.json")
        receipt = {
            "schema": 1, "api": 3, "status": "current_source_compile_qualified_not_runtime",
            "source_bytes_before_after_verified": True,
            "conformance_artifact": {"package": "org.wonad.desktop", "signed": False,
                "native_code": False, "privileged": False, "test_only": False,
                "sha256": unsigned["sha256"], "bytes": unsigned["size"]},
            "build": {"failures": 0, "errors": 0, "skipped": 0, "lint_errors": 0},
            "source": {"sha256": freeze_ref["sha256"], "bytes": freeze_ref["size"]},
            "sdk_publication": {"result": self.sdk_result, "files": sdk_files},
        }
        self.receipt = self.output / "build-receipt.json"
        write_json(self.receipt, receipt)
        self.private_key = base / "temporary-private.pem"
        self.certificate = base / "wonad-production.x509.pem"
        subprocess.run([
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
            "-subj", "/CN=Wonad Production/O=Wonad", "-keyout", str(self.private_key),
            "-out", str(self.certificate),
        ], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.private_key.unlink()
        cert = provenance.public_certificate(self.certificate)
        self.apksigner = base / "apksigner"
        self.apksigner.write_text(
            "#!/bin/sh\n"
            "if [ \"$1\" = lineage ]; then\n"
            "  echo 'The provided APK does not contain a valid lineage.'\n"
            "  exit 1\n"
            "fi\n"
            "echo 'Verified using v1 scheme (JAR signing): true'\n"
            "echo 'Verified using v2 scheme (APK Signature Scheme v2): true'\n"
            f"echo 'Signer #1 certificate SHA-256 digest: {cert['der_sha256']}'\n")
        self.apksigner.chmod(0o755)

    def collect(self, qualification="production"):
        verifier = types.SimpleNamespace(verify_repository=lambda repository, source: self.sdk_result)
        with patch.object(provenance, "import_sdk_verifier", return_value=verifier):
            return provenance.collect_clients(self.sdk, self.signed, self.receipt,
                                              self.certificate, self.apksigner, qualification)


class Phase1ClientProvenanceTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="wonad-client-provenance-")
        self.root = Path(self.temporary.name)
        self.fixture = ClientFixture(self.root)

    def tearDown(self):
        self.temporary.cleanup()

    def test_signed_apk_sdk_signer_and_complete_source_freeze_are_bound(self):
        record = self.fixture.collect()
        self.assertEqual(3, record["schema"])
        self.assertEqual("production", record["qualification"])
        self.assertEqual(record["public_signer"]["der_sha256"],
                         record["conformance"]["signing"]["certificate_sha256"])
        self.assertEqual([], record["conformance"]["signing"]
                         ["lineage_certificate_sha256"])
        self.assertEqual(2, len(record["source_freeze"]["files"]))
        provenance.validate_clients_shape(record)

    def test_production_record_shape_rejects_signing_history(self):
        record = self.fixture.collect()
        record["conformance"]["signing"]["lineage_certificate_sha256"] = ["a" * 64]
        with self.assertRaisesRegex(provenance.ProvenanceError, "lineage/history"):
            provenance.validate_clients_shape(record)

    def test_signed_payload_change_is_rejected(self):
        make_apk(self.fixture.signed, changed=True, signed=True)
        with self.assertRaisesRegex(provenance.ProvenanceError, "payload differs"):
            self.fixture.collect()

    def test_sdk_publication_and_frozen_source_drift_are_rejected(self):
        (self.fixture.sdk / "publication.bin").write_bytes(b"drift")
        with self.assertRaisesRegex(provenance.ProvenanceError, "SDK publication differs"):
            self.fixture.collect()
        (self.fixture.sdk / "publication.bin").write_bytes(b"sdk")
        source = self.fixture.output / "source/android/conformance/src/Main.kt"
        source.write_text("drift")
        with self.assertRaisesRegex(provenance.ProvenanceError, "Frozen conformance/SDK source differs"):
            self.fixture.collect()

    def test_sdk_contract_member_digest_must_be_a_string(self):
        record = self.fixture.collect()
        record["sdk_publication"]["verification"]["contract_members"][
            "API-v3.md"]["sha256"] = int("1" * 64)
        with self.assertRaisesRegex(provenance.ProvenanceError, "contract-member"):
            provenance.validate_clients_shape(record)

    def test_full_collection_rejects_alternate_valid_member_digest(self):
        self.fixture.sdk_result["contract_members"]["API-v3.md"]["sha256"] = "9" * 64
        with self.assertRaisesRegex(provenance.ProvenanceError, "SDK publication differs"):
            self.fixture.collect()

    def test_signer_mismatch_and_development_identity_are_explicit(self):
        self.fixture.apksigner.write_text(
            "#!/bin/sh\nif [ \"$1\" = lineage ]; then\n"
            "  echo 'The provided APK does not contain a valid lineage.'\n  exit 1\nfi\n"
            "echo 'Verified using v2 scheme (APK Signature Scheme v2): true'\n"
            "echo 'Signer #1 certificate SHA-256 digest: " + "0" * 64 + "'\n")
        with self.assertRaisesRegex(provenance.ProvenanceError, "signer differs"):
            self.fixture.collect()
        # Development status is a distinct immutable receipt field, not a
        # production receipt with an informal note attached.
        cert = provenance.public_certificate(self.fixture.certificate)
        self.fixture.apksigner.write_text(
            "#!/bin/sh\nif [ \"$1\" = lineage ]; then\n"
            "  echo 'The provided APK does not contain a valid lineage.'\n  exit 1\nfi\n"
            "echo 'Verified using v2 scheme (APK Signature Scheme v2): true'\n"
            f"echo 'Signer #1 certificate SHA-256 digest: {cert['der_sha256']}'\n")
        self.assertEqual("development", self.fixture.collect("development")["qualification"])

    def test_production_rejects_history_hidden_by_single_current_signer(self):
        cert = provenance.public_certificate(self.fixture.certificate)
        previous = "a" * 64
        self.fixture.apksigner.write_text(
            "#!/bin/sh\n"
            "if [ \"$1\" = lineage ]; then\n"
            f"  echo 'Signer #1 in lineage certificate SHA-256 digest: {previous}'\n"
            f"  echo 'Signer #2 in lineage certificate SHA-256 digest: {cert['der_sha256']}'\n"
            "  exit 0\n"
            "fi\n"
            "echo 'Verified using v3 scheme (APK Signature Scheme v3): true'\n"
            "echo 'Number of signers: 1'\n"
            f"echo 'Signer #1 certificate SHA-256 digest: {cert['der_sha256']}'\n")
        with self.assertRaisesRegex(provenance.ProvenanceError, "lineage/history"):
            self.fixture.collect("production")
        development = self.fixture.collect("development")
        self.assertEqual(
            [previous, cert["der_sha256"]],
            development["conformance"]["signing"]["lineage_certificate_sha256"])

    def test_lineage_absence_query_fails_closed(self):
        cert = provenance.public_certificate(self.fixture.certificate)
        verify = (
            "echo 'Verified using v3 scheme (APK Signature Scheme v3): true'\n"
            f"echo 'Signer #1 certificate SHA-256 digest: {cert['der_sha256']}'\n")
        for status, output in (
                (0, ""),
                (0, "Signer #2 in lineage certificate SHA-256 digest: " + "a" * 64),
                (1, "unexpected parser failure"),
                (2, "The provided APK does not contain a valid lineage.")):
            with self.subTest(status=status, output=output):
                self.fixture.apksigner.write_text(
                    "#!/bin/sh\n"
                    "if [ \"$1\" = lineage ]; then\n"
                    f"  echo '{output}'\n"
                    f"  exit {status}\n"
                    "fi\n" + verify)
                with self.assertRaisesRegex(
                        provenance.ProvenanceError,
                        "lineage output is malformed|Cannot prove absence"):
                    self.fixture.collect("production")

    def test_private_key_like_inputs_are_never_inventoried(self):
        secret = self.root / "releasekey.pk8"
        secret.write_bytes(b"secret")
        with self.assertRaisesRegex(provenance.ProvenanceError, "key-like"):
            provenance.public_certificate(secret)

    def test_wonad_signer_must_be_distinct_from_every_os_signing_role(self):
        other_key = self.root / "other-private.pem"
        other_certificate = self.root / "platform.x509.pem"
        subprocess.run([
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
            "-subj", "/CN=GrapheneOS Platform/O=Wonad Test", "-keyout", str(other_key),
            "-out", str(other_certificate),
        ], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        other_key.unlink()
        result = provenance.assert_distinct_os_signers(
            self.fixture.certificate, [other_certificate])
        self.assertEqual(1, result["os_certificate_count"])
        with self.assertRaisesRegex(provenance.ProvenanceError,
                                    "distinct from GrapheneOS signer"):
            provenance.assert_distinct_os_signers(
                self.fixture.certificate, [other_certificate, self.fixture.certificate])

    def test_production_client_and_source_evidence_are_staged_without_private_keys(self):
        os_fixture = self.root / "os-fixture"
        os_fixture.mkdir()
        source_fixture = SourceFixture(os_fixture)
        source_record = self.root / "source-provenance.json"
        write_json(source_record, source_fixture.collect())
        client_record = self.root / "client-provenance.json"
        write_json(client_record, self.fixture.collect())
        destination = self.root / "release/wonad-provenance"
        destination.parent.mkdir()
        verifier = types.SimpleNamespace(
            verify_repository=lambda repository, source: self.fixture.sdk_result)
        with patch.object(provenance, "import_sdk_verifier", return_value=verifier):
            staged = provenance.stage_client_evidence(
                self.fixture.sdk, self.fixture.signed, self.fixture.receipt,
                self.fixture.certificate, self.fixture.apksigner, client_record,
                source_record, destination)
        self.assertEqual("production", staged["clients"]["qualification"])
        self.assertTrue((destination / "source-provenance.json").is_file())
        self.assertTrue((destination / "client-provenance.json").is_file())
        self.assertTrue((destination / "conformance.apk").is_file())
        self.assertTrue((destination / "compile/source/android/conformance/src/Main.kt").is_file())
        self.assertTrue((destination / "sdk/publication.bin").is_file())
        self.assertFalse(any(path.suffix in provenance.PRIVATE_SUFFIXES
                             for path in destination.rglob("*")))
        with patch.object(provenance, "import_sdk_verifier", return_value=verifier), \
                self.assertRaisesRegex(provenance.ProvenanceError, "already exists"):
            provenance.stage_client_evidence(
                self.fixture.sdk, self.fixture.signed, self.fixture.receipt,
                self.fixture.certificate, self.fixture.apksigner, client_record,
                source_record, destination)


if __name__ == "__main__":
    unittest.main()
