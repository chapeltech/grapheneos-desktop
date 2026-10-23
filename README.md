# GrapheneOS external-desktop integration

This repository owns the privileged desktop extension, API v3 / SDK 3.1.0,
conformance tests, upstream manifest pins, build tools and OS-specific notes.
It does not own window-manager policy, StyX11, grsh or the Compose laboratory.

Our Android project modifications are commits in independent Git repositories
under `forks/`, indexed by `forks.lock.json`. There are no object alternates into
the old checkouts; immutable upstream objects are hard-linked locally to avoid
duplicating gigabytes. Deleting an old checkout does not delete a fork's links.
Do not add `forks/` as ordinary files to this integration repository: use the
lab's source export, which bundles the unique commits separately.

Edit upstream changes in the small canonical Git worktrees under `projects/`
(for example `projects/frameworks/base`), on `desktop/work`. They initially show
only changed files; use Git sparse-checkout to expand the view when needed.
Keep new commits in the fork, then deliberately update the lock before using them
in a reproducible build. The lab export includes dirty fork worktrees as well as refs.

Each preserved checkout has an `archive/...` branch. `desktop/emulator` and
`desktop/pixel10` also preserve the previously selected development trees.
The active lock now selects `desktop/source-stack`: the exact current declared
43 framework / 6 Launcher / 4 Goldfish patch inputs, mechanically imported into
Git with no manual edits. `current-input-import.json` records that conversion;
`previous_active` retains the older selections. None implies runtime qualification.
Old patches/staging tools are provenance/compatibility material, not an authority
for new edits. Modify fork commits and update the lock for future source changes.

Generate a repo local manifest using the lab's `tools/fork_manifest.py
grapheneos-desktop --profile emulator` (or `pixel10`). It pins exact fork commits;
keep the authenticated upstream manifest for all unchanged projects. Application
of this manifest and subsequent builds require an explicitly chosen build workspace.

Build the SDK directly with `gradle --offline -p android
:desktop-sdk:verifyPhase1Publication`. Its Maven coordinate remains
`org.wonad:desktop-sdk:3.1.0`; no API/package identity was changed in migration.
The native broker/input and OS integration modules remain below `android/`.

The [shared lab](../wonad-lab/README.md) owns image composition and cross-component
tests. The Pixel 10 target remains frankel; the x86-64 emulator is only a development
sibling. Existing release/build/source gates remain required; moving files does
not qualify a release or grant authority to install one.
