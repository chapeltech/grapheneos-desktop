# Phase-1 custom-7 metadata review

Read-only metadata audit passed at 2026-10-11T13:07:27.847675+00:00. Candidate source root: `/u/elric/tree/wonad-grapheneos-2026100600-phase1-custom-7`.

- All 5,159 `.repo` symlinks resolve within source7; all 1,057 object symlinks resolve within its `.repo`.
- All 1,057 project `.git` links resolve to the corresponding new `.repo/projects/...git`. The metadata project set exactly matches `project.list`.
- All 30,489 regular metadata/object files observed during this audit have link count 1 and UID/GID 1000:1000. No examined metadata entry shares its original counterpart's device/inode. A subsequent metadata-only count was 30,488 with no additional file lacking an original counterpart; one transient entry disappeared between observations while root's checks ran. No stable/frozen metadata inventory is claimed.
- No `alternates`, `http-alternates`, `commondir`, or `gitdir` control file exists. No local filesystem remote URL or operational Git include/worktree/object path key was found.
- Source root/repo/out device-inodes are `64513/1385832169`, `64513/647041825`, and `64513/205344858`; all owned 1000:1000, mode 0755. `out/` stayed literal, empty, and distinct from the original's root-owned out inode `7646663`.
- Old-root text outside historical trace logs appears only in `repo.syncstate.sys.argv` in the manifest Git config/cache: inert sync history, not operational aliases.

The accompanying JSON records counts and inventory digests. This is not source-byte identity, signed-pin verification, tracked-cleanliness, source-freeze, staging, or build proof. Root runs those checks separately. No source7/source6/original mutation, compiler, vendor preparation, guest, or full source-byte walk occurred.
