#!/usr/bin/env bash
# Run selected targets from an existing Android Ninja graph without restaging,
# regenerating, or cleaning the source checkout. This is intentionally narrower
# than source-build.sh and is meant for recovery/incremental builds in the
# pinned builder image.
set -euo pipefail

usage() {
    cat >&2 <<'EOF'
Usage: direct-target-build.sh \
  --source SOURCE --out OUT --graph GRAPH --jobs JOBS -- TARGET [TARGET ...]

SOURCE is the Android/GrapheneOS checkout. OUT and GRAPH must be normalized,
relative paths below SOURCE; GRAPH must be a combined-*.ninja file below OUT.
At least one explicit Ninja target is required.

The highmem pool depth is already encoded in GRAPH by Soong; this helper does
not claim to change it at Ninja execution time.
EOF
}

die() {
    echo "direct-target-build.sh: $*" >&2
    exit 2
}

need_value() {
    (($# >= 2)) && [[ -n "$2" ]] || die "$1 requires a value"
}

source_arg=
out_arg=
graph_arg=
jobs=
source_set=0
out_set=0
graph_set=0
jobs_set=0

while (($#)); do
    case "$1" in
        --source)
            need_value "$@"
            ((source_set == 0)) || die '--source may only be specified once'
            source_arg=$2
            source_set=1
            shift 2
            ;;
        --out)
            need_value "$@"
            ((out_set == 0)) || die '--out may only be specified once'
            out_arg=$2
            out_set=1
            shift 2
            ;;
        --graph)
            need_value "$@"
            ((graph_set == 0)) || die '--graph may only be specified once'
            graph_arg=$2
            graph_set=1
            shift 2
            ;;
        --jobs)
            need_value "$@"
            ((jobs_set == 0)) || die '--jobs may only be specified once'
            jobs=$2
            jobs_set=1
            shift 2
            ;;
        --)
            shift
            break
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            die "unknown option $1 (use -- before explicit targets)"
            ;;
    esac
done

((source_set == 1)) || die '--source is required'
((out_set == 1)) || die '--out is required'
((graph_set == 1)) || die '--graph is required'
((jobs_set == 1)) || die '--jobs is required'
(($# > 0)) || die 'at least one explicit target is required after --'

[[ "$jobs" =~ ^[1-9][0-9]*$ ]] || die '--jobs must be a positive decimal integer'
((${#jobs} <= 3)) && ((jobs <= 256)) || die '--jobs must not exceed 256'

[[ -d "$source_arg" ]] || die 'source directory does not exist'
source_dir=$(realpath -e -- "$source_arg")
[[ "$source_dir" != / ]] || die 'source directory must not be the filesystem root'
[[ -d "$source_dir/.repo" ]] || die 'source is not a repo-managed Android checkout'
[[ -f "$source_dir/build/soong/soong_ui.bash" ]] || die 'source is missing build/soong/soong_ui.bash'

validate_relative() {
    local label=$1 value=$2
    [[ -n "$value" && "$value" != /* ]] || die "$label must be a non-empty relative path"
    [[ "$value" =~ ^[A-Za-z0-9._/-]+$ ]] || die "$label contains unsupported characters"
    [[ "$value" != . && "$value" != .. && "$value" != ./* ]] || die "$label must be normalized"
    [[ "$value" != */./* && "$value" != */. && "$value" != ../* && "$value" != */../* && "$value" != */.. ]] ||
        die "$label must not contain dot path components"
    [[ "$value" != *//* ]] || die "$label must be normalized"
}

validate_relative '--out' "$out_arg"
validate_relative '--graph' "$graph_arg"

out_path="$source_dir/$out_arg"
[[ -d "$out_path" && ! -L "$out_path" ]] || die 'out must be an existing, non-symlink directory'
[[ $(realpath -e -- "$out_path") == "$out_path" ]] || die 'out must resolve directly below source'

case "$graph_arg" in
    "$out_arg"/*) ;;
    *) die 'graph must be below out' ;;
esac
[[ $(basename -- "$graph_arg") =~ ^combined-[A-Za-z0-9._-]+\.ninja$ ]] ||
    die 'graph must be a combined-*.ninja file'
graph_path="$source_dir/$graph_arg"
[[ -f "$graph_path" && ! -L "$graph_path" ]] || die 'graph must be an existing, non-symlink regular file'
[[ $(realpath -e -- "$graph_path") == "$graph_path" ]] || die 'graph must resolve directly below out'
[[ $(grep -Fxc -- "builddir = $out_arg" "$graph_path" || true) == 1 ]] ||
    die 'graph builddir does not exactly match out'
grep -Eq -- "^subninja ${out_arg//./\\.}/" "$graph_path" ||
    die 'graph does not include an out-tree subninja'

ninja="$source_dir/prebuilts/build-tools/linux-x86/bin/ninja"
[[ -f "$ninja" && -x "$ninja" && ! -L "$ninja" ]] ||
    die 'source is missing the executable pinned Ninja binary'

targets=("$@")
for target in "${targets[@]}"; do
    [[ -n "$target" ]] || die 'targets must not be empty'
    [[ "$target" != -* ]] || die "target must not begin with '-': $target"
    [[ "$target" != *[[:cntrl:]]* ]] ||
        die 'targets must not contain control characters'
done

cd -- "$source_dir"
export OUT_DIR="$out_arg"
# Soong consumes these as extra Ninja options. A direct build deliberately has
# a fixed option set, so do not leak caller-provided additions into build tools.
unset NINJA_ARGS NINJA_EXTRA_ARGS

exec "$ninja" \
    -d keepdepfile \
    -d keeprsp \
    -d stats \
    -o usesphonyoutputs=yes \
    -w dupbuild=err \
    -w missingdepfile=err \
    -w missingoutfile=err \
    -f "$graph_arg" \
    -j "$jobs" \
    "${targets[@]}"
