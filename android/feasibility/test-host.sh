#!/usr/bin/env bash
set -euo pipefail
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
out="$root/android/out/host-probe"
mkdir -p "$out/classes" "$out/objects"
for tool in ghc javac java; do
    command -v "$tool" >/dev/null || { echo "Missing host tool: $tool" >&2; exit 2; }
done
jdk=$(dirname -- "$(dirname -- "$(readlink -f -- "$(command -v javac)")")")
ghc --make -O1 -Wall -Werror -fPIC -dynamic -shared -threaded \
    -no-hs-main -flink-rts \
    -i"$root/android/feasibility" \
    -I"$jdk/include" -I"$jdk/include/linux" \
    -odir "$out/objects" -hidir "$out/objects" -stubdir "$out/objects" \
    "$root/android/feasibility/NativeProbe.hs" \
    "$root/android/feasibility/probe_jni.c" \
    -o "$out/libwonad_probe.so"
javac -Xlint:all -Werror -d "$out/classes" \
    "$root/android/feasibility/java/org/wonad/probe/NativeProbe.java" \
    "$root/android/feasibility/java/org/wonad/probe/ProbeChecks.java"
java -Xcheck:jni -Djava.library.path="$out" -cp "$out/classes" org.wonad.probe.ProbeChecks
