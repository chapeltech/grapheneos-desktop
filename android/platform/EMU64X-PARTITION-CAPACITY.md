# Phase-1 x86 emulator partition capacity

## Failure classification

The pristine 2026100600 x86 baseline attempt 4 did not fail because of RAM,
host disk space, or Wonad. It reached the debug `super.img` rule and `lpmake`
rejected the stock Goldfish dynamic-partition group.

The five generated images were:

| partition | bytes |
|---|---:|
| `system` | 1,468,854,272 |
| `system_dlkm` | 9,408,512 |
| `system_ext` | 530,649,088 |
| `product` | 870,113,280 |
| `vendor` | 116,178,944 |
| **total** | **2,995,204,096** |

The product default in
`device/generic/goldfish/64bitonly/product/sdk_phone64_x86_64.mk` is 2,800 MiB,
or 2,936,012,800 bytes. The pristine images exceed it by 59,191,296 bytes
(56.449 MiB). Merely rounding the total up would leave no useful reserve for
the custom build or for filesystem allocation changes.

## Fixed development-build contract

Both the pristine baseline and Wonad custom launchers export exactly:

```text
BOARD_EMULATOR_DYNAMIC_PARTITIONS_SIZE=3355443200
```

That is a 3,200 MiB group. The locked Goldfish product declares the group with
`?=` and derives `BOARD_SUPER_PARTITION_SIZE` as the group plus 8 MiB, so the
generated values must be:

```text
super_emulator_dynamic_partitions_group_size=3355443200
super_super_device_size=3363831808
super_partition_size=3363831808
```

The failed baseline's images leave 360,239,104 bytes (343.551 MiB) free under
this contract. The verifier requires at least 256 MiB after every baseline and
custom build. All three fixed sizes and every constituent image must be
4,096-byte aligned. The existing 8 MiB super-device reserve is retained; this
is greater than the build system's 1 MiB metadata warning threshold.

This is deliberately an identical build input, not a source patch. It keeps
the baseline checkout pristine, keeps the custom checkout limited to the
schema-4 Wonad stage, and prevents an emulator-capacity change from appearing
as an OS-glue delta.

## Enforcement

`android/tools/run_x86_build.py` pins the value in the retained Docker process
contract. A zero Docker exit is not accepted until
`android/tools/x86_partition_capacity.py` has checked the generated
`misc_info.txt`, each named partition image, the exact group/super values,
alignment, and the 256 MiB headroom floor. The receipt verifier binds both the
launcher and the capacity verifier by SHA-256. The current x86 build receipt
and baseline/custom comparison format is schema 4; a receipt from an older
schema or an earlier tool ledger cannot qualify this contract.

The same retained contract pins both baseline and custom builds to `m -j6`.
R8 edges are not consistently assigned to Android's high-memory Ninja pool;
at `-j16` they exhausted a 64 GiB build host even with
`NINJA_HIGHMEM_NUM_JOBS=1`. Six global jobs keep the two builds symmetric while
bounding concurrent R8/Java memory, and the receipt records both the command
and the job count.

The same check can be run independently after a build:

```sh
/usr/bin/python3.14 android/tools/x86_partition_capacity.py \
  --out /absolute/path/to/external-out
```

The preserved attempt-4 OUT_DIR correctly fails this command because it records
the stock 2,800 MiB group and 2,808 MiB super device. It must remain failed
evidence and must not be resumed or represented as a successful baseline.
