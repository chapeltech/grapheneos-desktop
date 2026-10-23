# Supplemental frozen payload replay

2026-10-12. External-only packaging/byte-consistency check, not staging,
native/framework build, VM/JNI execution or runtime qualification.

Final payload: `sealed-2/MANIFEST.json`, SHA-256
`512be7775dc1874fea65ad1868848fe3c89d70fc246cbf8b0b8709f812f55975`.
The final source/host payload is read-only, and every `SHA256SUMS` item passes.

`validate_payload.py` authenticates the manifest and each exact original,
copies only selected originals to fresh temporary external project copies,
runs ordered `git apply --check` and applies there, then checks all resulting
target hashes. It never applies to the parent repository or custom-7 source.

Observed final result, exit 0:

```text
PATCH_REPLAY_PASS 01-frameworks-base-wonad-private-key-admission.patch
PATCH_REPLAY_PASS 02-frameworks-native-wonad-private-key-admission.patch
PATCH_REPLAY_PASS 03-wonad-input-integration.patch
ORDERED_PRIVATE_PATCH_TARGET_PASS checks=24
```

Patch SHA-256:

```text
base: 2fe9332aae8fcbad5337e381ae87b11aac0a2c0d6ade11efb9b7e62ab9ffc5b5
native: 703f9824007f6ab0c4a5ecc0c5d67fcd5e4562ca16f6e637a1904bdd968beb5a
integration: 1f36487bd0963b6a83006eb4d2c5fa1fd3a1136c9a0bc3ec854c40f8926f3c1a
```

The first immutable `sealed/` remains preserved, with manifest SHA-256
`be0890af0dccecdd6c43c24fd50e3a591d8b3f283ae7a4f7a77baefa312d0d63`.
Its base/native patches passed, but integration additions lacked new-file-mode
headers, causing `git apply` to treat `/dev/null` as a target. `sealed-2/`
corrects only those packaging headers and documentation/sealing destination;
the implementation and native/base patch bytes are unchanged.
