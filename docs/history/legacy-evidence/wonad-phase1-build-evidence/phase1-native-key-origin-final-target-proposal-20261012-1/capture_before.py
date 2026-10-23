#!/usr/bin/env python3
from pathlib import Path
import hashlib
import json
import shutil

HERE = Path(__file__).resolve().parent
STAGE = Path("/u/elric/tree/wonad-grapheneos-2026100600-phase1-custom-7")
PREFIX = "frameworks/native/services/inputflinger/"
INPUTS = {
    "dispatcher/InputDispatcher.cpp": "4598e3a96e0196a5965be2a4232736ba7e14616c8435b201ab6d394e44b762c9",
    "dispatcher/InputDispatcher.h": "713ca2351b28ebde8829edada02bea18c4923614f353bd7ca277eff69f4994d6",
    "dispatcher/Entry.h": "57aa994e65bfeebdceec811dd2bd380c6918508df93ce4799b3e682c433442b0",
    "dispatcher/InputState.cpp": "ba322dd34e39f4421147a3187382bded3721b9a0f747a0c12e1b2462209115b8",
    "dispatcher/InputState.h": "bb8ad78a1971ec4757d8d0d7b3ceb30771dcc65df01b1b7ad4a6e92c9dfed5d9",
    "dispatcher/CancellationOptions.h": "890999251333246bb989d17c34bb2aaae72c6805b7350249eb17809f5fd41ea6",
    "dispatcher/FocusResolver.h": "25892b8775a0e5e6fb5c40acdc758891feaf6dd6712a0606eaed6afeea78e246",
    "dispatcher/FocusResolver.cpp": "ed6a861b85cb67e5cc57b31455667f16b77f8c3c264a4074fa8645b3790006c3",
    "dispatcher/Connection.h": "b4e546e55edf8aea20cd1762add3272d831be45cc976bd503ac3dd096169a7f1",
    "NotifyArgs.cpp": "0d37d426eb810482da856c3b0f7a52ab80111432e384d961176e58cf7a4dbabf",
    "InputListener.cpp": "8a03ffb7e60868e68b4f5a4d71d695e9aa20e497dc91f6e2f2f8b9b6ace81e16",
    "include/NotifyArgs.h": "1aa9199e4187c3daa88be448b8b833366442376534eab9448c88aeaf49672376",
    "reader/InputReader.cpp": "3a5acd8dbbd4d880a27eb84d9de68cbcceb81a91593749340a1800be7856eb5d",
    "reader/InputDevice.cpp": "5a27592c180326513ef9aa3260a8f126ada0c5b3cfe24b942bf63c59ae339cea",
    "reader/include/InputDevice.h": "5261231edbe36deb1b338ed66635898d64ea76140244af8d0c2c62f1ab533d7a",
    "reader/mapper/KeyboardInputMapper.cpp": "0a8bc5d7d66b02d4faac11f9c8252e6bb059f7ad2f4cbbae80865d32a810f303",
}

def digest(path): return hashlib.sha256(path.read_bytes()).hexdigest()

def main():
    target = HERE / "before"
    if target.exists(): raise SystemExit("before snapshot already exists; preserve it")
    target.mkdir()
    inputs = {}
    for relative, pin in INPUTS.items():
        original = STAGE / PREFIX / relative
        assert digest(original) == pin, relative
        output = target / relative
        output.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(original, output)
        output.chmod(0o444)
        inputs[relative] = {"source": str(original), "sha256": pin}
    (target / "MANIFEST.json").write_text(json.dumps(inputs, sort_keys=True, indent=2) + "\n")
    (target / "MANIFEST.json").chmod(0o444)
    for path in target.rglob("*"):
        if path.is_dir(): path.chmod(0o555)
    target.chmod(0o555)
    print("IMMUTABLE_BEFORE_MANIFEST=" + digest(target / "MANIFEST.json"))

if __name__ == "__main__": main()
