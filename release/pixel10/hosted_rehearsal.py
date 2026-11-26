#!/usr/bin/python3
"""Exercise GitHub-hosted OS signing without access to any production secrets."""
import os
from pathlib import Path
import sys
import tempfile

import hosted_keygen
import hosted_keys
import hosted_run
from publish import LIMIT


def main():
    if (os.environ.get("GITHUB_REPOSITORY") != hosted_run.security.REPO
            or os.environ.get("HOSTED_RUNNER") != "github-hosted"
            or os.environ.get("CHANNEL") != "sign-only"):
        raise ValueError("disposable rehearsal requires the GitHub-hosted signing test job")
    if any(name in os.environ for kind in hosted_keys.FILES for name in hosted_keys.secret_names(kind)):
        raise ValueError("production secret unexpectedly present in rehearsal")
    os.umask(0o077)
    build, commit, approved = (os.environ[name] for name in
                               ("BUILD_NUMBER", "SOURCE_COMMIT", "UNSIGNED_SUMS_SHA256"))
    hosted_run.intake.COMMON["identity"](build, commit, approved)
    work = Path(os.environ["RUNNER_TEMP"]) / ("frankel-os-" + build)
    target = work / "unsigned" / build
    hosted_run.run_verify_tools(work, target)
    with tempfile.TemporaryDirectory(prefix=".rehearsal-", dir=work) as tmp:
        generated = Path(tmp) / "disposable"
        hosted_keygen.generate(generated, str(work / "verify-tools/avbtool"), "Disposable GitHub rehearsal", 4)
        hosted_run.TRUST = generated / "trust"
        for kind in hosted_keys.FILES:
            os.environ.update(zip(hosted_keys.secret_names(kind), hosted_keys.pack(kind, generated / kind)))
        hosted_run.sign("os", work, target, build, commit, approved)
        signed = work / "signed" / build
        hosted_run.verify_os(signed, hosted_run.TRUST, build, commit, approved)
        ota = signed / f"frankel-ota_update-{build}.zip"
        factory = signed / f"frankel-install-{build}.zip"
        if ota.stat().st_size >= LIMIT:
            raise ValueError("rehearsal OTA exceeds the GitHub Release asset limit")
        print(f"Verified disposable factory image ({factory.stat().st_size} bytes) and OTA "
              f"({ota.stat().st_size} bytes). No files or keys were published.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
