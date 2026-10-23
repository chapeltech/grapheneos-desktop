"""Pure literal installed base-APK boundary; no filesystem/package authority.

Pinned PMSUtils.getNextCodePath uses two URL_SAFE base64 16-byte nonces,
with PMS.RANDOM_DIR_PREFIX='~~'. Historical one-directory observations remain
readable; arbitrary extra directories, aliases and split APKs do not.
Exact package/UID/version/bytes admission remains each caller's responsibility.
"""
import base64
import re


def installed_apk_path(value, package=None, *, package_row=False):
    if type(value) is not str or type(package_row) is not bool:
        raise ValueError("Installed base APK path must be a literal string")
    if package is not None and (type(package) is not str or not re.fullmatch(
            r"[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z0-9_]+)+", package)):
        raise ValueError("Invalid expected installed package")
    if package_row:
        if not value.startswith("package:"):
            raise ValueError("Installed APK observation must be exactly one package row")
        value = value[len("package:"):]
        if value.endswith("\n"): value = value[:-1]
    if not value.startswith("/data/app/") or not value.endswith("/base.apk"):
        raise ValueError("Installed path is not one literal /data/app base APK")
    directories = value[len("/data/app/"):-len("/base.apk")].split("/")
    def nonce(text):
        if not re.fullmatch(r"[A-Za-z0-9_-]{22}==", text): return False
        decoded = base64.urlsafe_b64decode(text)
        return len(decoded) == 16 and base64.urlsafe_b64encode(decoded).decode("ascii") == text
    if len(directories) == 1:
        valid = directories[0] not in {".", ".."} and re.fullmatch(r"[A-Za-z0-9_+=.-]+", directories[0]) is not None
    elif len(directories) == 2:
        first, second = directories
        match = re.fullmatch(r"([A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z0-9_]+)+)-([A-Za-z0-9_-]{22}==)", second)
        valid = first.startswith("~~") and nonce(first[2:]) and match is not None and \
            nonce(match[2]) and (package is None or match[1] == package)
    else: valid = False
    if not valid: raise ValueError("Unsafe/aliased/split installed base APK path")
    return value
