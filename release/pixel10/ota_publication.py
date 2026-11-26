"""GitHub-backed OTA pointers. The public branch stores metadata, never binaries."""
import base64
import json
import os
import re
import time
from urllib.error import HTTPError
from urllib.request import Request, urlopen

REPO = "chapeltech/grapheneos-desktop"
BRANCH = "ota"
RAW = f"https://raw.githubusercontent.com/{REPO}/{BRANCH}/"
RELEASES = f"https://github.com/{REPO}/releases/download/"
NAME = re.compile(r"(?:frankel-(?:beta|stable)|desktop-apps-(?:beta|stable)\.json)")


def pointer(name):
    if not NAME.fullmatch(name):
        raise ValueError("not an OTA pointer")
    return f"https://api.github.com/repos/{REPO}/contents/{name}"


def api(url, data=None):
    req = Request(url, data=data, method="PUT" if data is not None else "GET", headers={
        "Authorization": "Bearer " + os.environ["GH_TOKEN"],
        "Accept": "application/vnd.github+json",
        "Content-Type": "application/json",
    })
    with urlopen(req, timeout=30) as response:
        return json.load(response)


def read(name):
    endpoint = pointer(name)
    try:
        record = api(endpoint + "?ref=" + BRANCH)
    except HTTPError as e:
        if e.code == 404:
            return None, None
        raise
    if not (record["type"] == "file" and record["encoding"] == "base64" and
            record["size"] <= 32768 and re.fullmatch("[a-f0-9]{40}", record["sha"])):
        raise ValueError("unexpected OTA content record")
    body = base64.b64decode(record["content"])
    if len(body) != record["size"]:
        raise ValueError("invalid OTA content length")
    return body, record["sha"]


def write(name, body, previous_sha):
    update = {"message": f"Advance {name}", "content": base64.b64encode(body).decode(),
              "branch": BRANCH}
    if previous_sha is not None:
        update["sha"] = previous_sha
    api(pointer(name), json.dumps(update).encode())


def wait_visible(name, body, public):
    # The public Raw CDN may cache a prior response, including a missing path.
    for attempt in range(12):
        if public(name) == body:
            return
        if attempt != 11:
            time.sleep(10)
    raise ValueError(f"{name} written but not visible on GitHub Raw yet; retry")
