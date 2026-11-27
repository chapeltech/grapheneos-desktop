#!/usr/bin/python3
"""Fail closed if the repository's production key boundary is weakened."""
import json
import os
import sys
from urllib.request import Request, urlopen

REPO = "chapeltech/grapheneos-desktop"
REF = "refs/heads/release/pixel10"
ENVIRONMENT = "pixel10-sign"


def require(condition, detail):
    if not condition:
        raise ValueError(detail)


def check(ref, protected, runner, environment, policies, expected=ENVIRONMENT):
    require(ref == REF and protected, "dispatch from the protected release/pixel10 branch")
    require(runner == "github-hosted", "production keys may only be used on a GitHub-hosted runner")
    require(environment["name"] == expected, f"unexpected release environment; expected {expected}")
    require(any(rule["type"] == "required_reviewers" and rule.get("reviewers")
                for rule in environment["protection_rules"]), "configure a signing environment reviewer")
    require(environment.get("deployment_branch_policy") == {
        "protected_branches": False, "custom_branch_policies": True,
    } and [(p["type"], p["name"]) for p in policies["branch_policies"]] == [("branch", "release/pixel10")],
        f"restrict {expected} to the release/pixel10 branch only")


def github(suffix, name=ENVIRONMENT):
    headers = {"Accept": "application/vnd.github+json"}
    if token := os.environ.get("GH_TOKEN"):
        headers["Authorization"] = "Bearer " + token
    url = f"https://api.github.com/repos/{REPO}/environments/{name}" + suffix
    with urlopen(Request(url, headers=headers), timeout=15) as response:
        return json.load(response)


def main():
    try:
        require(os.environ["GITHUB_REPOSITORY"] == REPO, "unexpected repository")
        env = "pixel10-stable" if os.environ.get("CHANNEL") == "stable" else ENVIRONMENT
        check(os.environ["GITHUB_REF"], os.environ["REF_PROTECTED"] == "true", os.environ["HOSTED_RUNNER"],
              github("", env), github("/deployment-branch-policies", env), env)
    except (KeyError, OSError, ValueError) as error:
        print(f"Signing preflight refused: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
