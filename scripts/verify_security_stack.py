#!/usr/bin/env python3
"""Verify reviewed Git ancestry and deltas for security-sensitive stacked PRs.

A configured PR base branch is not sufficient evidence after a force-rewrite:
GitHub updates the base ref but does not rewrite descendant commit parents.
The reviewed manifest therefore binds each PR head, its actual Git parent, its
configured base SHA, both ref/repository identities, and its exact changed-file
set.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

API = "https://api.github.com"
SCHEMA_VERSION = 2
PROFILE = "xenia-security-stack-integrity-v2"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


class GitHub:
    def __init__(self, token: str | None) -> None:
        self.token = token

    @staticmethod
    def _request(path: str, token: str | None) -> Any:
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "xenia-security-stack-integrity-v2",
        }
        if token:
            headers["Authorization"] = f"Bearer {token}"
        request = urllib.request.Request(f"{API}{path}", headers=headers)
        with urllib.request.urlopen(request, timeout=30) as response:
            return json.load(response)

    def get(self, path: str) -> Any:
        try:
            return self._request(path, self.token)
        except urllib.error.HTTPError as exc:
            # A workflow GITHUB_TOKEN is repository-scoped. The guarded wire
            # repository is public, so retry unauthenticated if a cross-repo
            # token is refused rather than widening token permissions.
            if self.token and exc.code in (403, 404):
                try:
                    return self._request(path, None)
                except urllib.error.HTTPError as retry_exc:
                    detail = retry_exc.read().decode("utf-8", errors="replace")
                    raise RuntimeError(
                        f"GitHub API {retry_exc.code} for {path}: {detail}"
                    ) from retry_exc
            detail = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"GitHub API {exc.code} for {path}: {detail}") from exc


def check(condition: bool, message: str, failures: list[str]) -> None:
    if not condition:
        failures.append(message)


def validate_manifest(manifest: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    if manifest.get("schema_version") != SCHEMA_VERSION:
        failures.append(
            f"unsupported security-stack manifest schema: "
            f"{manifest.get('schema_version')!r} != {SCHEMA_VERSION}"
        )
        return failures

    stacks = manifest.get("stacks")
    if not isinstance(stacks, list) or not stacks:
        failures.append("manifest must contain at least one stack")
        return failures

    seen_nodes: set[tuple[str, int]] = set()
    required = {
        "pr",
        "mode",
        "head",
        "head_ref",
        "head_repo",
        "parent",
        "configured_base",
        "base_ref",
        "base_repo",
        "files",
    }

    for stack_index, stack in enumerate(stacks):
        if not isinstance(stack, dict):
            failures.append(f"stack[{stack_index}] must be an object")
            continue
        repo = stack.get("repository")
        nodes = stack.get("nodes")
        if not isinstance(repo, str) or "/" not in repo:
            failures.append(f"stack[{stack_index}] has invalid repository {repo!r}")
            continue
        if not isinstance(nodes, list) or not nodes:
            failures.append(f"{repo}: stack must contain at least one node")
            continue

        for node_index, node in enumerate(nodes):
            prefix = f"{repo}:node[{node_index}]"
            if not isinstance(node, dict):
                failures.append(f"{prefix}: node must be an object")
                continue
            missing = sorted(required - node.keys())
            if missing:
                failures.append(f"{prefix}: missing required keys {missing}")
                continue
            try:
                pr_number = int(node["pr"])
            except (TypeError, ValueError):
                failures.append(f"{prefix}: invalid PR number {node.get('pr')!r}")
                continue
            identity = (repo, pr_number)
            if identity in seen_nodes:
                failures.append(f"{repo}#{pr_number}: duplicate manifest node")
            seen_nodes.add(identity)

            files = node.get("files")
            if not isinstance(files, list) or not files or not all(
                isinstance(path, str) and path for path in files
            ):
                failures.append(f"{repo}#{pr_number}: files must be non-empty strings")
            elif len(files) != len(set(files)):
                failures.append(f"{repo}#{pr_number}: duplicate file entries")

            if node.get("head_repo") != repo or node.get("base_repo") != repo:
                failures.append(
                    f"{repo}#{pr_number}: v2 guard currently requires same-repository "
                    "head/base identities"
                )

    return failures


def inspect_node(gh: GitHub, repo: str, node: dict[str, Any]) -> dict[str, Any]:
    pr_number = int(node["pr"])
    expected_head = node["head"]
    expected_head_ref = node["head_ref"]
    expected_head_repo = node["head_repo"]
    expected_parent = node["parent"]
    expected_base = node["configured_base"]
    expected_base_ref = node["base_ref"]
    expected_base_repo = node["base_repo"]
    expected_files = sorted(node["files"])
    mode = node["mode"]

    pr = gh.get(f"/repos/{repo}/pulls/{pr_number}")
    commit = gh.get(f"/repos/{repo}/git/commits/{expected_head}")
    comparison = gh.get(f"/repos/{repo}/compare/{expected_parent}...{expected_head}")

    parents = [parent["sha"] for parent in commit.get("parents", [])]
    observed_parent = parents[0] if len(parents) == 1 else None
    observed_files = sorted(item["filename"] for item in comparison.get("files", []))

    head = pr.get("head") or {}
    base = pr.get("base") or {}
    head_repo = (head.get("repo") or {}).get("full_name")
    base_repo = (base.get("repo") or {}).get("full_name")

    failures: list[str] = []
    prefix = f"{repo}#{pr_number}"

    check(pr.get("state") == "open", f"{prefix}: expected open PR", failures)
    if node.get("require_draft", True):
        check(pr.get("draft") is True, f"{prefix}: expected draft PR", failures)

    check(
        head.get("sha") == expected_head,
        f"{prefix}: head moved: {head.get('sha')} != {expected_head}",
        failures,
    )
    check(
        head.get("ref") == expected_head_ref,
        f"{prefix}: head ref moved: {head.get('ref')!r} != {expected_head_ref!r}",
        failures,
    )
    check(
        head_repo == expected_head_repo,
        f"{prefix}: head repo moved: {head_repo!r} != {expected_head_repo!r}",
        failures,
    )
    check(
        base.get("sha") == expected_base,
        f"{prefix}: configured base moved: {base.get('sha')} != {expected_base}",
        failures,
    )
    check(
        base.get("ref") == expected_base_ref,
        f"{prefix}: base ref moved: {base.get('ref')!r} != {expected_base_ref!r}",
        failures,
    )
    check(
        base_repo == expected_base_repo,
        f"{prefix}: base repo moved: {base_repo!r} != {expected_base_repo!r}",
        failures,
    )

    check(len(parents) == 1, f"{prefix}: expected exactly one Git parent: {parents}", failures)
    check(
        observed_parent == expected_parent,
        f"{prefix}: Git parent mismatch: {observed_parent} != {expected_parent}",
        failures,
    )
    check(
        comparison.get("status") == "ahead",
        f"{prefix}: parent..head status {comparison.get('status')!r} != 'ahead'",
        failures,
    )
    check(
        comparison.get("ahead_by") == 1,
        f"{prefix}: ahead_by={comparison.get('ahead_by')} != 1",
        failures,
    )
    check(
        comparison.get("behind_by") == 0,
        f"{prefix}: behind_by={comparison.get('behind_by')} != 0",
        failures,
    )
    check(
        observed_files == expected_files,
        f"{prefix}: changed files {observed_files} != {expected_files}",
        failures,
    )

    if mode == "clean":
        check(
            expected_parent == expected_base,
            f"{prefix}: clean manifest node must bind parent == configured base",
            failures,
        )
    elif mode == "blocked-divergent":
        check(
            expected_parent != expected_base,
            f"{prefix}: blocked-divergent manifest node must bind parent != configured base",
            failures,
        )
        check(pr.get("merged_at") is None, f"{prefix}: blocked PR must not be merged", failures)
    else:
        failures.append(f"{prefix}: unknown mode {mode!r}")

    return {
        "repo": repo,
        "pr": pr_number,
        "mode": mode,
        "expected": {
            "head": expected_head,
            "head_ref": expected_head_ref,
            "head_repo": expected_head_repo,
            "parent": expected_parent,
            "configured_base": expected_base,
            "base_ref": expected_base_ref,
            "base_repo": expected_base_repo,
            "files": expected_files,
        },
        "observed": {
            "head": head.get("sha"),
            "head_ref": head.get("ref"),
            "head_repo": head_repo,
            "configured_base": base.get("sha"),
            "base_ref": base.get("ref"),
            "base_repo": base_repo,
            "parent": observed_parent,
            "parents": parents,
            "draft": pr.get("draft"),
            "state": pr.get("state"),
            "mergeable": pr.get("mergeable"),
            "compare_status": comparison.get("status"),
            "ahead_by": comparison.get("ahead_by"),
            "behind_by": comparison.get("behind_by"),
            "files": observed_files,
        },
        "failures": failures,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", default=".github/security-stack-integrity.json")
    parser.add_argument("--report", default="security-stack-integrity-report.json")
    args = parser.parse_args()

    manifest_path = Path(args.manifest)
    report_path = Path(args.report)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

    failures = validate_manifest(manifest)
    observations: list[dict[str, Any]] = []

    if not failures:
        gh = GitHub(os.environ.get("GITHUB_TOKEN"))
        for stack in manifest["stacks"]:
            repo = stack["repository"]
            for node in stack["nodes"]:
                try:
                    observation = inspect_node(gh, repo, node)
                except Exception as exc:
                    observation = {
                        "repo": repo,
                        "pr": node.get("pr"),
                        "mode": node.get("mode"),
                        "failures": [f"{repo}#{node.get('pr')}: inspection error: {exc}"],
                    }
                observations.append(observation)
                failures.extend(observation["failures"])

    report = {
        "schema_version": SCHEMA_VERSION,
        "profile": PROFILE,
        "observed_at_utc": datetime.now(timezone.utc).isoformat(),
        "manifest_sha256": sha256_file(manifest_path),
        "script_sha256": sha256_file(Path(__file__)),
        "ok": not failures,
        "failures": failures,
        "observations": observations,
    }
    report_path.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    if failures:
        print("SECURITY STACK INTEGRITY: FAIL")
        for failure in failures:
            print(f"- {failure}")
        return 1

    print("SECURITY STACK INTEGRITY: PASS")
    for observation in observations:
        print(
            f"- {observation['repo']}#{observation['pr']}: "
            f"{observation['mode']} "
            f"{observation['observed']['parent'][:12]} -> "
            f"{observation['observed']['head'][:12]} "
            f"({len(observation['observed']['files'])} files)"
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
