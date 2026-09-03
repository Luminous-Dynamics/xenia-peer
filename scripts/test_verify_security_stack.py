#!/usr/bin/env python3
"""Offline adversarial regressions for verify_security_stack.py."""

from __future__ import annotations

import copy
import unittest

from verify_security_stack import inspect_node, validate_manifest

REPO = "Luminous-Dynamics/xenia-wire"
HEAD = "1" * 40
PARENT = "2" * 40
OTHER_BASE = "3" * 40


class FakeGitHub:
    def __init__(self, responses: dict[str, object]) -> None:
        self.responses = responses

    def get(self, path: str) -> object:
        if path not in self.responses:
            raise AssertionError(f"unexpected API request: {path}")
        return copy.deepcopy(self.responses[path])


def clean_node() -> dict[str, object]:
    return {
        "pr": 37,
        "mode": "clean",
        "require_draft": True,
        "head": HEAD,
        "head_ref": "feature",
        "head_repo": REPO,
        "parent": PARENT,
        "configured_base": PARENT,
        "base_ref": "main",
        "base_repo": REPO,
        "files": ["src/session.rs"],
    }


def responses_for(node: dict[str, object]) -> dict[str, object]:
    pr = int(node["pr"])
    parent = str(node["parent"])
    head = str(node["head"])
    return {
        f"/repos/{REPO}/pulls/{pr}": {
            "state": "open",
            "draft": True,
            "merged_at": None,
            "mergeable": True,
            "head": {
                "sha": head,
                "ref": node["head_ref"],
                "repo": {"full_name": node["head_repo"]},
            },
            "base": {
                "sha": node["configured_base"],
                "ref": node["base_ref"],
                "repo": {"full_name": node["base_repo"]},
            },
        },
        f"/repos/{REPO}/git/commits/{head}": {
            "parents": [{"sha": parent}],
        },
        f"/repos/{REPO}/compare/{parent}...{head}": {
            "status": "ahead",
            "ahead_by": 1,
            "behind_by": 0,
            "files": [{"filename": path} for path in node["files"]],
        },
    }


def inspect(node: dict[str, object], mutate=None) -> list[str]:
    responses = responses_for(node)
    if mutate is not None:
        mutate(responses)
    return inspect_node(FakeGitHub(responses), REPO, node)["failures"]


class InspectNodeTests(unittest.TestCase):
    def test_clean_exact_identity_passes(self) -> None:
        self.assertEqual(inspect(clean_node()), [])

    def test_same_sha_base_ref_retarget_fails(self) -> None:
        node = clean_node()

        def mutate(responses: dict[str, object]) -> None:
            responses[f"/repos/{REPO}/pulls/37"]["base"]["ref"] = "different-ref"

        failures = inspect(node, mutate)
        self.assertTrue(any("base ref moved" in failure for failure in failures))

    def test_same_sha_head_ref_retarget_fails(self) -> None:
        node = clean_node()

        def mutate(responses: dict[str, object]) -> None:
            responses[f"/repos/{REPO}/pulls/37"]["head"]["ref"] = "different-head"

        failures = inspect(node, mutate)
        self.assertTrue(any("head ref moved" in failure for failure in failures))

    def test_head_repository_drift_fails(self) -> None:
        node = clean_node()

        def mutate(responses: dict[str, object]) -> None:
            responses[f"/repos/{REPO}/pulls/37"]["head"]["repo"]["full_name"] = "fork/xenia-wire"

        failures = inspect(node, mutate)
        self.assertTrue(any("head repo moved" in failure for failure in failures))

    def test_actual_parent_drift_fails(self) -> None:
        node = clean_node()

        def mutate(responses: dict[str, object]) -> None:
            responses[f"/repos/{REPO}/git/commits/{HEAD}"]["parents"] = [{"sha": OTHER_BASE}]

        failures = inspect(node, mutate)
        self.assertTrue(any("Git parent mismatch" in failure for failure in failures))

    def test_changed_file_widening_fails(self) -> None:
        node = clean_node()

        def mutate(responses: dict[str, object]) -> None:
            compare = responses[f"/repos/{REPO}/compare/{PARENT}...{HEAD}"]
            compare["files"].append({"filename": "src/unreviewed.rs"})

        failures = inspect(node, mutate)
        self.assertTrue(any("changed files" in failure for failure in failures))

    def test_blocked_divergent_shape_is_explicitly_accepted(self) -> None:
        node = clean_node()
        node.update(
            {
                "pr": 44,
                "mode": "blocked-divergent",
                "parent": PARENT,
                "configured_base": OTHER_BASE,
                "base_ref": "new-parent-branch",
            }
        )
        responses = responses_for(node)
        responses[f"/repos/{REPO}/pulls/44"]["mergeable"] = False
        observation = inspect_node(FakeGitHub(responses), REPO, node)
        self.assertEqual(observation["failures"], [])

    def test_blocked_mode_cannot_hide_matching_parent_and_base(self) -> None:
        node = clean_node()
        node["mode"] = "blocked-divergent"
        failures = inspect(node)
        self.assertTrue(any("parent != configured base" in failure for failure in failures))


class ManifestValidationTests(unittest.TestCase):
    def manifest(self, nodes: list[dict[str, object]]) -> dict[str, object]:
        return {
            "schema_version": 2,
            "tracker": "Luminous-Dynamics/xenia-peer#214",
            "stacks": [
                {
                    "name": "test",
                    "repository": REPO,
                    "nodes": nodes,
                }
            ],
        }

    def test_duplicate_pr_node_fails(self) -> None:
        node = clean_node()
        failures = validate_manifest(self.manifest([node, copy.deepcopy(node)]))
        self.assertTrue(any("duplicate manifest node" in failure for failure in failures))

    def test_duplicate_file_entry_fails(self) -> None:
        node = clean_node()
        node["files"] = ["src/session.rs", "src/session.rs"]
        failures = validate_manifest(self.manifest([node]))
        self.assertTrue(any("duplicate file entries" in failure for failure in failures))

    def test_cross_repo_identity_fails_closed_in_v2(self) -> None:
        node = clean_node()
        node["head_repo"] = "fork/xenia-wire"
        failures = validate_manifest(self.manifest([node]))
        self.assertTrue(any("same-repository" in failure for failure in failures))


if __name__ == "__main__":
    unittest.main(verbosity=2)
