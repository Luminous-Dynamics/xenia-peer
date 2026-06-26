#!/usr/bin/env python3
"""Generate deterministic source-archive checksum evidence for Xenia RC1."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
from typing import Any


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def run(command: list[str], cwd: Path) -> dict[str, Any]:
    proc = subprocess.run(command, cwd=cwd, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    return {
        "command": [sanitize_arg(arg) for arg in command],
        "exit_code": proc.returncode,
        "output": sanitize_output(proc.stdout),
        "status": "pass" if proc.returncode == 0 else "fail",
    }


def sanitize_arg(arg: str) -> str:
    # Keep evidence stable and free of local absolute paths.
    if arg.startswith("/tmp/") or arg.startswith("/var/tmp/"):
        return "<temp-artifact>"
    return arg


def sanitize_output(output: str) -> str:
    sanitized_lines: list[str] = []
    for line in output.splitlines():
        workspace_prefix = "/srv" + "/luminous-dynamics"
        artifact_prefix = "/mnt" + "/data"
        line = line.replace(workspace_prefix, "<workspace-root>")
        line = line.replace(artifact_prefix, "<artifact-workspace>")
        if "/tmp/" in line:
            # The exact temp path is not release evidence.
            parts = line.split()
            line = " ".join("<temp-artifact>" if part.startswith("/tmp/") else part for part in parts)
        sanitized_lines.append(line)
    return "\n".join(sanitized_lines).strip()


def archive_members(archive: Path) -> list[dict[str, Any]]:
    members: list[dict[str, Any]] = []
    with tarfile.open(archive, "r:gz") as tar:
        for member in tar.getmembers():
            item: dict[str, Any] = {
                "path": member.name,
                "type": "dir" if member.isdir() else "file" if member.isfile() else "other",
                "mode": oct(member.mode),
                "size": member.size,
                "mtime": member.mtime,
                "uid": member.uid,
                "gid": member.gid,
                "uname": member.uname,
                "gname": member.gname,
            }
            if member.isfile():
                extracted = tar.extractfile(member)
                if extracted is None:
                    raise RuntimeError(f"could not read tar member: {member.name}")
                h = hashlib.sha256()
                for chunk in iter(lambda: extracted.read(1024 * 1024), b""):
                    h.update(chunk)
                item["sha256"] = h.hexdigest()
            members.append(item)
    return sorted(members, key=lambda item: item["path"])


def render_markdown(manifest: dict[str, Any]) -> str:
    checks = manifest["checks"]
    lines = [
        "# RC1 Source Archive Checksum Evidence",
        "",
        "Status: generated for RC1 soft-blocker review.",
        "",
        "This evidence verifies that Xenia source archive generation is deterministic,",
        "source-only, and paired with a checksum manifest. It does not promote Xenia",
        "to RC1 and does not close unrelated soft blockers.",
        "",
        "## Archive identity",
        "",
        f"- Archive name: `{manifest['archive']['name']}`",
        f"- Archive SHA-256: `{manifest['archive']['sha256']}`",
        f"- Inventory SHA-256: `{manifest['inventory_sha256']}`",
        f"- Entries: `{manifest['archive']['entry_count']}`",
        f"- Files: `{manifest['archive']['file_count']}`",
        f"- Reproducible rebuild: `{manifest['reproducibility']['rebuild_sha256_match']}`",
        "",
        "## Checks",
        "",
    ]
    for check in checks:
        lines.append(f"- `{check['name']}`: `{check['status']}` / exit `{check['exit_code']}`")
    lines.extend([
        "",
        "## Non-goals",
        "",
        "- Does not commit generated tarballs.",
        "- Does not remove runtime-risk, fault-injection, observability, or dashboard soft blockers.",
        "- Does not change `release_train.status`.",
        "",
    ])
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", nargs="?", default=".")
    parser.add_argument("--manifest", default="docs/release/evidence/rc1-source-archive-checksums.json")
    parser.add_argument("--markdown", default="docs/release/evidence/RC1_SOURCE_ARCHIVE_CHECKSUMS.md")
    parser.add_argument("--archive-name", default="xenia-peer-source.tar.gz")
    args = parser.parse_args()

    root = Path(args.root).resolve()
    export_script = root / "scripts" / "export-source-archive.sh"
    check_script = root / "scripts" / "check-source-archive.sh"
    if not export_script.is_file():
        print(f"error: missing {export_script.relative_to(root)}", file=sys.stderr)
        return 2
    if not check_script.is_file():
        print(f"error: missing {check_script.relative_to(root)}", file=sys.stderr)
        return 2

    with tempfile.TemporaryDirectory(prefix="xenia-source-archive-") as td:
        tmp = Path(td)
        archive = tmp / args.archive_name
        archive_rebuild = tmp / f"rebuild-{args.archive_name}"

        export_one = run(["bash", "scripts/export-source-archive.sh", ".", str(archive)], cwd=root)
        export_two = run(["bash", "scripts/export-source-archive.sh", ".", str(archive_rebuild)], cwd=root)
        check_one = run(["bash", "scripts/check-source-archive.sh", str(archive)], cwd=root)

        if export_one["exit_code"] != 0 or export_two["exit_code"] != 0 or check_one["exit_code"] != 0:
            for result in (export_one, export_two, check_one):
                print(result["output"], file=sys.stderr)
            return 1

        archive_sha = sha256_file(archive)
        rebuild_sha = sha256_file(archive_rebuild)
        members = archive_members(archive)
        files = [member for member in members if member["type"] == "file"]
        inventory_text = "\n".join(
            f"{member['sha256']}  {member['path']}" for member in files
        ) + "\n"

        manifest: dict[str, Any] = {
            "schema_version": 1,
            "root": "<repo-root>",
            "generated_by": "scripts/generate-source-archive-checksums.py",
            "archive": {
                "name": args.archive_name,
                "sha256": archive_sha,
                "size_bytes": archive.stat().st_size,
                "entry_count": len(members),
                "file_count": len(files),
                "top_level": "xenia-peer/",
            },
            "reproducibility": {
                "deterministic_tar": True,
                "gzip_timestamp_suppressed": True,
                "first_sha256": archive_sha,
                "second_sha256": rebuild_sha,
                "rebuild_sha256_match": archive_sha == rebuild_sha,
            },
            "policy": {
                "committed_archive": False,
                "source_only": True,
                "excludes_build_output": True,
                "excludes_nested_vcs": True,
                "excludes_runtime_state_and_secrets": True,
                "excludes_generated_checksum_evidence": True,
            },
            "inventory_sha256": sha256_text(inventory_text),
            "files": files,
            "checks": [
                {"name": "export-source-archive", **export_one},
                {"name": "export-source-archive-rebuild", **export_two},
                {"name": "check-source-archive", **check_one},
            ],
        }
        if archive_sha != rebuild_sha:
            print("error: archive rebuild SHA-256 mismatch", file=sys.stderr)
            return 1

    manifest_path = root / args.manifest
    markdown_path = root / args.markdown
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    markdown_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    markdown_path.write_text(render_markdown(manifest), encoding="utf-8")
    print(f"wrote manifest: {manifest_path.relative_to(root)}")
    print(f"wrote markdown: {markdown_path.relative_to(root)}")
    print(f"archive_sha256: {archive_sha}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
