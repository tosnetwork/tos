#!/usr/bin/env python3
"""Temporary branch-local source migration entry point."""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys

root = Path(__file__).resolve().parents[1]
env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")

def run(*args: str) -> None:
    subprocess.run(args, cwd=root, env=env, check=True)

run(sys.executable, "scripts/test-token-naming.py")
run(sys.executable, "scripts/migrate-token-naming.py", "--apply", "--manifest", "/tmp/token-source-migration.json")
run(sys.executable, "scripts/migrate-token-naming.py", "--check")
manifest = json.loads(Path("/tmp/token-source-migration.json").read_text())
print("MIGRATION_SUMMARY", json.dumps({"source_commit": manifest["source_commit"], "changed_files": len(manifest["files"]), "renamed_paths": sum(item["old_path"] != item["new_path"] for item in manifest["files"])}), flush=True)
run("git", "diff", "--cached", "--stat")
if subprocess.run(["git", "diff", "--cached", "--quiet"], cwd=root).returncode == 1:
    run("git", "-c", "user.name=github-actions[bot]", "-c", "user.email=41898282+github-actions[bot]@users.noreply.github.com", "commit", "-m", "refactor!: replace legacy fungible-token naming with Token")
print("MATERIALIZED_COMMIT", subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip(), flush=True)
