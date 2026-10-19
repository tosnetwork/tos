#!/usr/bin/env python3
"""Temporary branch-local inventory for the token naming migration."""
import collections
import json
import pathlib
import re
import subprocess

root = pathlib.Path(__file__).resolve().parents[1]
files = subprocess.check_output(["git", "ls-files", "-z"], cwd=root).decode().split("\0")
pattern = re.compile(r"jetton", re.IGNORECASE)
matched = []
for name in files:
    if not name:
        continue
    path = root / name
    if path.is_symlink() or not path.is_file():
        continue
    if path.name == "AGENTS.md" and name != "AGENTS.md":
        print("NESTED_INSTRUCTIONS", name, path.read_text())
    try:
        text = path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        if pattern.search(name):
            print("BINARY", name, path.stat().st_size)
        continue
    hits = len(pattern.findall(text))
    if hits or pattern.search(name):
        matched.append((name, hits, path.stat().st_size))
print("INVENTORY", json.dumps(matched))
print("SUMMARY", json.dumps(dict(collections.Counter(p.split('/')[0] for p, _, _ in matched))))
for name in files:
    if not name:
        continue
    path = root / name
    if not path.is_file() or path.is_symlink():
        continue
    if name.startswith(("scripts/", "sdk/js/", "crypto/CMakeLists", "tol/CMakeLists", "CMakeLists")):
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except UnicodeDecodeError:
            continue
        for number, line in enumerate(lines, 1):
            if (re.search(r"jetton.*(?:boc|CODE_HEX|code_hash)|(?:boc|CODE_HEX|code_hash).*jetton", line, re.I)
                or (name.startswith("scripts/") and re.search(r"(?:/tol|/fift|update.*code)", line))):
                print("BUILD_REFERENCE", name, number, line[:400])
