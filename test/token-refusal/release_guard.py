"""Keep the local receiver fixture outside every shipped/released input."""

import re
from pathlib import Path


def forbidden(data, reject_owner, code_hash):
    text = data.decode("utf-8", errors="ignore").lower()
    markers = ("local-only-test", "token-refusal", reject_owner, code_hash)
    paired = "globalid" in text and re.search(
        r"(?:throw(?:_if|_unless)?\s*\(\s*1980|\b1980\s+throw)", text
    )
    return (
        any(marker in text for marker in markers) or paired or bytes.fromhex(reject_owner) in data
    )


def cmake_release_text(text):
    # These two exact registrations execute this source guard; neither installs
    # an input. Do not exempt arbitrary test commands or variable definitions.
    text = re.sub(
        r"add_test\(NAME\s+local-token-refusal-fixture\s+COMMAND\s+\$\{Python3_EXECUTABLE\}\s+\$\{CMAKE_CURRENT_SOURCE_DIR\}/test/token-refusal/test_local_only\.py\)",
        "",
        text,
    )
    return re.sub(
        r'set_tests_properties\(local-token-refusal-fixture\s+PROPERTIES\s+LABELS\s+"source-guard"\)',
        "",
        text,
    )


def release_leaks(root, reject_owner, code_hash):
    root = Path(root)
    paths = set()
    workflows = root / ".github/workflows"
    if workflows.exists():
        # Include all workflows, so a custom artifact publisher or reusable
        # release cannot evade classification by choosing another action name.
        paths.update(
            p for p in workflows.iterdir() if p.is_file() and p.suffix in (".yml", ".yaml")
        )
    shipped = root / "crypto/smartcont"
    if shipped.exists():
        paths.update(p for p in shipped.rglob("*") if p.is_file())
    manifest = root / "scripts/release-artifacts.json"
    if manifest.exists():
        paths.add(manifest)
    for path in root.rglob("CMakeLists.txt"):
        if path.is_file() and re.search(
            r"\binstall\s*\(", path.read_text(errors="replace"), re.IGNORECASE
        ):
            paths.add(path)
    leaks = []
    for path in sorted(paths):
        data = path.read_bytes()
        if path.name == "CMakeLists.txt":
            data = cmake_release_text(data.decode("utf-8", errors="replace")).encode()
        relative = str(path.relative_to(root))
        if forbidden(relative.encode() + b"\n" + data, reject_owner, code_hash):
            leaks.append(relative)
    return leaks
