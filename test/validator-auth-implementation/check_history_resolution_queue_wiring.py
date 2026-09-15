"""Check that the frozen manager uses the tested history-resolution queue."""
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def verify(manager_h: str, manager_cpp: str, insertion: str) -> None:
    header_required = [
        "tos::auth::NativeHistoryResolutionQueue validator_auth_resolution_queue_;",
    ]
    source_required = [
        "auto batch = validator_auth_resolution_queue_.submit(coordinates);",
        "required_finalized_blocks(batch.value(),",
        "fetch_validator_auth_block(std::move(batch.value()),",
        "auto pending = validator_auth_resolution_queue_.complete();",
        "SCOPE_EXIT {",
        "resolve_validator_auth_history(std::move(pending.value()));",
    ]
    forbidden = ["validator_auth_resolving_"]

    for needle in header_required:
        if manager_h.count(needle) != 1:
            raise ValueError(f"manager header queue binding count for {needle!r} is {manager_h.count(needle)}")
    for needle in source_required:
        if manager_cpp.count(needle) != 1:
            raise ValueError(f"manager queue wiring count for {needle!r} is {manager_cpp.count(needle)}")
        if insertion.count(needle) != 1:
            raise ValueError(f"insertion queue wiring count for {needle!r} is {insertion.count(needle)}")
    for needle in forbidden:
        if needle in manager_h or needle in manager_cpp or needle in insertion:
            raise ValueError(f"obsolete in-flight flag remains: {needle}")


def main() -> None:
    manager_h = (ROOT / "validator/manager.hpp").read_text()
    manager_cpp = (ROOT / "validator/manager.cpp").read_text()
    manifest = json.loads((ROOT / "doc/validator-auth-p0-native-insertions.json").read_text())
    entries = manifest["insertions"]["validator/manager.cpp"]
    matches = [entry["text"] for entry in entries if "resolve_validator_auth_history" in entry["text"]]
    if len(matches) != 1:
        raise ValueError(f"manager history insertion count is {len(matches)}")
    insertion = matches[0]
    verify(manager_h, manager_cpp, insertion)

    # Silence is not evidence: removing either side of the manager-to-queue
    # binding from an in-memory probe must make this checker reject it.
    for changed_h, changed_cpp, changed_insertion in (
        (manager_h.replace("tos::auth::NativeHistoryResolutionQueue validator_auth_resolution_queue_;", "", 1),
         manager_cpp, insertion),
        (manager_h, manager_cpp.replace("auto batch = validator_auth_resolution_queue_.submit(coordinates);", "", 1),
         insertion),
        (manager_h, manager_cpp,
         insertion.replace("auto pending = validator_auth_resolution_queue_.complete();", "", 1)),
    ):
        try:
            verify(changed_h, changed_cpp, changed_insertion)
        except ValueError:
            pass
        else:
            raise RuntimeError("manager queue wiring negative control survived")
    print("PASS: manager history resolution submits, drains and inventories the tested queue")


if __name__ == "__main__":
    main()
