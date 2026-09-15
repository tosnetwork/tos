"""Check that the frozen manager uses the tested history-resolution queue."""
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

IMMEDIATE_DRAIN = '''auto pending = validator_auth_resolution_queue_.complete();
    if (pending.has_value()) {
      resolve_validator_auth_history(std::move(pending.value()));
    }
    return;'''

FINISH_DRAIN = '''auto pending = validator_auth_resolution_queue_.complete();
  SCOPE_EXIT {
    if (pending.has_value()) {
      resolve_validator_auth_history(std::move(pending.value()));
    }
  };'''


def require_once(text: str, needle: str, label: str) -> None:
    count = text.count(needle)
    if count != 1:
        raise ValueError(f"{label} count for {needle!r} is {count}, expected 1")


def verify(manager_h: str, manager_cpp: str, insertion: str) -> None:
    require_once(
        manager_h,
        "tos::auth::NativeHistoryResolutionQueue validator_auth_resolution_queue_;",
        "manager header queue binding",
    )

    source_required = [
        "auto batch = validator_auth_resolution_queue_.submit(coordinates);",
        "required_finalized_blocks(batch.value(),",
        "fetch_validator_auth_block(std::move(batch.value()),",
        IMMEDIATE_DRAIN,
        FINISH_DRAIN,
    ]
    for needle in source_required:
        require_once(manager_cpp, needle, "manager queue wiring")
        require_once(insertion, needle, "insertion queue wiring")

    if manager_cpp.count("auto pending = validator_auth_resolution_queue_.complete();") != 2:
        raise ValueError("manager must complete the queue in exactly the setup-failure and finish paths")
    if insertion.count("auto pending = validator_auth_resolution_queue_.complete();") != 2:
        raise ValueError("insertion must inventory exactly the two queue completion paths")

    forbidden = "validator_auth_resolving_"
    if forbidden in manager_h or forbidden in manager_cpp or forbidden in insertion:
        raise ValueError(f"obsolete in-flight flag remains: {forbidden}")


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

    # Silence is not evidence: remove each distinct manager-to-queue binding in
    # an in-memory probe and require this checker to reject it.
    probes = (
        (
            manager_h.replace(
                "tos::auth::NativeHistoryResolutionQueue validator_auth_resolution_queue_;", "", 1
            ),
            manager_cpp,
            insertion,
        ),
        (
            manager_h,
            manager_cpp.replace(
                "auto batch = validator_auth_resolution_queue_.submit(coordinates);", "", 1
            ),
            insertion,
        ),
        (manager_h, manager_cpp.replace(IMMEDIATE_DRAIN, "", 1), insertion),
        (manager_h, manager_cpp.replace(FINISH_DRAIN, "", 1), insertion),
        (manager_h, manager_cpp, insertion.replace(FINISH_DRAIN, "", 1)),
    )
    for changed_h, changed_cpp, changed_insertion in probes:
        try:
            verify(changed_h, changed_cpp, changed_insertion)
        except ValueError:
            pass
        else:
            raise RuntimeError("manager queue wiring negative control survived")
    print("PASS: manager history resolution submits and drains the tested queue on both completion paths")


if __name__ == "__main__":
    main()
