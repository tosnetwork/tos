"""Check that the frozen manager uses the tested history-resolution queue and one snapshot."""
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

SNAPSHOT_BUILD = '''const auto state = last_masterchain_state_->root_cell();
  const auto head = tos::auth::anchor_of(last_masterchain_block_id_, state);
  auto snapshot = std::make_shared<const ValidatorAuthResolutionSnapshot>(
      ValidatorAuthResolutionSnapshot{state, head, validator_auth_chain_.value()});'''

SNAPSHOT_ENUMERATION = '''required_finalized_blocks(batch.value(), snapshot->masterchain_state, snapshot->head,
                                                     snapshot->chain, validator_auth_anchors_)'''

SNAPSHOT_RESOLUTION = '''resolve_declared_history(coordinates, snapshot->masterchain_state, snapshot->head,
                                                      snapshot->chain, reader, validator_auth_anchors_)'''


def require_once(text: str, needle: str, label: str) -> None:
    count = text.count(needle)
    if count != 1:
        raise ValueError(f"{label} count for {needle!r} is {count}, expected 1")


def verify(manager_h: str, manager_cpp: str, insertion: str) -> None:
    header_required = [
        "struct ValidatorAuthResolutionSnapshot {",
        "td::Ref<vm::Cell> masterchain_state;",
        "tos::auth::Anchor head;",
        "tos::auth::ChainContext chain;",
        "tos::auth::NativeHistoryResolutionQueue validator_auth_resolution_queue_;",
        "std::shared_ptr<const ValidatorAuthResolutionSnapshot> snapshot",
    ]
    for needle in header_required:
        if needle not in manager_h:
            raise ValueError(f"manager header is missing snapshot/queue binding {needle!r}")

    source_required = [
        "auto batch = validator_auth_resolution_queue_.submit(coordinates);",
        SNAPSHOT_BUILD,
        SNAPSHOT_ENUMERATION,
        "fetch_validator_auth_block(std::move(batch.value()), std::move(snapshot),",
        "snapshot = std::move(snapshot),",
        "&ValidatorManagerImpl::fetch_validator_auth_block, std::move(coordinates), std::move(snapshot),",
        "finish_validator_auth_resolution(std::move(coordinates), std::move(snapshot), std::move(fetched));",
        SNAPSHOT_RESOLUTION,
        IMMEDIATE_DRAIN,
        FINISH_DRAIN,
    ]
    for needle in source_required:
        require_once(manager_cpp, needle, "manager queue/snapshot wiring")
        require_once(insertion, needle, "insertion queue/snapshot wiring")

    if manager_cpp.count("auto pending = validator_auth_resolution_queue_.complete();") != 2:
        raise ValueError("manager must complete the queue in exactly the setup-failure and finish paths")
    if insertion.count("auto pending = validator_auth_resolution_queue_.complete();") != 2:
        raise ValueError("insertion must inventory exactly the two queue completion paths")

    forbidden = "validator_auth_resolving_"
    if forbidden in manager_h or forbidden in manager_cpp or forbidden in insertion:
        raise ValueError(f"obsolete in-flight flag remains: {forbidden}")

    # Enumeration may read the live tip only while constructing the immutable
    # snapshot. Resolution after async IO must use that snapshot, not a moving
    # manager member or the old helper that rereads those members.
    finish_at = manager_cpp.find("void ValidatorManagerImpl::finish_validator_auth_resolution(")
    if finish_at < 0:
        raise ValueError("finish function is absent")
    finish_end = manager_cpp.find("\n}\n", finish_at)
    if finish_end < 0:
        raise ValueError("finish function end is absent")
    finish = manager_cpp[finish_at:finish_end]
    for needle in ("last_masterchain_state_", "validator_auth_head()", "validator_auth_chain_.value()"):
        if needle in finish:
            raise ValueError(f"finish rereads moving resolution input: {needle}")

    if "tos::auth::Anchor ValidatorManagerImpl::validator_auth_head() const" in manager_cpp:
        raise ValueError("obsolete moving-head helper remains after snapshot wiring")


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

    # Silence is not evidence: remove queue and snapshot bindings in memory and
    # require each independent probe to be rejected.
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
        (manager_h, manager_cpp.replace(SNAPSHOT_BUILD, "", 1), insertion),
        (manager_h, manager_cpp.replace(SNAPSHOT_RESOLUTION, "", 1), insertion),
        (manager_h, manager_cpp, insertion.replace(SNAPSHOT_ENUMERATION, "", 1)),
    )
    for changed_h, changed_cpp, changed_insertion in probes:
        try:
            verify(changed_h, changed_cpp, changed_insertion)
        except ValueError:
            pass
        else:
            raise RuntimeError("manager queue/snapshot wiring negative control survived")
    print("PASS: manager queues history requests and authenticates each async resolution against one captured tip")


if __name__ == "__main__":
    main()
