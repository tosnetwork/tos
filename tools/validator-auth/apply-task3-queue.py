"""Apply the exact Task 3 queue wiring to the frozen manager and its inventory."""
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

MANAGER_H = ROOT / "validator/manager.hpp"
MANAGER_CPP = ROOT / "validator/manager.cpp"
MANIFEST = ROOT / "doc/validator-auth-p0-native-insertions.json"

OLD_MEMBER = "  bool validator_auth_resolving_ = false;"
NEW_MEMBER = "  tos::auth::NativeHistoryResolutionQueue validator_auth_resolution_queue_;"

OLD_RESOLVE = '''void ValidatorManagerImpl::resolve_validator_auth_history(std::vector<td::uint32> coordinates) {
  // One resolution in flight at a time. A request that arrives while another is
  // running is dropped rather than queued: the update that prompted it is still
  // in the message queue and the next block defers on it again, so the request
  // returns on its own.
  if (!validator_auth_chain_ || coordinates.empty() || validator_auth_resolving_ ||
      last_masterchain_state_.is_null() || !last_masterchain_block_id_.is_valid()) {
    return;
  }
  auto wanted = tos::auth::required_finalized_blocks(coordinates, last_masterchain_state_->root_cell(),
                                                     validator_auth_head(), validator_auth_chain_.value(),
                                                     validator_auth_anchors_);
  if (!wanted.ok()) {
    LOG(INFO) << "cannot resolve the history a registry update declared: " << wanted.error().code;
    return;
  }
  validator_auth_resolving_ = true;
  auto fetched = std::make_shared<std::map<BlockSeqno, tos::auth::Bytes>>();
  fetch_validator_auth_block(std::move(coordinates), std::move(wanted.value()), 0, std::move(fetched));
}'''

NEW_RESOLVE = '''void ValidatorManagerImpl::resolve_validator_auth_history(std::vector<td::uint32> coordinates) {
  if (!validator_auth_chain_ || coordinates.empty() || last_masterchain_state_.is_null() ||
      !last_masterchain_block_id_.is_valid()) {
    return;
  }
  auto batch = validator_auth_resolution_queue_.submit(coordinates);
  if (!batch.has_value()) {
    return;
  }
  auto wanted = tos::auth::required_finalized_blocks(batch.value(), last_masterchain_state_->root_cell(),
                                                     validator_auth_head(), validator_auth_chain_.value(),
                                                     validator_auth_anchors_);
  if (!wanted.ok()) {
    LOG(INFO) << "cannot resolve the history a registry update declared: " << wanted.error().code;
    auto pending = validator_auth_resolution_queue_.complete();
    if (pending.has_value()) {
      resolve_validator_auth_history(std::move(pending.value()));
    }
    return;
  }
  auto fetched = std::make_shared<std::map<BlockSeqno, tos::auth::Bytes>>();
  fetch_validator_auth_block(std::move(batch.value()), std::move(wanted.value()), 0, std::move(fetched));
}'''

OLD_FINISH = '''void ValidatorManagerImpl::finish_validator_auth_resolution(
    std::vector<td::uint32> coordinates, std::shared_ptr<std::map<BlockSeqno, tos::auth::Bytes>> fetched) {
  validator_auth_resolving_ = false;
  if (!validator_auth_chain_ || last_masterchain_state_.is_null()) {
    return;
  }'''

NEW_FINISH = '''void ValidatorManagerImpl::finish_validator_auth_resolution(
    std::vector<td::uint32> coordinates, std::shared_ptr<std::map<BlockSeqno, tos::auth::Bytes>> fetched) {
  auto pending = validator_auth_resolution_queue_.complete();
  SCOPE_EXIT {
    if (pending.has_value()) {
      resolve_validator_auth_history(std::move(pending.value()));
    }
  };
  if (!validator_auth_chain_ || last_masterchain_state_.is_null()) {
    return;
  }'''


def replace_once(path: Path, old: str, new: str) -> None:
    text = path.read_text()
    count = text.count(old)
    if count != 1:
        raise RuntimeError(f"{path}: anchor count {count}, expected 1")
    path.write_text(text.replace(old, new, 1))


def main() -> None:
    replace_once(MANAGER_H, OLD_MEMBER, NEW_MEMBER)
    replace_once(MANAGER_CPP, OLD_RESOLVE, NEW_RESOLVE)
    replace_once(MANAGER_CPP, OLD_FINISH, NEW_FINISH)

    raw = MANIFEST.read_text()
    for old, new in ((OLD_RESOLVE, NEW_RESOLVE), (OLD_FINISH, NEW_FINISH)):
        escaped_old = json.dumps(old)[1:-1]
        escaped_new = json.dumps(new)[1:-1]
        count = raw.count(escaped_old)
        if count != 1:
            raise RuntimeError(f"manifest escaped anchor count {count}, expected 1")
        raw = raw.replace(escaped_old, escaped_new, 1)
    MANIFEST.write_text(raw)
    print("TASK3_EDIT_OK")


if __name__ == "__main__":
    main()
