"""Apply the verified history-resolution queue and snapshot wiring exactly once."""
from __future__ import annotations

import json
from pathlib import Path

MANAGER_H = Path("validator/manager.hpp")
MANAGER_CPP = Path("validator/manager.cpp")
MANIFEST = Path("doc/validator-auth-p0-native-insertions.json")

OLD_DECLARATIONS = '''  tos::auth::Anchor validator_auth_head() const;
  void resolve_validator_auth_history(std::vector<td::uint32> coordinates);
  void fetch_validator_auth_block(std::vector<td::uint32> coordinates, std::vector<BlockIdExt> wanted, size_t index,
                                  std::shared_ptr<std::map<BlockSeqno, tos::auth::Bytes>> fetched);
  void finish_validator_auth_resolution(std::vector<td::uint32> coordinates,
                                        std::shared_ptr<std::map<BlockSeqno, tos::auth::Bytes>> fetched);
'''

NEW_DECLARATIONS = '''  struct ValidatorAuthResolutionSnapshot {
    // The state cell and head describe one masterchain tip. The state supplies
    // the previous-block record that selects archive blocks, while the head
    // binds that same block id to that same state cell. They travel together
    // through asynchronous reads so enumeration and authentication cannot see
    // different tips. The chain context is immutable but travels with them so
    // finish never rereads an authority member after IO.
    td::Ref<vm::Cell> masterchain_state;
    tos::auth::Anchor head;
    tos::auth::ChainContext chain;
  };

  void resolve_validator_auth_history(std::vector<td::uint32> coordinates);
  void fetch_validator_auth_block(std::vector<td::uint32> coordinates,
                                  std::shared_ptr<const ValidatorAuthResolutionSnapshot> snapshot,
                                  std::vector<BlockIdExt> wanted, size_t index,
                                  std::shared_ptr<std::map<BlockSeqno, tos::auth::Bytes>> fetched);
  void finish_validator_auth_resolution(std::vector<td::uint32> coordinates,
                                        std::shared_ptr<const ValidatorAuthResolutionSnapshot> snapshot,
                                        std::shared_ptr<std::map<BlockSeqno, tos::auth::Bytes>> fetched);
'''

OLD_HEAD = '''tos::auth::Anchor ValidatorManagerImpl::validator_auth_head() const {
  return tos::auth::anchor_of(last_masterchain_block_id_,
                              last_masterchain_state_.is_null() ? td::Ref<vm::Cell>{}
                                                                : last_masterchain_state_->root_cell());
}

'''

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

  // Enumeration and authentication must describe the same finalized-history
  // view. Capture the parent state cell and the head built from the matching
  // block id in this actor turn, before the first archive read can yield.
  const auto state = last_masterchain_state_->root_cell();
  const auto head = tos::auth::anchor_of(last_masterchain_block_id_, state);
  auto snapshot = std::make_shared<const ValidatorAuthResolutionSnapshot>(
      ValidatorAuthResolutionSnapshot{state, head, validator_auth_chain_.value()});
  auto wanted = tos::auth::required_finalized_blocks(batch.value(), snapshot->masterchain_state, snapshot->head,
                                                     snapshot->chain, validator_auth_anchors_);
  if (!wanted.ok()) {
    LOG(INFO) << "cannot resolve the history a registry update declared: " << wanted.error().code;
    auto pending = validator_auth_resolution_queue_.complete();
    if (pending.has_value()) {
      resolve_validator_auth_history(std::move(pending.value()));
    }
    return;
  }
  auto fetched = std::make_shared<std::map<BlockSeqno, tos::auth::Bytes>>();
  fetch_validator_auth_block(std::move(batch.value()), std::move(snapshot), std::move(wanted.value()), 0,
                             std::move(fetched));
}'''

OLD_FETCH_SIGNATURE = '''void ValidatorManagerImpl::fetch_validator_auth_block(std::vector<td::uint32> coordinates,
                                                      std::vector<BlockIdExt> wanted, size_t index,
                                                      std::shared_ptr<std::map<BlockSeqno, tos::auth::Bytes>> fetched) {'''

NEW_FETCH_SIGNATURE = '''void ValidatorManagerImpl::fetch_validator_auth_block(
    std::vector<td::uint32> coordinates, std::shared_ptr<const ValidatorAuthResolutionSnapshot> snapshot,
    std::vector<BlockIdExt> wanted, size_t index,
    std::shared_ptr<std::map<BlockSeqno, tos::auth::Bytes>> fetched) {'''

OLD_FETCH_FINISH = '''    finish_validator_auth_resolution(std::move(coordinates), std::move(fetched));'''
NEW_FETCH_FINISH = '''    finish_validator_auth_resolution(std::move(coordinates), std::move(snapshot), std::move(fetched));'''

OLD_FETCH_CAPTURE = '''  auto P = td::PromiseCreator::lambda([SelfId = actor_id(this), coordinates = std::move(coordinates),
                                       wanted = std::move(wanted), index, fetched,
                                       id](td::Result<td::Ref<BlockData>> R) mutable {'''
NEW_FETCH_CAPTURE = '''  auto P = td::PromiseCreator::lambda([SelfId = actor_id(this), coordinates = std::move(coordinates),
                                       snapshot = std::move(snapshot), wanted = std::move(wanted), index, fetched,
                                       id](td::Result<td::Ref<BlockData>> R) mutable {'''

OLD_FETCH_RECURSE = '''    td::actor::send_closure(SelfId, &ValidatorManagerImpl::fetch_validator_auth_block, std::move(coordinates),
                            std::move(wanted), index + 1, std::move(fetched));'''
NEW_FETCH_RECURSE = '''    td::actor::send_closure(SelfId, &ValidatorManagerImpl::fetch_validator_auth_block, std::move(coordinates),
                            std::move(snapshot), std::move(wanted), index + 1, std::move(fetched));'''

OLD_FINISH_PREFIX = '''void ValidatorManagerImpl::finish_validator_auth_resolution(
    std::vector<td::uint32> coordinates, std::shared_ptr<std::map<BlockSeqno, tos::auth::Bytes>> fetched) {
  validator_auth_resolving_ = false;
  if (!validator_auth_chain_ || last_masterchain_state_.is_null()) {
    return;
  }'''

NEW_FINISH_PREFIX = '''void ValidatorManagerImpl::finish_validator_auth_resolution(
    std::vector<td::uint32> coordinates, std::shared_ptr<const ValidatorAuthResolutionSnapshot> snapshot,
    std::shared_ptr<std::map<BlockSeqno, tos::auth::Bytes>> fetched) {
  auto pending = validator_auth_resolution_queue_.complete();
  SCOPE_EXIT {
    if (pending.has_value()) {
      resolve_validator_auth_history(std::move(pending.value()));
    }
  };
  if (!snapshot || snapshot->masterchain_state.is_null()) {
    return;
  }'''

OLD_RESOLVED = '''  auto resolved = tos::auth::resolve_declared_history(coordinates, last_masterchain_state_->root_cell(),
                                                      validator_auth_head(), validator_auth_chain_.value(), reader,
                                                      validator_auth_anchors_);'''

NEW_RESOLVED = '''  auto resolved = tos::auth::resolve_declared_history(coordinates, snapshot->masterchain_state, snapshot->head,
                                                      snapshot->chain, reader, validator_auth_anchors_);'''

OLD_MEMBER = "  bool validator_auth_resolving_ = false;"
NEW_MEMBER = "  tos::auth::NativeHistoryResolutionQueue validator_auth_resolution_queue_;"

CPP_REPLACEMENTS = [
    (OLD_HEAD, ""),
    (OLD_RESOLVE, NEW_RESOLVE),
    (OLD_FETCH_SIGNATURE, NEW_FETCH_SIGNATURE),
    (OLD_FETCH_FINISH, NEW_FETCH_FINISH),
    (OLD_FETCH_CAPTURE, NEW_FETCH_CAPTURE),
    (OLD_FETCH_RECURSE, NEW_FETCH_RECURSE),
    (OLD_FINISH_PREFIX, NEW_FINISH_PREFIX),
    (OLD_RESOLVED, NEW_RESOLVED),
]


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise RuntimeError(f"{label}: anchor count {count}, expected 1")
    return text.replace(old, new, 1)


def main() -> None:
    header = MANAGER_H.read_text()
    header = replace_once(header, OLD_DECLARATIONS, NEW_DECLARATIONS, "manager.hpp declarations")
    header = replace_once(header, OLD_MEMBER, NEW_MEMBER, "manager.hpp queue member")

    source = MANAGER_CPP.read_text()
    for old, new in CPP_REPLACEMENTS:
        source = replace_once(source, old, new, "manager.cpp")

    manifest = json.loads(MANIFEST.read_text())
    entries = manifest["insertions"]["validator/manager.cpp"]
    history_entries = [entry for entry in entries if "resolve_validator_auth_history" in entry["text"]]
    if len(history_entries) != 1:
        raise RuntimeError(f"history insertion count {len(history_entries)}, expected 1")
    insertion = history_entries[0]["text"]
    for old, new in CPP_REPLACEMENTS:
        insertion = replace_once(insertion, old, new, "manager.cpp insertion")
    history_entries[0]["text"] = insertion

    MANAGER_H.write_text(header)
    MANAGER_CPP.write_text(source)
    MANIFEST.write_text(json.dumps(manifest, indent=1) + "\n")
    print("TASK3_COMPLETION_EDIT_OK")


if __name__ == "__main__":
    main()
