#pragma once

#include "block/block-auto.h"
#include "block/block-parse.h"
#include "validator/validator.h"
#include "vm/boc.h"

namespace tos::validator::test {

// Test executable only. Replays a genuine network-produced proof through the
// real manager, then submits a structurally valid conflicting root declaration.
// This is not transport fault injection or an uncached signature test.
class CounterProofProbe final : public td::actor::Actor {
 public:
  CounterProofProbe(td::actor::ActorId<ValidatorManagerInterface> manager, BlockIdExt block)
      : manager_(manager), block_(block) {
  }

 private:
  td::actor::ActorId<ValidatorManagerInterface> manager_;
  BlockIdExt block_;

  void start_up() override {
    run().start().detach();
  }

  td::actor::Task<> run() {
    auto result = co_await check().wrap();
    if (result.is_error()) {
      LOG(ERROR) << "COUNTER_PROOF_PROBE_FAIL " << result.error();
    } else {
      LOG(WARNING) << "COUNTER_PROOF_PROBE_PASS root-binding " << block_.to_str();
    }
    stop();
    co_return td::Unit{};
  }

  td::actor::Task<> check() {
    auto handle = co_await td::actor::ask(manager_, &ValidatorManagerInterface::get_block_handle, block_, false);
    auto bytes = co_await td::actor::ask(manager_, &ValidatorManagerInterface::get_block_proof, handle);
    co_await td::actor::ask(manager_, &ValidatorManagerInterface::validate_block_proof, block_, bytes.clone());
    auto root = vm::std_boc_deserialize(bytes);
    if (root.is_error()) {
      co_return root.move_as_error();
    }
    block::gen::BlockProof::Record record;
    if (!tlb::unpack_cell(root.move_as_ok(), record)) {
      co_return td::Status::Error("cannot unpack genuine proof");
    }
    auto conflicting = block_;
    conflicting.root_hash.data()[0] ^= 1;
    vm::CellBuilder id;
    if (!block::tlb::t_BlockIdExt.pack(id, conflicting)) {
      co_return td::Status::Error("cannot encode conflicting proof identity");
    }
    record.proof_for = vm::load_cell_slice_ref(id.finalize());
    td::Ref<vm::Cell> forged;
    if (!tlb::pack_cell(forged, record)) {
      co_return td::Status::Error("cannot encode conflicting proof envelope");
    }
    auto encoded = vm::std_boc_serialize(forged);
    if (encoded.is_error()) {
      co_return encoded.move_as_error();
    }
    auto rejected = co_await td::actor::ask(manager_, &ValidatorManagerInterface::validate_block_proof,
                                         conflicting, encoded.move_as_ok()).wrap();
    if (rejected.is_ok()) {
      co_return td::Status::Error("conflicting proof root was accepted");
    }
    // Identify the exercised branch; a download timeout or malformed BoC is
    // not evidence of root authentication. Acceptance is checked independently.
    if (rejected.error().message().str().find("incorrect root hash") == std::string::npos) {
      co_return td::Status::Error(PSTRING() << "unexpected rejection: " << rejected.error());
    }
    co_return td::Unit{};
  }
};

}  // namespace tos::validator::test
