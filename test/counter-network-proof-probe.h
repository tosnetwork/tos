#pragma once

#include "block/block-auto.h"
#include "block/block-parse.h"
#include "validator/validator.h"
#include "validator/interfaces/validator-manager.h"
#include "auto/tl/tos_api.hpp"
#include "vm/boc.h"

namespace tos::validator::test {

// Test executable only. Replays a genuine network-produced proof through the
// real manager, then submits a structurally valid conflicting root declaration.
// Signature probing uses the separate broadcast signature-only entry point.
// Neither probe injects bytes through a remote transport.
class CounterProofProbe final : public td::actor::Actor {
 public:
  CounterProofProbe(td::actor::ActorId<ValidatorManagerInterface> manager, BlockIdExt block, bool signatures)
      : manager_(manager), block_(block), signatures_(signatures) {
  }

 private:
  td::actor::ActorId<ValidatorManagerInterface> manager_;
  BlockIdExt block_;
  bool signatures_;

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
    if (signatures_) {
      co_await check_shard_signatures();
    }
    co_return td::Unit{};
  }

  td::actor::Task<> check_shard_signatures() {
    auto full_manager = td::actor::actor_dynamic_cast<ValidatorManager>(manager_);
    td::Ref<ShardTopBlockDescription> description;
    // Descriptions disappear when the masterchain incorporates them. Sample
    // this live cache more frequently than block production, within five seconds.
    for (unsigned attempt = 0; attempt != 250; ++attempt) {
      auto descriptions = co_await td::actor::ask(full_manager,
          &ValidatorManager::get_shard_blocks_for_collator, block_);
      for (auto& candidate : descriptions) {
        if (candidate->shard() == ShardIdFull{2, shardIdAll} && candidate->block_id().seqno() > 0) {
          description = candidate;
          break;
        }
      }
      if (description.not_null()) {
        break;
      }
      co_await td::actor::coro_sleep(td::Timestamp::in(0.02));
    }
    if (description.is_null()) {
      co_return td::Status::Error("no live Counter description for signature probe");
    }
    auto root = vm::std_boc_deserialize(description->serialize());
    if (root.is_error()) {
      co_return root.move_as_error();
    }
    block::gen::TopBlockDescr::Record record;
    if (!tlb::unpack_cell(root.move_as_ok(), record) || record.len < 1) {
      co_return td::Status::Error("cannot decode live Counter description");
    }
    ValidatorWeight weight;
    auto decoded = block::BlockSignatureSet::fetch(record.signatures->prefetch_ref(), weight);
    if (decoded.is_error()) {
      co_return decoded.move_as_error();
    }
    auto signatures = decoded.move_as_ok();
    const auto shard = description->block_id();
    vm::CellBuilder proof;
    if (!(proof.store_long_bool(0xc3, 8) && block::tlb::t_BlockIdExt.pack(proof, shard) &&
          proof.store_ref_bool(record.chain->prefetch_ref()) && proof.store_bool_bool(false))) {
      co_return td::Status::Error("cannot reconstruct head proof link");
    }
    auto proof_bytes = vm::std_boc_serialize(proof.finalize());
    if (proof_bytes.is_error()) {
      co_return proof_bytes.move_as_error();
    }
    BlockBroadcast broadcast{shard, signatures, {}, proof_bytes.move_as_ok()};
    auto original = broadcast.clone();
    co_await td::actor::ask(manager_, &ValidatorManagerInterface::validate_block_broadcast_signatures,
                          broadcast.clone());
    auto encoded = signatures->tl();
    bool changed = false;
    tos_api::downcast_call(*encoded, [&](auto& set) {
      if (!set.signatures_.empty() && set.signatures_[0]->signature_.size() == 64) {
        // BufferSlice::clone shares storage. Detach the bytes before changing
        // them, so the positive control retains the original signature.
        set.signatures_[0]->signature_ = td::BufferSlice(set.signatures_[0]->signature_.as_slice());
        set.signatures_[0]->signature_.as_slice()[0] ^= 1;
        changed = true;
      }
    });
    if (!changed) {
      co_return td::Status::Error("cannot mutate a genuine 64-byte signature");
    }
    broadcast.sig_set = block::BlockSignatureSet::fetch(encoded);
    auto rejected = co_await td::actor::ask(manager_,
        &ValidatorManagerInterface::validate_block_broadcast_signatures, std::move(broadcast)).wrap();
    if (rejected.is_ok()) {
      co_return td::Status::Error("corrupted committee signature was accepted");
    }
    if (rejected.error().message().str().find("failed signature check:") == std::string::npos) {
      co_return td::Status::Error(PSTRING() << "unexpected signature rejection: " << rejected.error());
    }
    co_await td::actor::ask(manager_, &ValidatorManagerInterface::validate_block_broadcast_signatures,
                          std::move(original));
    LOG(WARNING) << "COUNTER_SIGNATURE_PROBE_PASS " << shard.to_str() << " " << rejected.error();
    co_return td::Unit{};
  }
};

}  // namespace tos::validator::test
