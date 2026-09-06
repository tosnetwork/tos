#pragma once

#include <atomic>
#include <cstdlib>
#include <fstream>

#include "block/block-auto.h"
#include "block/block-parse.h"
#include "vm/boc.h"

namespace tos::validator::test {

inline td::Result<BlockIdExt> proof_declared_block(td::Slice bytes) {
  TRY_RESULT(root, vm::std_boc_deserialize(bytes));
  block::gen::BlockProof::Record record;
  BlockIdExt declared;
  if (!tlb::unpack_cell(root, record) || !block::tlb::t_BlockIdExt.unpack(record.proof_for.write(), declared)) {
    return td::Status::Error("cannot decode proof identity");
  }
  return declared;
}

// Called only by the isolated test library. Arm after the initial committee
// has produced blocks, so startup downloads cannot consume the one-shot fault.
inline td::Result<td::BufferSlice> misbind_counter_proof(BlockIdExt id, td::BufferSlice bytes) {
  const auto *armed_file = std::getenv("TOS_COUNTER_MISBOUND_PROOF_FILE");
  static std::atomic<bool> injected{false};
  if (id.id.workchain != 2 || id.seqno() == 0 || !armed_file || !std::ifstream(armed_file).good() ||
      injected.exchange(true)) {
    return bytes;
  }
  TRY_RESULT(root, vm::std_boc_deserialize(bytes));
  block::gen::BlockProof::Record record;
  if (!tlb::unpack_cell(root, record)) {
    return td::Status::Error("cannot unpack Counter proof for injection");
  }
  auto conflicting = id;
  conflicting.file_hash.data()[0] ^= 1;
  vm::CellBuilder identity;
  if (!block::tlb::t_BlockIdExt.pack(identity, conflicting)) {
    return td::Status::Error("cannot encode conflicting Counter identity");
  }
  record.proof_for = vm::load_cell_slice_ref(identity.finalize());
  td::Ref<vm::Cell> forged;
  if (!tlb::pack_cell(forged, record)) {
    return td::Status::Error("cannot repack Counter proof");
  }
  TRY_RESULT(encoded, vm::std_boc_serialize(forged));
  LOG(WARNING) << "COUNTER_MISBOUND_PROOF_SENT " << id.to_str();
  return encoded;
}

}  // namespace tos::validator::test
