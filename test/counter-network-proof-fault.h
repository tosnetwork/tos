#pragma once

#include <atomic>
#include <cstdlib>
#include <fstream>

#include "block/block-auto.h"
#include "block/block-parse.h"
#include "vm/boc.h"
#include "vm/dict.h"

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

inline td::Result<std::string> proof_cell_fingerprint(td::Slice bytes) {
  TRY_RESULT(root, vm::std_boc_deserialize(bytes));
  return root->get_hash().to_hex();
}

inline td::Result<td::BufferSlice> corrupt_masterchain_signature(BlockIdExt id, td::BufferSlice bytes) {
  const auto *armed_file = std::getenv("TOS_COUNTER_BAD_SIGNATURE_FILE");
  static std::atomic<bool> injected{false};
  // The initial committee has already verified block 1 before arming. Target
  // the cold observer's uncached first proof, not a warm node's cached tip.
  if (!id.is_masterchain() || id.seqno() != 1 || !armed_file || !std::ifstream(armed_file).good() ||
      injected.exchange(true)) {
    return bytes;
  }
  TRY_RESULT(root, vm::std_boc_deserialize(bytes));
  block::gen::BlockProof::Record proof;
  block::gen::BlockSignatures::Record_block_signatures_simplex signatures;
  if (!tlb::unpack_cell(root, proof) ||
      !tlb::unpack_cell(proof.signatures->prefetch_ref(), signatures)) {
    return td::Status::Error("cannot unpack signed masterchain proof");
  }
  vm::Dictionary dict{signatures.signatures, 16};
  const auto key = td::BitArray<16>::zero();
  auto value = dict.lookup(key);
  td::Bits256 signer;
  unsigned char signature[64];
  if (value.is_null() || !value.write().fetch_bits_to(signer) || value.write().fetch_ulong(4) != 5 ||
      !value.write().fetch_bytes(signature, 64) || !value->empty_ext()) {
    return td::Status::Error("cannot decode first 64-byte committee signature");
  }
  signature[0] ^= 1;
  vm::CellBuilder entry;
  if (!(entry.store_bits_bool(signer) && entry.store_long_bool(5, 4) && entry.store_bytes_bool(signature, 64) &&
        dict.set_builder(key, entry, vm::Dictionary::SetMode::Replace))) {
    return td::Status::Error("cannot replace committee signature");
  }
  vm::CellBuilder dictionary;
  if (!dict.append_dict_to_bool(dictionary)) {
    return td::Status::Error("cannot encode changed signature dictionary");
  }
  signatures.signatures = vm::load_cell_slice_ref(dictionary.finalize());
  td::Ref<vm::Cell> changed_signatures;
  if (!tlb::pack_cell(changed_signatures, signatures)) {
    return td::Status::Error("cannot encode changed signature set");
  }
  proof.signatures = vm::load_cell_slice_ref(vm::CellBuilder().store_long(1, 1).store_ref(changed_signatures).finalize());
  td::Ref<vm::Cell> changed_proof;
  if (!tlb::pack_cell(changed_proof, proof)) {
    return td::Status::Error("cannot encode changed signed proof");
  }
  TRY_RESULT(encoded, vm::std_boc_serialize(changed_proof));
  LOG(WARNING) << "COUNTER_BAD_SIGNATURE_SENT " << changed_proof->get_hash().to_hex() << " " << id.to_str();
  return encoded;
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
