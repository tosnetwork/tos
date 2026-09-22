/*
    This file is part of TOS Blockchain Library.

    TOS Blockchain Library is free software: you can redistribute it and/or modify
    it under the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation, either version 2 of the License, or
    (at your option) any later version.

    TOS Blockchain Library is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with TOS Blockchain Library.  If not, see <http://www.gnu.org/licenses/>.
*/
#include <cstring>
#include <limits>

#include "auto/tl/tos_api.h"
#include "auto/tl/tos_api.hpp"
#include "common/errorcode.h"
#include "crypto/pq/mldsa44.h"
#include "crypto/pq/pq-bytes.h"
#include "keys/keys.hpp"
#include "td/utils/overloaded.h"
#include "tl-utils/common-utils.hpp"
#include "tl-utils/tl-utils.hpp"
#include "tos/quorum.h"
#include "tos/tos-tl.hpp"
#include "vm/boc.h"
#include "vm/cells/CellString.h"

#include "block-auto.h"
#include "mc-config.h"
#include "pq-signature-limits.h"
#include "signature-set.h"

namespace block {

static_assert(pq::pq_candidate_data_max_bytes == vm::CellString::max_bytes);

static td::Result<std::size_t> tl_bytes_field_size(std::size_t bytes) {
  const std::size_t prefix = bytes < 254 ? 1 : 4;
  if (bytes > std::numeric_limits<std::size_t>::max() - prefix - 3) {
    return td::Status::Error("TL bytes size overflow");
  }
  return (prefix + bytes + 3) & ~std::size_t{3};
}

static td::Status add_size_checked(std::size_t& total, std::size_t value) {
  if (value > std::numeric_limits<std::size_t>::max() - total) {
    return td::Status::Error("signature data size overflow");
  }
  total += value;
  return td::Status::OK();
}

static td::Status check_vset(const BlockSignatureSet* sig_set, const td::Ref<ValidatorSet>& vset) {
  if (vset->get_catchain_seqno() != sig_set->get_catchain_seqno()) {
    return td::Status::Error(tos::ErrorCode::protoviolation, PSTRING() << "catchain seqno mismatch: expected "
                                                                       << vset->get_catchain_seqno() << ", found "
                                                                       << sig_set->get_catchain_seqno());
  }
  if (vset->get_validator_set_hash() != sig_set->get_validator_set_hash()) {
    return td::Status::Error(tos::ErrorCode::protoviolation, PSTRING() << "validator set hash mismatch: expected "
                                                                       << vset->get_validator_set_hash() << ", found "
                                                                       << sig_set->get_validator_set_hash());
  }
  return td::Status::OK();
}

static td::Status check_carrier_compatibility(const BlockSignatureSet* sig_set, const td::Ref<ValidatorSet>& vset) {
  bool has_pq = false;
  bool has_classical = false;
  for (const auto& validator : vset->export_vector()) {
    has_pq |= validator.is_pq();
    has_classical |= !validator.is_pq();
  }
  if (has_pq && has_classical) {
    return td::Status::Error("mixed validator set has no admitted signature carrier");
  }
  if (has_pq && !sig_set->is_pq()) {
    return td::Status::Error("unsupported carrier for post-quantum validator set");
  }
  if (!has_pq && sig_set->is_pq()) {
    return td::Status::Error("post-quantum carrier for classical validator set");
  }
  return td::Status::OK();
}

td::Result<tos::ValidatorWeight> BlockSignatureSet::check_signatures(td::Ref<ValidatorSet> vset,
                                                                     tos::BlockIdExt block_id) const {
  if (is_pq()) {
    return td::Status::Error("pq finality: trusted expected session context is required");
  }
  TRY_STATUS(check_carrier_compatibility(this, vset));
  if (!is_final()) {
    return td::Status::Error(tos::ErrorCode::protoviolation, "not final signatures");
  }
  return check_signatures_impl(std::move(vset), block_id);
}

td::Result<tos::ValidatorWeight> BlockSignatureSet::check_approve_signatures(td::Ref<ValidatorSet> vset,
                                                                             tos::BlockIdExt block_id) const {
  if (is_pq()) {
    return td::Status::Error("pq finality: trusted expected session context is required");
  }
  TRY_STATUS(check_carrier_compatibility(this, vset));
  if (is_final()) {
    return td::Status::Error(tos::ErrorCode::protoviolation, "not approve signatures");
  }
  return check_signatures_impl(std::move(vset), block_id);
}

td::Result<tos::ValidatorWeight> BlockSignatureSet::check_pq_signatures_under_carried_session_for_test(
    td::Ref<ValidatorSet> vset, tos::BlockIdExt block_id, FinalityRole role) const {
  TRY_STATUS(check_carrier_compatibility(this, vset));
  if (!is_pq()) {
    return td::Status::Error("pq finality: post-quantum carrier required");
  }
  if ((role == FinalityRole::Final) != is_final()) {
    return td::Status::Error(
        std::string{role == FinalityRole::Final ? "not final signatures" : "not approve signatures"});
  }
  return check_signatures_impl(std::move(vset), block_id);
}

td::Result<tos::ValidatorWeight> verify_pq_finality(const PQFinalityVerificationContext& context,
                                                    const BlockSignatureSet& signature_set, FinalityRole role) {
  if (context.validator_set.is_null()) {
    return td::Status::Error("pq finality: trusted validator set is missing");
  }
  if (!signature_set.is_pq()) {
    return td::Status::Error("pq finality: post-quantum carrier required");
  }
  TRY_STATUS(check_carrier_compatibility(&signature_set, context.validator_set));
  TRY_STATUS(check_vset(&signature_set, context.validator_set));
  if ((role == FinalityRole::Final) != signature_set.is_final()) {
    return td::Status::Error(
        std::string{role == FinalityRole::Final ? "not final signatures" : "not approve signatures"});
  }
  TRY_RESULT(carried_session_id, signature_set.pq_session_id());
  if (carried_session_id != context.expected_session_id) {
    return td::Status::Error("pq finality: carried session_id does not match trusted expected session_id");
  }
  return signature_set.check_signatures_impl(context.validator_set, context.block_id);
}

static tos::tl_object_ptr<tos::tos_api::consensus_CandidateParent> clone_tl(
    const tos::tl_object_ptr<tos::tos_api::consensus_CandidateParent>& f) {
  tos::tl_object_ptr<tos::tos_api::consensus_CandidateParent> result;
  tos::tos_api::downcast_call(
      *f, td::overloaded(
              [&](const tos::tos_api::consensus_candidateParent& obj) {
                result = tos::create_tl_object<tos::tos_api::consensus_candidateParent>(
                    tos::create_tl_object<tos::tos_api::consensus_candidateId>(obj.id_->slot_, obj.id_->hash_));
              },
              [&](const tos::tos_api::consensus_candidateWithoutParents&) {
                result = tos::create_tl_object<tos::tos_api::consensus_candidateWithoutParents>();
              }));
  return result;
}

static tos::tl_object_ptr<tos::tos_api::consensus_CandidateHashData> clone_tl(
    const tos::tl_object_ptr<tos::tos_api::consensus_CandidateHashData>& f) {
  tos::tl_object_ptr<tos::tos_api::consensus_CandidateHashData> result;
  tos::tos_api::downcast_call(
      *f, td::overloaded(
              [&](const tos::tos_api::consensus_candidateHashDataOrdinary& obj) {
                result = tos::create_tl_object<tos::tos_api::consensus_candidateHashDataOrdinary>(
                    tos::create_tl_block_id(tos::create_block_id(obj.block_)), obj.collated_file_hash_,
                    clone_tl(obj.parent_));
              },
              [&](const tos::tos_api::consensus_candidateHashDataEmpty& obj) {
                result = tos::create_tl_object<tos::tos_api::consensus_candidateHashDataEmpty>(
                    tos::create_tl_block_id(tos::create_block_id(obj.block_)),
                    tos::create_tl_object<tos::tos_api::consensus_candidateId>(obj.parent_->slot_, obj.parent_->hash_));
              }));
  return result;
}

td::Result<td::BufferSlice> BlockSignatureSet::build_simplex_data_to_sign(
    td::Bits256 session_id, td::uint32 slot,
    const tos::tl_object_ptr<tos::tos_api::consensus_CandidateHashData>& candidate, bool final,
    tos::BlockIdExt block_id) {
  if (candidate == nullptr) {
    return td::Status::Error("simplex candidate data is null");
  }
  tos::BlockIdExt expected_block_id;
  tos::tos_api::downcast_call(*candidate, td::overloaded(
                                              [&](const tos::tos_api::consensus_candidateHashDataOrdinary& obj) {
                                                expected_block_id = tos::create_block_id(obj.block_);
                                              },
                                              [&](const tos::tos_api::consensus_candidateHashDataEmpty& obj) {
                                                expected_block_id = tos::create_block_id(obj.block_);
                                              }));
  if (block_id != expected_block_id) {
    return td::Status::Error("block id mismatch");
  }
  auto candidate_id = tos::create_tl_object<tos::tos_api::consensus_candidateId>(
      slot, td::Bits256{tos::get_tl_object_sha256(candidate).raw});
  td::BufferSlice vote;
  if (final) {
    vote = tos::create_serialize_tl_object<tos::tos_api::consensus_simplex_finalizeVote>(std::move(candidate_id));
  } else {
    vote = tos::create_serialize_tl_object<tos::tos_api::consensus_simplex_notarizeVote>(std::move(candidate_id));
  }
  return tos::create_serialize_tl_object<tos::tos_api::consensus_dataToSign>(session_id, std::move(vote));
}

class BlockSignatureSetBase : public BlockSignatureSet {
 public:
  explicit BlockSignatureSetBase(std::vector<tos::BlockSignature> signatures, tos::CatchainSeqno cc_seqno,
                                 td::uint32 validator_set_hash)
      : BlockSignatureSet(cc_seqno, validator_set_hash), signatures_(std::move(signatures)) {
  }

  virtual td::Result<td::BufferSlice> to_sign(tos::BlockIdExt block_id) const = 0;
  virtual bool check_threshold(tos::ValidatorWeight sig_weight, tos::ValidatorWeight total_weight) const {
    return tos::has_quorum(sig_weight, total_weight);
  }

  size_t get_size() const override {
    return signatures_.size();
  }

  td::Result<std::size_t> get_signature_data_size() const override {
    std::size_t total = 0;
    for (const auto& signature : signatures_) {
      constexpr std::size_t identity_bytes = 32;
      TRY_RESULT(encoded_signature_bytes, tl_bytes_field_size(signature.signature.size()));
      TRY_STATUS(add_size_checked(total, identity_bytes));
      TRY_STATUS(add_size_checked(total, encoded_signature_bytes));
    }
    return total;
  }

  td::Result<tos::ValidatorWeight> get_weight(td::Ref<ValidatorSet> vset) const override {
    TRY_STATUS(check_vset(this, vset));
    tos::ValidatorWeight weight = 0;
    std::set<tos::NodeIdShort> nodes;
    for (auto& sig : signatures_) {
      if (nodes.contains(sig.node)) {
        return td::Status::Error(tos::ErrorCode::protoviolation, "duplicate node");
      }
      nodes.insert(sig.node);
      // This is the classical signature path, where a signer is identified by the
      // identity derived from its Ed25519 key, which for a classical descriptor is
      // also its membership identity.
      auto validator = vset->get_validator(tos::ValidatorId{sig.node});
      if (!validator) {
        return td::Status::Error(tos::ErrorCode::protoviolation, "unknown node");
      }
      // A post-quantum validator has no Ed25519 key. Accepting a classical signature
      // for one would mean verifying against a key that does not exist.
      if (validator->is_pq()) {
        return td::Status::Error(tos::ErrorCode::protoviolation,
                                 "classical signature offered for a post-quantum validator");
      }
      weight += validator->weight;
    }
    return weight;
  }

  td::Result<td::Ref<vm::Cell>> serialize_dict() const {
    vm::Dictionary dict{16};  // HashmapE 16 CryptoSignaturePair
    for (unsigned i = 0; i < signatures_.size(); i++) {
      const tos::BlockSignature& sig = signatures_[i];
      vm::CellBuilder cb;
      if (!(cb.store_bits_bool(sig.node)                      // sig_pair$_ node_id_short:bits256
            && cb.store_long_bool(5, 4)                       //   ed25519_signature#5
            && sig.signature.size() == 64                     // signature must be 64 bytes long
            && cb.store_bytes_bool(sig.signature.data(), 64)  // R:bits256 s:bits256
            && dict.set_builder(td::BitArray<16>{i}, cb, vm::Dictionary::SetMode::Add))) {
        return td::Status::Error(PSTRING() << "failed to serialize");
      }
    }
    return std::move(dict).extract_root_cell();
  }

 protected:
  std::vector<tos::BlockSignature> signatures_;

  td::Result<tos::ValidatorWeight> check_signatures_impl(td::Ref<ValidatorSet> vset,
                                                         tos::BlockIdExt block_id) const override {
    TRY_STATUS(check_vset(this, vset));
    TRY_RESULT(data, to_sign(block_id));
    tos::ValidatorWeight weight = 0;
    std::set<tos::NodeIdShort> nodes;
    for (auto& sig : signatures_) {
      if (nodes.contains(sig.node)) {
        return td::Status::Error(tos::ErrorCode::protoviolation, "duplicate node");
      }
      nodes.insert(sig.node);

      // This is the classical signature path, where a signer is identified by the
      // identity derived from its Ed25519 key, which for a classical descriptor is
      // also its membership identity.
      auto validator = vset->get_validator(tos::ValidatorId{sig.node});
      if (!validator) {
        return td::Status::Error(tos::ErrorCode::protoviolation, "unknown node");
      }
      // A post-quantum validator has no Ed25519 key. Accepting a classical signature
      // for one would mean verifying against a key that does not exist.
      if (validator->is_pq()) {
        return td::Status::Error(tos::ErrorCode::protoviolation,
                                 "classical signature offered for a post-quantum validator");
      }

      auto E = tos::PublicKey{tos::pubkeys::Ed25519{validator->classical_key()}}.create_encryptor().move_as_ok();
      TRY_STATUS(E->check_signature(data, sig.signature.as_slice()));
      weight += validator->weight;
    }

    if (!check_threshold(weight, vset->get_total_weight())) {
      return td::Status::Error(tos::ErrorCode::protoviolation, "too small sig weight");
    }
    return weight;
  }
};

class BlockSignatureSetOrdinary : public BlockSignatureSetBase {
 public:
  explicit BlockSignatureSetOrdinary(std::vector<tos::BlockSignature> signatures, tos::CatchainSeqno cc_seqno,
                                     td::uint32 validator_set_hash)
      : BlockSignatureSetBase(std::move(signatures), cc_seqno, validator_set_hash) {
  }
  ~BlockSignatureSetOrdinary() override = default;

  CntObject* make_copy() const override {
    std::vector<tos::BlockSignature> copy;
    for (const auto& s : signatures_) {
      copy.emplace_back(s.node, s.signature.clone());
    }
    return new BlockSignatureSetOrdinary(std::move(copy), cc_seqno_, validator_set_hash_);
  }

  bool is_ordinary() const override {
    return true;
  }
  bool is_final() const override {
    return true;
  }

  td::Result<td::BufferSlice> to_sign(tos::BlockIdExt block_id) const override {
    return tos::create_serialize_tl_object<tos::tos_api::tos_blockId>(block_id.root_hash, block_id.file_hash);
  }

  tos::tl_object_ptr<tos::tos_api::tosNode_SignatureSet> tl() const override {
    auto f = tos::create_tl_object<tos::tos_api::tosNode_signatureSet_ordinary>();
    f->cc_seqno_ = cc_seqno_;
    f->validator_set_hash_ = validator_set_hash_;
    for (auto& sig : signatures_) {
      f->signatures_.push_back(
          tos::create_tl_object<tos::tos_api::tosNode_blockSignature>(sig.node, sig.signature.clone()));
    }
    return f;
  }

  tos::tl_object_ptr<tos::lite_api::liteServer_SignatureSet> tl_lite() const override {
    auto f = tos::create_tl_object<tos::lite_api::liteServer_signatureSet_ordinary>();
    f->catchain_seqno_ = cc_seqno_;
    f->validator_set_hash_ = validator_set_hash_;
    for (auto& sig : signatures_) {
      f->signatures_.push_back(
          tos::create_tl_object<tos::lite_api::liteServer_signature>(sig.node, sig.signature.clone()));
    }
    return f;
  }

  std::vector<tos::tl_object_ptr<tos::tos_api::tosNode_blockSignature>> tl_legacy() const override {
    std::vector<tos::tl_object_ptr<tos::tos_api::tosNode_blockSignature>> f;
    for (auto& sig : signatures_) {
      f.push_back(tos::create_tl_object<tos::tos_api::tosNode_blockSignature>(sig.node, sig.signature.clone()));
    }
    return f;
  }

  td::Result<td::Ref<vm::Cell>> serialize(td::Ref<ValidatorSet> vset) const override {
    TRY_RESULT(weight, get_weight(vset));
    TRY_RESULT(dict_root, serialize_dict());
    // block_signatures_ordinary#11 validator_list_hash_short:uint32 catchain_seqno:uint32
    //   sig_count:uint32 sig_weight:uint64
    //   signatures:(HashmapE 16 CryptoSignaturePair) = BlockSignatures;
    vm::CellBuilder cb;
    cb.store_long(0x11, 8);
    cb.store_long(validator_set_hash_, 32);
    cb.store_long(cc_seqno_, 32);
    cb.store_long(signatures_.size(), 32);
    cb.store_long(weight, 64);
    cb.store_maybe_ref(dict_root);
    return cb.finalize_novm();
  }
};

class BlockSignatureSetSimplex : public BlockSignatureSetBase {
 public:
  explicit BlockSignatureSetSimplex(std::vector<tos::BlockSignature> signatures, tos::CatchainSeqno cc_seqno,
                                    td::uint32 validator_set_hash, td::Bits256 session_id, td::uint32 slot,
                                    tos::tl_object_ptr<tos::tos_api::consensus_CandidateHashData> candidate, bool final)
      : BlockSignatureSetBase(std::move(signatures), cc_seqno, validator_set_hash)
      , session_id_(session_id)
      , slot_(slot)
      , candidate_(std::move(candidate))
      , final_(final) {
  }
  ~BlockSignatureSetSimplex() override = default;

  CntObject* make_copy() const override {
    std::vector<tos::BlockSignature> copy;
    for (const auto& s : signatures_) {
      copy.emplace_back(s.node, s.signature.clone());
    }
    return new BlockSignatureSetSimplex(std::move(copy), cc_seqno_, validator_set_hash_, session_id_, slot_,
                                        clone_tl(candidate_), final_);
  }

  bool is_final() const override {
    return final_;
  }

  td::Result<td::BufferSlice> to_sign(tos::BlockIdExt block_id) const override {
    return build_simplex_data_to_sign(session_id_, slot_, candidate_, final_, block_id);
  }

  tos::tl_object_ptr<tos::tos_api::tosNode_SignatureSet> tl() const override {
    auto f = tos::create_tl_object<tos::tos_api::tosNode_signatureSet_simplex>();
    f->cc_seqno_ = cc_seqno_;
    f->validator_set_hash_ = validator_set_hash_;
    for (auto& sig : signatures_) {
      f->signatures_.push_back(
          tos::create_tl_object<tos::tos_api::tosNode_blockSignature>(sig.node, sig.signature.clone()));
    }
    f->session_id_ = session_id_;
    f->slot_ = slot_;
    f->candidate_ = clone_tl(candidate_);
    f->final_ = final_;
    return f;
  }

  tos::tl_object_ptr<tos::lite_api::liteServer_SignatureSet> tl_lite() const override {
    CHECK(final_);
    auto f = tos::create_tl_object<tos::lite_api::liteServer_signatureSet_simplex>();
    f->cc_seqno_ = cc_seqno_;
    f->validator_set_hash_ = validator_set_hash_;
    for (auto& sig : signatures_) {
      f->signatures_.push_back(
          tos::create_tl_object<tos::lite_api::liteServer_signature>(sig.node, sig.signature.clone()));
    }
    f->session_id_ = session_id_;
    f->slot_ = slot_;
    f->candidate_ = tos::serialize_tl_object(candidate_, true);
    return f;
  }

  td::Result<td::Ref<vm::Cell>> serialize(td::Ref<ValidatorSet> vset) const override {
    if (!final_) {
      return td::Status::Error(tos::ErrorCode::protoviolation, "cannot serialize approve simplex signatures to cell");
    }
    TRY_RESULT(weight, get_weight(vset));
    TRY_RESULT(dict_root, serialize_dict());
    // block_signatures_simplex#12 validator_list_hash_short:uint32 catchain_seqno:uint32
    //   sig_count:uint32 sig_weight:uint64
    //   signatures:(HashmapE 16 CryptoSignaturePair)
    //   session_id:bits256 slot:uint32 candidate_data:^Cell = BlockSignatures;
    vm::CellBuilder cb;
    cb.store_long(0x12, 8);
    cb.store_long(validator_set_hash_, 32);
    cb.store_long(cc_seqno_, 32);
    cb.store_long(signatures_.size(), 32);
    cb.store_long(weight, 64);
    cb.store_maybe_ref(dict_root);
    cb.store_bytes(session_id_.as_slice());
    cb.store_long(slot_, 32);
    TRY_RESULT(candidate_cell, vm::CellString::create(tos::serialize_tl_object(candidate_, true)));
    cb.store_ref(candidate_cell);
    return cb.finalize_novm();
  }

 private:
  td::Bits256 session_id_;
  td::uint32 slot_;
  tos::tl_object_ptr<tos::tos_api::consensus_CandidateHashData> candidate_;
  bool final_;
};

static td::Status preflight_candidate_chain(const td::Ref<vm::Cell>& root) {
  td::Ref<vm::Cell> current = root;
  std::size_t cells = 0;
  while (current.not_null()) {
    if (++cells > vm::CellString::max_chain_length) {
      return td::Status::Error("pq candidate data: chain too long");
    }
    if (current->get_level() != 0) {
      return td::Status::Error("pq candidate data: nonzero level");
    }
    vm::CellSlice slice(vm::NoVm(), current);
    if (slice.is_special()) {
      return td::Status::Error("pq candidate data: exotic cell");
    }
    if (slice.size() % 8 != 0) {
      return td::Status::Error("pq candidate data: non-byte-aligned cell");
    }
    if (slice.size_refs() > 1) {
      return td::Status::Error("pq candidate data: multiple continuation refs");
    }
    if (slice.size_refs() == 0) {
      return td::Status::OK();
    }
    current = slice.fetch_ref();
  }
  return td::Status::Error("pq candidate data: missing terminal cell");
}

static td::Result<td::BufferSlice> unpack_candidate_data_strict(td::Ref<vm::Cell> root) {
  if (root.is_null()) {
    return td::Status::Error("pq candidate data: null root");
  }
  TRY_STATUS(preflight_candidate_chain(root));
  std::string bytes;
  td::Ref<vm::Cell> current = std::move(root);
  std::size_t cells = 0;
  while (current.not_null()) {
    ++cells;
    if (current->get_level() != 0) {
      return td::Status::Error("pq candidate data: nonzero level");
    }
    vm::CellSlice slice(vm::NoVm(), current);
    if (slice.is_special()) {
      return td::Status::Error("pq candidate data: exotic cell");
    }
    if (slice.size() % 8 != 0) {
      return td::Status::Error("pq candidate data: non-byte-aligned cell");
    }
    const auto cell_bytes = static_cast<std::size_t>(slice.size() / 8);
    const auto refs = slice.size_refs();
    if (refs > 1) {
      return td::Status::Error("pq candidate data: multiple continuation refs");
    }
    if (refs == 1 && cell_bytes != vm::Cell::max_bits / 8) {
      return td::Status::Error("pq candidate data: noncanonical chunk size");
    }
    if (refs == 0 && cells > 1 && cell_bytes == 0) {
      return td::Status::Error("pq candidate data: trailing empty cell");
    }
    if (cell_bytes > pq::pq_candidate_data_max_bytes - bytes.size()) {
      return td::Status::Error("pq candidate data: oversize");
    }
    const auto old_size = bytes.size();
    bytes.resize(old_size + cell_bytes);
    if (cell_bytes != 0 && !slice.fetch_bytes(reinterpret_cast<unsigned char*>(bytes.data()) + old_size,
                                              static_cast<unsigned>(cell_bytes))) {
      return td::Status::Error("pq candidate data: byte extraction failed");
    }
    if (refs == 0) {
      break;
    }
    current = slice.fetch_ref();
  }
  return td::BufferSlice(bytes);
}

static td::Result<tos::tl_object_ptr<tos::tos_api::consensus_CandidateHashData>> parse_candidate_data_strict(
    td::Ref<vm::Cell> root) {
  TRY_RESULT(bytes, unpack_candidate_data_strict(std::move(root)));
  auto candidate = tos::fetch_tl_object<tos::tos_api::consensus_CandidateHashData>(bytes.clone(), true);
  if (candidate.is_error()) {
    return candidate.move_as_error_prefix("pq candidate data: invalid TL: ");
  }
  return candidate.move_as_ok();
}

static td::Status validate_pq_signatures(const std::vector<PQBlockSignature>& signatures) {
  if (!pq::pq_block_signatures_accepts_signer_count(signatures.size())) {
    return td::Status::Error("pq signatures: signer count exceeds maximum");
  }
  std::set<tos::ValidatorId> validator_ids;
  for (const auto& signature : signatures) {
    if (!tos::pq::is_admitted(signature.algorithm_id)) {
      return td::Status::Error("pq signatures: unsupported algorithm");
    }
    if (signature.signature.size() != tos::pq::mldsa44_signature_bytes) {
      return td::Status::Error("pq signatures: signature length");
    }
    if (!validator_ids.insert(signature.validator_id).second) {
      return td::Status::Error("pq signatures: duplicate validator_id");
    }
  }
  return td::Status::OK();
}

static td::Result<td::Ref<vm::Cell>> serialize_simplex_pq_cell(
    const std::vector<PQBlockSignature>& signatures, tos::CatchainSeqno cc_seqno, td::uint32 validator_set_hash,
    tos::ValidatorWeight signature_weight, td::Bits256 session_id, td::uint32 slot,
    const tos::tl_object_ptr<tos::tos_api::consensus_CandidateHashData>& candidate) {
  TRY_STATUS(validate_pq_signatures(signatures));
  if (candidate == nullptr) {
    return td::Status::Error("pq candidate data: null object");
  }
  vm::Dictionary dict{16};
  for (std::size_t i = 0; i < signatures.size(); ++i) {
    const auto& signature = signatures[i];
    TRY_RESULT(packed_signature,
               tos::pq::pack_pq_bytes(signature.signature.as_slice(), tos::pq::mldsa44_signature_bytes));
    vm::CellBuilder pair;
    if (!(pair.store_bits_bool(signature.validator_id.value.cbits(), 256) &&
          pair.store_long_bool(static_cast<td::uint16>(signature.algorithm_id), 16) &&
          pair.store_ref_bool(std::move(packed_signature)) &&
          dict.set_builder(td::BitArray<16>{static_cast<unsigned>(i)}, pair, vm::Dictionary::SetMode::Add))) {
      return td::Status::Error("pq signatures: dictionary serialization failed");
    }
  }
  const auto candidate_bytes = tos::serialize_tl_object(candidate, true);
  if (candidate_bytes.size() > pq::pq_candidate_data_max_bytes) {
    return td::Status::Error("pq candidate data: oversize");
  }
  TRY_RESULT(candidate_cell, vm::CellString::create(candidate_bytes.as_slice()));
  vm::CellBuilder root;
  if (!(root.store_long_bool(0x13, 8) && root.store_long_bool(validator_set_hash, 32) &&
        root.store_long_bool(cc_seqno, 32) && root.store_long_bool(signatures.size(), 32) &&
        root.store_long_bool(signature_weight, 64) && root.store_maybe_ref(std::move(dict).extract_root_cell()) &&
        root.store_bits_bool(session_id.cbits(), 256) && root.store_long_bool(slot, 32) &&
        root.store_ref_bool(std::move(candidate_cell)))) {
    return td::Status::Error("pq signatures: root serialization failed");
  }
  auto cell = root.finalize_novm();
  TRY_RESULT(serialized, vm::std_boc_serialize(cell, 0));
  if (!pq::pq_block_signatures_accepts_serialized_size(serialized.size())) {
    return td::Status::Error("pq signatures: serialized bytes exceed maximum");
  }
  return cell;
}

class BlockSignatureSetSimplexPQ final : public BlockSignatureSet {
 public:
  BlockSignatureSetSimplexPQ(std::vector<PQBlockSignature> signatures, tos::CatchainSeqno cc_seqno,
                             td::uint32 validator_set_hash, td::Bits256 session_id, td::uint32 slot,
                             tos::tl_object_ptr<tos::tos_api::consensus_CandidateHashData> candidate, bool final)
      : BlockSignatureSet(cc_seqno, validator_set_hash)
      , signatures_(std::move(signatures))
      , session_id_(session_id)
      , slot_(slot)
      , candidate_(std::move(candidate))
      , final_(final) {
  }

  CntObject* make_copy() const override {
    std::vector<PQBlockSignature> signatures;
    signatures.reserve(signatures_.size());
    for (const auto& signature : signatures_) {
      signatures.push_back(
          PQBlockSignature{signature.validator_id, signature.algorithm_id, signature.signature.clone()});
    }
    return new BlockSignatureSetSimplexPQ(std::move(signatures), cc_seqno_, validator_set_hash_, session_id_, slot_,
                                          clone_tl(candidate_), final_);
  }

  std::size_t get_size() const override {
    return signatures_.size();
  }
  td::Result<std::size_t> get_signature_data_size() const override {
    std::size_t total = 0;
    for (const auto& signature : signatures_) {
      constexpr std::size_t identity_and_algorithm_bytes = 32 + 4;
      TRY_RESULT(encoded_signature_bytes, tl_bytes_field_size(signature.signature.size()));
      TRY_STATUS(add_size_checked(total, identity_and_algorithm_bytes));
      TRY_STATUS(add_size_checked(total, encoded_signature_bytes));
    }
    return total;
  }
  bool is_pq() const override {
    return true;
  }
  bool is_final() const override {
    return final_;
  }

  td::Result<tos::ValidatorWeight> get_weight(td::Ref<ValidatorSet> vset) const override {
    TRY_STATUS(check_vset(this, vset));
    TRY_STATUS(validate_pq_signatures(signatures_));
    tos::ValidatorWeight weight = 0;
    for (const auto& signature : signatures_) {
      const auto* validator = vset->get_validator(signature.validator_id);
      if (validator == nullptr) {
        return td::Status::Error("pq signatures: unknown validator_id");
      }
      if (!validator->is_pq()) {
        return td::Status::Error("pq signatures: validator is not post-quantum");
      }
      if (validator->algorithm_id != static_cast<td::uint16>(signature.algorithm_id)) {
        return td::Status::Error("pq signatures: validator algorithm mismatch");
      }
      const auto derived_key_id = tos::pq::derive_key_id(signature.algorithm_id, validator->pq_public_key);
      if (!derived_key_id.has_value()) {
        return td::Status::Error("pq signatures: malformed validator public key");
      }
      td::Bits256 derived_key_id_bits;
      std::memcpy(derived_key_id_bits.data(), derived_key_id->data(), derived_key_id->size());
      if (validator->key_id != tos::ConsensusKeyId{derived_key_id_bits}) {
        return td::Status::Error("pq signatures: validator key_id mismatch");
      }
      if (!tos::checked_add_validator_weight(weight, validator->weight)) {
        return td::Status::Error("pq signatures: weight overflow");
      }
    }
    return weight;
  }

  td::Result<td::Ref<vm::Cell>> serialize(td::Ref<ValidatorSet> vset) const override {
    if (!final_) {
      return td::Status::Error(tos::ErrorCode::protoviolation,
                               "cannot serialize approve post-quantum simplex signatures to cell");
    }
    TRY_STATUS(validate_pq_signatures(signatures_));
    TRY_RESULT(weight, get_weight(std::move(vset)));
    return serialize_simplex_pq_cell(signatures_, cc_seqno_, validator_set_hash_, weight, session_id_, slot_,
                                     candidate_);
  }

  tos::tl_object_ptr<tos::tos_api::tosNode_SignatureSet> tl() const override {
    std::vector<tos::tl_object_ptr<tos::tos_api::tosNode_pqBlockSignature>> signatures;
    signatures.reserve(signatures_.size());
    for (const auto& signature : signatures_) {
      signatures.push_back(tos::create_tl_object<tos::tos_api::tosNode_pqBlockSignature>(
          signature.validator_id.value, static_cast<td::uint16>(signature.algorithm_id), signature.signature.clone()));
    }
    return tos::create_tl_object<tos::tos_api::tosNode_signatureSet_simplexPq>(
        final_, cc_seqno_, validator_set_hash_, std::move(signatures), session_id_, slot_, clone_tl(candidate_));
  }
  tos::tl_object_ptr<tos::lite_api::liteServer_SignatureSet> tl_lite() const override {
    std::vector<tos::tl_object_ptr<tos::lite_api::liteServer_pqSignature>> signatures;
    signatures.reserve(signatures_.size());
    for (const auto& signature : signatures_) {
      signatures.push_back(tos::create_tl_object<tos::lite_api::liteServer_pqSignature>(
          signature.validator_id.value, static_cast<td::uint16>(signature.algorithm_id), signature.signature.clone()));
    }
    return tos::create_tl_object<tos::lite_api::liteServer_signatureSet_simplexPq>(
        cc_seqno_, validator_set_hash_, std::move(signatures), session_id_, slot_,
        tos::serialize_tl_object(candidate_, true));
  }

  td::Result<std::vector<PQBlockSignature>> export_pq_signatures() const override {
    std::vector<PQBlockSignature> result;
    result.reserve(signatures_.size());
    for (const auto& signature : signatures_) {
      result.push_back(PQBlockSignature{signature.validator_id, signature.algorithm_id, signature.signature.clone()});
    }
    return result;
  }
  td::Result<td::Bits256> pq_session_id() const override {
    return session_id_;
  }
  td::Result<td::uint32> pq_slot() const override {
    return slot_;
  }
  td::Result<td::BufferSlice> pq_candidate_data() const override {
    return tos::serialize_tl_object(candidate_, true);
  }

 private:
  td::Result<tos::ValidatorWeight> check_signatures_impl(td::Ref<ValidatorSet> vset,
                                                         tos::BlockIdExt block_id) const override {
    TRY_STATUS(check_vset(this, vset));
    TRY_RESULT(message, build_simplex_data_to_sign(session_id_, slot_, candidate_, final_, block_id));
    TRY_RESULT(weight, get_weight(vset));
    for (const auto& signature : signatures_) {
      const auto* validator = vset->get_validator(signature.validator_id);
      if (validator == nullptr) {
        return td::Status::Error("pq signatures: unknown validator_id");
      }
      const auto result = tos::pq::verify_mldsa44(
          std::string_view(message.data(), message.size()), tos::pq::simplex_sign_context,
          std::string_view(signature.signature.data(), signature.signature.size()), validator->pq_public_key);
      if (result == tos::pq::VerifyResult::malformed_input) {
        return td::Status::Error("pq signatures: malformed verification input");
      }
      if (result == tos::pq::VerifyResult::backend_error) {
        return td::Status::Error("pq signatures: verification backend failure");
      }
      if (result != tos::pq::VerifyResult::valid) {
        return td::Status::Error("pq signatures: invalid signature");
      }
    }
    if (weight < tos::quorum_threshold(vset->get_total_weight())) {
      return td::Status::Error("pq signatures: insufficient verified weight");
    }
    return weight;
  }

  std::vector<PQBlockSignature> signatures_;
  td::Bits256 session_id_;
  td::uint32 slot_;
  tos::tl_object_ptr<tos::tos_api::consensus_CandidateHashData> candidate_;
  bool final_;
};

td::Ref<BlockSignatureSet> BlockSignatureSet::create_ordinary(std::vector<tos::BlockSignature> signatures,
                                                              tos::CatchainSeqno cc_seqno,
                                                              td::uint32 validator_set_hash) {
  return td::Ref<BlockSignatureSetOrdinary>{true, std::move(signatures), cc_seqno, validator_set_hash};
}

td::Ref<BlockSignatureSet> BlockSignatureSet::create_simplex(
    std::vector<tos::BlockSignature> signatures, tos::CatchainSeqno cc_seqno, td::uint32 validator_set_hash,
    td::Bits256 session_id, td::uint32 slot, tos::tl_object_ptr<tos::tos_api::consensus_CandidateHashData> candidate) {
  return td::Ref<BlockSignatureSetSimplex>{true, std::move(signatures), cc_seqno, validator_set_hash, session_id,
                                           slot, std::move(candidate),  true};
}

td::Ref<BlockSignatureSet> BlockSignatureSet::create_simplex_approve(
    std::vector<tos::BlockSignature> signatures, tos::CatchainSeqno cc_seqno, td::uint32 validator_set_hash,
    td::Bits256 session_id, td::uint32 slot, tos::tl_object_ptr<tos::tos_api::consensus_CandidateHashData> candidate) {
  return td::Ref<BlockSignatureSetSimplex>{true, std::move(signatures), cc_seqno, validator_set_hash, session_id,
                                           slot, std::move(candidate),  false};
}

td::Result<td::Ref<BlockSignatureSet>> BlockSignatureSet::create_simplex_pq_final(
    std::vector<PQBlockSignature> signatures, tos::CatchainSeqno cc_seqno, td::uint32 validator_set_hash,
    td::Bits256 session_id, td::uint32 slot, tos::tl_object_ptr<tos::tos_api::consensus_CandidateHashData> candidate) {
  TRY_STATUS(validate_pq_signatures(signatures));
  if (candidate == nullptr) {
    return td::Status::Error("pq candidate data: null object");
  }
  const auto candidate_bytes = tos::serialize_tl_object(candidate, true);
  if (candidate_bytes.size() > pq::pq_candidate_data_max_bytes) {
    return td::Status::Error("pq candidate data: oversize");
  }
  return td::Ref<BlockSignatureSetSimplexPQ>{true, std::move(signatures), cc_seqno, validator_set_hash, session_id,
                                             slot, std::move(candidate),  true};
}

td::Result<td::Ref<BlockSignatureSet>> BlockSignatureSet::create_simplex_pq_approve(
    std::vector<PQBlockSignature> signatures, tos::CatchainSeqno cc_seqno, td::uint32 validator_set_hash,
    td::Bits256 session_id, td::uint32 slot, tos::tl_object_ptr<tos::tos_api::consensus_CandidateHashData> candidate) {
  TRY_STATUS(validate_pq_signatures(signatures));
  if (candidate == nullptr) {
    return td::Status::Error("pq candidate data: null object");
  }
  const auto candidate_bytes = tos::serialize_tl_object(candidate, true);
  if (candidate_bytes.size() > pq::pq_candidate_data_max_bytes) {
    return td::Status::Error("pq candidate data: oversize");
  }
  return td::Ref<BlockSignatureSetSimplexPQ>{true, std::move(signatures), cc_seqno, validator_set_hash, session_id,
                                             slot, std::move(candidate),  false};
}

td::Result<td::Ref<vm::Cell>> BlockSignatureSet::serialize_simplex_pq(
    const std::vector<PQBlockSignature>& signatures, tos::CatchainSeqno cc_seqno, td::uint32 validator_set_hash,
    tos::ValidatorWeight signature_weight, td::Bits256 session_id, td::uint32 slot,
    const tos::tl_object_ptr<tos::tos_api::consensus_CandidateHashData>& candidate) {
  return serialize_simplex_pq_cell(signatures, cc_seqno, validator_set_hash, signature_weight, session_id, slot,
                                   candidate);
}

td::Result<std::vector<PQBlockSignature>> BlockSignatureSet::export_pq_signatures() const {
  return td::Status::Error("not a post-quantum signature set");
}

td::Result<td::Bits256> BlockSignatureSet::pq_session_id() const {
  return td::Status::Error("not a post-quantum signature set");
}

td::Result<td::uint32> BlockSignatureSet::pq_slot() const {
  return td::Status::Error("not a post-quantum signature set");
}

td::Result<td::BufferSlice> BlockSignatureSet::pq_candidate_data() const {
  return td::Status::Error("not a post-quantum signature set");
}

static td::Result<std::vector<tos::BlockSignature>> unpack_signatures_dict(td::Ref<vm::Cell> dict_root) {
  std::vector<tos::BlockSignature> signatures;
  vm::Dictionary dict{dict_root, 16};  // HashmapE 16 CryptoSignaturePair
  unsigned i = 0;
  if (!dict.check_for_each([&](Ref<vm::CellSlice> cs_ref, td::ConstBitPtr key, int n) -> bool {
        if (key.get_int(n) != i || cs_ref->size_ext() != 256 + 4 + 256 + 256) {
          return false;
        }
        vm::CellSlice cs{*cs_ref};
        tos::NodeIdShort node_id;
        unsigned char signature[64];
        if (!(cs.fetch_bits_to(node_id)         // sig_pair$_ node_id_short:bits256
              && cs.fetch_ulong(4) == 5         // ed25519_signature#5
              && cs.fetch_bytes(signature, 64)  // R:bits256 s:bits256
              && !cs.size_ext())) {
          return false;
        }
        signatures.emplace_back(node_id, td::BufferSlice{td::Slice{signature, 64}});
        ++i;
        return i <= BlockSignatureSet::MAX_SIGNATURES;
      })) {
    return td::Status::Error("failed to parse signatures dict");
  }
  return signatures;
}

static td::Result<std::vector<PQBlockSignature>> unpack_pq_signatures_dict(td::Ref<vm::CellSlice> encoded_dict,
                                                                           std::size_t declared_count) {
  if (!pq::pq_block_signatures_accepts_signer_count(declared_count)) {
    return td::Status::Error("pq signatures: signer count exceeds maximum");
  }
  vm::CellSlice dict_slice{*encoded_dict};
  const auto present = dict_slice.fetch_ulong(1);
  if (present < 0) {
    return td::Status::Error("pq signatures: malformed dictionary root");
  }
  td::Ref<vm::Cell> dict_root;
  if (present != 0) {
    if (dict_slice.size_refs() != 1) {
      return td::Status::Error("pq signatures: malformed dictionary root");
    }
    dict_root = dict_slice.fetch_ref();
  } else if (dict_slice.size_refs() != 0) {
    return td::Status::Error("pq signatures: malformed empty dictionary");
  }

  std::vector<PQBlockSignature> signatures;
  std::set<tos::ValidatorId> validator_ids;
  std::string failure;
  if (dict_root.not_null()) {
    vm::Dictionary dict{dict_root, 16};
    std::size_t expected_index = 0;
    const auto valid = dict.check_for_each([&](Ref<vm::CellSlice> value_ref, td::ConstBitPtr key, int key_bits) {
      if (static_cast<std::size_t>(key.get_uint(key_bits)) != expected_index) {
        failure = "pq signatures: dictionary index";
        return false;
      }
      vm::CellSlice value{*value_ref};
      gen::PQBlockSignaturePair::Record pair;
      if (!gen::t_PQBlockSignaturePair.unpack(value, pair) || !value.empty_ext()) {
        failure = "pq signatures: malformed dictionary value";
        return false;
      }
      const auto algorithm_id = static_cast<tos::pq::PQAlgorithmId>(pair.algorithm_id);
      if (!tos::pq::is_admitted(algorithm_id)) {
        failure = "pq signatures: unsupported algorithm";
        return false;
      }
      auto decoded = tos::pq::unpack_pq_bytes(pair.signature, tos::pq::mldsa44_signature_bytes);
      if (decoded.is_error()) {
        if (decoded.error().message() == "pq-bytes: oversize") {
          failure = "pq signatures: signature length exceeds 2420";
        } else {
          failure = PSTRING() << "pq signatures: noncanonical PQBytes: " << decoded.error().message();
        }
        return false;
      }
      auto signature = decoded.move_as_ok();
      if (signature.size() != tos::pq::mldsa44_signature_bytes) {
        failure = PSTRING() << "pq signatures: signature length " << signature.size() << ", expected 2420";
        return false;
      }
      tos::ValidatorId validator_id{pair.validator_id};
      if (!validator_ids.insert(validator_id).second) {
        failure = "pq signatures: duplicate validator_id";
        return false;
      }
      signatures.push_back(PQBlockSignature{validator_id, algorithm_id, std::move(signature)});
      ++expected_index;
      return true;
    });
    if (!valid) {
      return td::Status::Error(failure.empty() ? "pq signatures: malformed dictionary" : failure);
    }
  }
  if (signatures.size() < declared_count) {
    return td::Status::Error("pq signatures: dictionary missing entry");
  }
  if (signatures.size() > declared_count) {
    return td::Status::Error("pq signatures: dictionary extra entry");
  }
  return signatures;
}

static td::Result<unsigned> block_signatures_tag(const td::Ref<vm::Cell>& cell) {
  if (cell.is_null()) {
    return td::Status::Error("cell is null");
  }
  try {
    vm::CellSlice slice(vm::NoVm(), cell);
    if (slice.size() < 8) {
      return td::Status::Error("block signatures: missing constructor");
    }
    return static_cast<unsigned>(slice.prefetch_ulong(8));
  } catch (vm::VmError& e) {
    return e.as_status();
  } catch (const std::exception& e) {
    return td::Status::Error(PSTRING() << "block signatures: failed to read constructor: " << e.what());
  } catch (...) {
    return td::Status::Error("block signatures: failed to read constructor: unknown exception");
  }
}

td::Result<td::Ref<BlockSignatureSet>> BlockSignatureSet::fetch(td::Ref<vm::Cell> cell,
                                                                tos::ValidatorWeight& total_weight) {
  if (cell.is_null()) {
    return td::Status::Error("cell is null");
  }
  try {
    if (gen::BlockSignatures::Record_block_signatures_ordinary rec; gen::unpack_cell(cell, rec)) {
      TRY_RESULT(signatures, unpack_signatures_dict(rec.signatures->prefetch_ref()));
      auto sig_set = create_ordinary(std::move(signatures), rec.catchain_seqno, rec.validator_list_hash_short);
      if (sig_set->get_size() != rec.sig_count) {
        return td::Status::Error("signature count mismatch");
      }
      total_weight = rec.sig_weight;
      return sig_set;
    }
    if (gen::BlockSignatures::Record_block_signatures_simplex rec; gen::unpack_cell(cell, rec)) {
      TRY_RESULT(signatures, unpack_signatures_dict(rec.signatures->prefetch_ref()));
      vm::CellSlice candidate_cs = vm::load_cell_slice(rec.candidate_data);
      TRY_RESULT(candidate_data, vm::CellString::load(candidate_cs));
      TRY_RESULT(candidate, tos::fetch_tl_object<tos::tos_api::consensus_CandidateHashData>(candidate_data, true));
      auto sig_set = create_simplex(std::move(signatures), rec.catchain_seqno, rec.validator_list_hash_short,
                                    rec.session_id, rec.slot, std::move(candidate));
      if (sig_set->get_size() != rec.sig_count) {
        return td::Status::Error("signature count mismatch");
      }
      total_weight = rec.sig_weight;
      return sig_set;
    }
    if (gen::BlockSignatures::Record_block_signatures_simplex_pq rec; gen::unpack_cell(cell, rec)) {
      if (!pq::pq_block_signatures_accepts_signer_count(rec.sig_count)) {
        return td::Status::Error("pq signatures: signer count exceeds maximum");
      }
      TRY_RESULT(serialized, vm::std_boc_serialize(cell, 0));
      if (!pq::pq_block_signatures_accepts_serialized_size(serialized.size())) {
        return td::Status::Error("pq signatures: serialized bytes exceed maximum");
      }
      TRY_RESULT(signatures, unpack_pq_signatures_dict(rec.signatures, rec.sig_count));
      TRY_RESULT(candidate, parse_candidate_data_strict(rec.candidate_data));
      total_weight = rec.sig_weight;
      return td::Ref<BlockSignatureSetSimplexPQ>{true,
                                                 std::move(signatures),
                                                 rec.catchain_seqno,
                                                 rec.validator_list_hash_short,
                                                 rec.session_id,
                                                 rec.slot,
                                                 std::move(candidate),
                                                 true};
    }
    return td::Status::Error("failed to unpack signature set");
  } catch (vm::VmError& e) {
    return e.as_status();
  } catch (const std::exception& e) {
    return td::Status::Error(PSTRING() << "failed to unpack signature set: " << e.what());
  } catch (...) {
    return td::Status::Error("failed to unpack signature set: unknown exception");
  }
}

td::Result<td::Ref<BlockSignatureSet>> BlockSignatureSet::fetch(td::Ref<vm::Cell> cell, td::Ref<ValidatorSet> vset) {
  try {
    TRY_RESULT(tag, block_signatures_tag(cell));
    const auto validators = vset->export_vector();
    bool has_pq = false;
    bool has_classical = false;
    for (const auto& validator : validators) {
      has_pq |= validator.is_pq();
      has_classical |= !validator.is_pq();
    }
    if (has_pq && has_classical) {
      return td::Status::Error("mixed validator set has no admitted signature carrier");
    }
    if (has_pq && tag != 0x13) {
      return td::Status::Error("unsupported carrier for post-quantum validator set");
    }
    if (!has_pq && tag == 0x13) {
      return td::Status::Error("post-quantum carrier for classical validator set");
    }
    tos::ValidatorWeight total_weight;
    TRY_RESULT(sig_set, fetch(std::move(cell), total_weight));
    TRY_RESULT(expected_weight, sig_set->get_weight(vset));
    if (expected_weight != total_weight) {
      return td::Status::Error("signature weight mismatch");
    }
    return sig_set;
  } catch (vm::VmError& e) {
    return e.as_status();
  } catch (const std::exception& e) {
    return td::Status::Error(PSTRING() << "failed to validate signature set: " << e.what());
  } catch (...) {
    return td::Status::Error("failed to validate signature set: unknown exception");
  }
}

td::Ref<BlockSignatureSet> BlockSignatureSet::fetch(
    const std::vector<tos::tl_object_ptr<tos::tos_api::tosNode_blockSignature>>& f, tos::CatchainSeqno cc_seqno,
    td::uint32 validator_set_hash) {
  std::vector<tos::BlockSignature> signatures;
  for (auto& s : f) {
    signatures.emplace_back(s->who_, s->signature_.clone());
  }
  return create_ordinary(std::move(signatures), cc_seqno, validator_set_hash);
}

td::Ref<BlockSignatureSet> BlockSignatureSet::fetch(const tos::tl_object_ptr<tos::tos_api::tosNode_SignatureSet>& f) {
  td::Ref<BlockSignatureSet> sig_set;
  tos::tos_api::downcast_call(
      *f, td::overloaded(
              [&](const tos::tos_api::tosNode_signatureSet_ordinary& obj) {
                std::vector<tos::BlockSignature> signatures;
                for (auto& s : obj.signatures_) {
                  signatures.emplace_back(s->who_, s->signature_.clone());
                }
                sig_set = create_ordinary(std::move(signatures), obj.cc_seqno_, obj.validator_set_hash_);
              },
              [&](const tos::tos_api::tosNode_signatureSet_simplex& obj) {
                std::vector<tos::BlockSignature> signatures;
                for (auto& s : obj.signatures_) {
                  signatures.emplace_back(s->who_, s->signature_.clone());
                }
                sig_set = td::Ref<BlockSignatureSetSimplex>(true, std::move(signatures), obj.cc_seqno_,
                                                            obj.validator_set_hash_, obj.session_id_, obj.slot_,
                                                            clone_tl(obj.candidate_), obj.final_);
              },
              [&](const tos::tos_api::tosNode_signatureSet_simplexPq&) {
                // The legacy adapter cannot report why a variable-size PQ
                // carrier is malformed. Production callers use
                // fetch_node_checked instead.
                sig_set = {};
              }));
  return sig_set;
}

td::Result<td::Ref<BlockSignatureSet>> BlockSignatureSet::fetch(
    const tos::tl_object_ptr<tos::lite_api::liteServer_SignatureSet>& f) {
  return fetch_lite_checked(f);
}

template <class Signature>
static td::Result<std::vector<PQBlockSignature>> fetch_pq_tl_signatures_checked(
    const std::vector<tos::tl_object_ptr<Signature>>& input) {
  if (!pq::pq_block_signatures_accepts_signer_count(input.size())) {
    return td::Status::Error("pq tl: signer_count");
  }
  std::vector<PQBlockSignature> signatures;
  signatures.reserve(input.size());
  for (const auto& pair : input) {
    if (pair == nullptr) {
      return td::Status::Error("pq tl: null_signature_pair");
    }
    if (pair->algorithm_id_ < 0 || pair->algorithm_id_ > std::numeric_limits<td::uint16>::max()) {
      return td::Status::Error("pq tl: algorithm_range");
    }
    const auto algorithm = static_cast<tos::pq::PQAlgorithmId>(static_cast<td::uint16>(pair->algorithm_id_));
    if (!tos::pq::is_admitted(algorithm)) {
      return td::Status::Error("pq tl: unsupported_algorithm");
    }
    if (pair->signature_.size() != tos::pq::mldsa44_signature_bytes) {
      return td::Status::Error("pq tl: signature_length");
    }
    signatures.push_back(PQBlockSignature{tos::ValidatorId{pair->validator_id_}, algorithm, pair->signature_.clone()});
  }
  TRY_STATUS(validate_pq_signatures(signatures));
  return signatures;
}

td::Result<td::Ref<BlockSignatureSet>> BlockSignatureSet::fetch_pq_node_checked(
    const tos::tl_object_ptr<tos::tos_api::tosNode_SignatureSet>& f) {
  if (f == nullptr || f->get_id() != tos::tos_api::tosNode_signatureSet_simplexPq::ID) {
    return td::Status::Error("pq tl: wrong_node_constructor");
  }
  const auto& obj = static_cast<const tos::tos_api::tosNode_signatureSet_simplexPq&>(*f);
  TRY_RESULT(signatures, fetch_pq_tl_signatures_checked(obj.signatures_));
  if (obj.candidate_ == nullptr) {
    return td::Status::Error("pq tl: candidate_missing");
  }
  const auto candidate_bytes = tos::serialize_tl_object(obj.candidate_, true);
  if (candidate_bytes.size() > pq::pq_candidate_data_max_bytes) {
    return td::Status::Error("pq tl: candidate_oversize");
  }
  return obj.final_ ? create_simplex_pq_final(std::move(signatures), obj.cc_seqno_, obj.validator_set_hash_,
                                              obj.session_id_, obj.slot_, clone_tl(obj.candidate_))
                    : create_simplex_pq_approve(std::move(signatures), obj.cc_seqno_, obj.validator_set_hash_,
                                                obj.session_id_, obj.slot_, clone_tl(obj.candidate_));
}

td::Result<td::Ref<BlockSignatureSet>> BlockSignatureSet::fetch_pq_lite_checked(
    const tos::tl_object_ptr<tos::lite_api::liteServer_SignatureSet>& f) {
  if (f == nullptr || f->get_id() != tos::lite_api::liteServer_signatureSet_simplexPq::ID) {
    return td::Status::Error("pq tl: wrong_lite_constructor");
  }
  const auto& obj = static_cast<const tos::lite_api::liteServer_signatureSet_simplexPq&>(*f);
  TRY_RESULT(signatures, fetch_pq_tl_signatures_checked(obj.signatures_));
  if (obj.candidate_.size() > pq::pq_candidate_data_max_bytes) {
    return td::Status::Error("pq tl: candidate_oversize");
  }
  auto candidate = tos::fetch_tl_object<tos::tos_api::consensus_CandidateHashData>(obj.candidate_.clone(), true);
  if (candidate.is_error()) {
    return candidate.move_as_error_prefix("pq tl: candidate_invalid: ");
  }
  return create_simplex_pq_final(std::move(signatures), obj.cc_seqno_, obj.validator_set_hash_, obj.session_id_,
                                 obj.slot_, candidate.move_as_ok());
}

static td::Status validate_classical_tl_signatures(const std::vector<tos::BlockSignature>& signatures) {
  if (signatures.size() > BlockSignatureSet::MAX_SIGNATURES) {
    return td::Status::Error("classical tl: signer_count");
  }
  std::set<tos::NodeIdShort> validators;
  for (const auto& signature : signatures) {
    if (signature.signature.size() != 64) {
      return td::Status::Error("classical tl: signature_length");
    }
    if (!validators.insert(signature.node).second) {
      return td::Status::Error("classical tl: duplicate_validator_id");
    }
  }
  return td::Status::OK();
}

td::Result<td::Ref<BlockSignatureSet>> BlockSignatureSet::fetch_legacy_checked(
    const std::vector<tos::tl_object_ptr<tos::tos_api::tosNode_blockSignature>>& input, tos::CatchainSeqno cc_seqno,
    td::uint32 validator_set_hash) {
  std::vector<tos::BlockSignature> signatures;
  signatures.reserve(input.size());
  for (const auto& signature : input) {
    if (signature == nullptr) {
      return td::Status::Error("classical tl: null_signature_pair");
    }
    signatures.emplace_back(signature->who_, signature->signature_.clone());
  }
  TRY_STATUS(validate_classical_tl_signatures(signatures));
  return create_ordinary(std::move(signatures), cc_seqno, validator_set_hash);
}

td::Result<td::Ref<BlockSignatureSet>> BlockSignatureSet::fetch_node_checked(
    const tos::tl_object_ptr<tos::tos_api::tosNode_SignatureSet>& f) {
  if (f == nullptr) {
    return td::Status::Error("node signature set: null constructor");
  }
  try {
    if (f->get_id() == tos::tos_api::tosNode_signatureSet_simplexPq::ID) {
      return fetch_pq_node_checked(f);
    }
    td::Result<td::Ref<BlockSignatureSet>> result{td::Status::Error("node signature set: unknown constructor")};
    tos::tos_api::downcast_call(
        *f, td::overloaded(
                [&](const tos::tos_api::tosNode_signatureSet_ordinary& obj) {
                  std::vector<tos::BlockSignature> signatures;
                  signatures.reserve(obj.signatures_.size());
                  for (const auto& signature : obj.signatures_) {
                    if (signature == nullptr) {
                      result = td::Status::Error("classical tl: null_signature_pair");
                      return;
                    }
                    signatures.emplace_back(signature->who_, signature->signature_.clone());
                  }
                  auto status = validate_classical_tl_signatures(signatures);
                  if (status.is_error()) {
                    result = std::move(status);
                    return;
                  }
                  result = create_ordinary(std::move(signatures), obj.cc_seqno_, obj.validator_set_hash_);
                },
                [&](const tos::tos_api::tosNode_signatureSet_simplex& obj) {
                  if (obj.candidate_ == nullptr) {
                    result = td::Status::Error("classical tl: candidate_missing");
                    return;
                  }
                  std::vector<tos::BlockSignature> signatures;
                  signatures.reserve(obj.signatures_.size());
                  for (const auto& signature : obj.signatures_) {
                    if (signature == nullptr) {
                      result = td::Status::Error("classical tl: null_signature_pair");
                      return;
                    }
                    signatures.emplace_back(signature->who_, signature->signature_.clone());
                  }
                  auto status = validate_classical_tl_signatures(signatures);
                  if (status.is_error()) {
                    result = std::move(status);
                    return;
                  }
                  result = td::Ref<BlockSignatureSetSimplex>(true, std::move(signatures), obj.cc_seqno_,
                                                             obj.validator_set_hash_, obj.session_id_, obj.slot_,
                                                             clone_tl(obj.candidate_), obj.final_);
                },
                [&](const tos::tos_api::tosNode_signatureSet_simplexPq&) {
                  result = td::Status::Error("node signature set: internal dispatch error");
                }));
    return result;
  } catch (const vm::VmError& error) {
    return error.as_status().move_as_error_prefix("node signature set: ");
  } catch (const std::exception& error) {
    return td::Status::Error(PSTRING() << "node signature set: " << error.what());
  } catch (...) {
    return td::Status::Error("node signature set: unknown exception");
  }
}

td::Result<td::Ref<BlockSignatureSet>> BlockSignatureSet::fetch_lite_checked(
    const tos::tl_object_ptr<tos::lite_api::liteServer_SignatureSet>& f) {
  if (f == nullptr) {
    return td::Status::Error("lite signature set: null constructor");
  }
  try {
    if (f->get_id() == tos::lite_api::liteServer_signatureSet_simplexPq::ID) {
      return fetch_pq_lite_checked(f);
    }
    td::Result<td::Ref<BlockSignatureSet>> result{td::Status::Error("lite signature set: unknown constructor")};
    tos::lite_api::downcast_call(
        *f, td::overloaded(
                [&](const tos::lite_api::liteServer_signatureSet_ordinary& obj) {
                  std::vector<tos::BlockSignature> signatures;
                  signatures.reserve(obj.signatures_.size());
                  for (const auto& signature : obj.signatures_) {
                    if (signature == nullptr) {
                      result = td::Status::Error("classical tl: null_signature_pair");
                      return;
                    }
                    signatures.emplace_back(signature->node_id_short_, signature->signature_.clone());
                  }
                  auto status = validate_classical_tl_signatures(signatures);
                  if (status.is_error()) {
                    result = std::move(status);
                    return;
                  }
                  result = create_ordinary(std::move(signatures), obj.catchain_seqno_, obj.validator_set_hash_);
                },
                [&](const tos::lite_api::liteServer_signatureSet_simplex& obj) {
                  std::vector<tos::BlockSignature> signatures;
                  signatures.reserve(obj.signatures_.size());
                  for (const auto& signature : obj.signatures_) {
                    if (signature == nullptr) {
                      result = td::Status::Error("classical tl: null_signature_pair");
                      return;
                    }
                    signatures.emplace_back(signature->node_id_short_, signature->signature_.clone());
                  }
                  auto status = validate_classical_tl_signatures(signatures);
                  if (status.is_error()) {
                    result = std::move(status);
                    return;
                  }
                  auto candidate =
                      tos::fetch_tl_object<tos::tos_api::consensus_CandidateHashData>(obj.candidate_.clone(), true);
                  if (candidate.is_error()) {
                    result = candidate.move_as_error_prefix("failed to unpack candidate data: ");
                    return;
                  }
                  result = create_simplex(std::move(signatures), obj.cc_seqno_, obj.validator_set_hash_,
                                          obj.session_id_, obj.slot_, candidate.move_as_ok());
                },
                [&](const tos::lite_api::liteServer_signatureSet_simplexPq&) {
                  result = td::Status::Error("lite signature set: internal dispatch error");
                }));
    return result;
  } catch (const vm::VmError& error) {
    return error.as_status().move_as_error_prefix("lite signature set: ");
  } catch (const std::exception& error) {
    return td::Status::Error(PSTRING() << "lite signature set: " << error.what());
  } catch (...) {
    return td::Status::Error("lite signature set: unknown exception");
  }
}

}  // namespace block
