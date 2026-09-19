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
#pragma once

#include "keys/encryptor.h"
#include "tos/tos-types.h"

namespace block {

class Config;
struct TotalValidatorSet;

class ValidatorSet : public td::CntObject {
 public:
  // Membership is asked by stable validator identity, never by an ADNL identity and
  // never by a key identity. Rotating a validator's consensus key must not move it in
  // or out of the set, which is only true if this is keyed on validator_id.
  const tos::ValidatorDescr* get_validator(const tos::ValidatorId& id) const;
  bool is_validator(const tos::ValidatorId& id) const;
  // Separate from membership on purpose: this answers "is this key currently in the
  // set", which is a different question from "is this validator a member".
  const tos::ValidatorDescr* get_validator_by_key_id(const tos::ConsensusKeyId& key_id) const;
  tos::CatchainSeqno get_catchain_seqno() const {
    return cc_seqno_;
  }
  td::uint32 get_validator_set_hash() const {
    return hash_;
  }
  tos::ShardIdFull get_shard() const {
    return for_;
  }
  tos::ValidatorWeight get_total_weight() const {
    return total_weight_;
  }
  std::vector<tos::ValidatorDescr> export_vector() const;
  ValidatorSet* make_copy() const override;
  ValidatorSet(tos::CatchainSeqno cc_seqno, tos::ShardIdFull from, std::vector<tos::ValidatorDescr> nodes);

 private:
  tos::CatchainSeqno cc_seqno_;
  tos::ShardIdFull for_;
  td::uint32 hash_;
  tos::ValidatorWeight total_weight_;
  std::vector<tos::ValidatorDescr> ids_;
  std::vector<std::pair<tos::ValidatorId, size_t>> ids_map_;
  std::vector<std::pair<tos::ConsensusKeyId, size_t>> key_id_map_;
};

class ValidatorSetCompute {
 public:
  td::Ref<ValidatorSet> get_validator_set(tos::ShardIdFull shard, tos::UnixTime utime, tos::CatchainSeqno cc) const;
  td::Ref<ValidatorSet> get_next_validator_set(tos::ShardIdFull shard, tos::UnixTime utime,
                                               tos::CatchainSeqno cc) const;
  td::Status init(const Config* config);
  ValidatorSetCompute() = default;

 private:
  const Config* config_{nullptr};
  std::shared_ptr<TotalValidatorSet> cur_validators_, next_validators_;
  td::Ref<ValidatorSet> compute_validator_set(tos::ShardIdFull shard, const TotalValidatorSet& vset, tos::UnixTime time,
                                              tos::CatchainSeqno cc_seqno) const;
};

}  // namespace block
