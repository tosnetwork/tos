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

    Copyright 2017-2020 Telegram Systems LLP
    Copyright 2025-2026 TOS Blockchain Teams
*/

#include "block/validator-session-id.h"

#include "session-compat.h"

namespace tos::validator::consensus {

ValidatorSessionOptions::ValidatorSessionOptions(const ValidatorSessionConfig &conf)
    : catchain_opts(conf.catchain_opts)
    , round_candidates(conf.round_candidates)
    , next_candidate_delay(conf.next_candidate_delay)
    , round_attempt_duration(conf.round_attempt_duration)
    , max_round_attempts(conf.max_round_attempts)
    , max_block_size(conf.max_block_size)
    , max_collated_data_size(conf.max_collated_data_size)
    , new_catchain_ids(conf.new_catchain_ids)
    , use_quic(conf.use_quic)
    , proto_version(conf.proto_version) {
}

td::Bits256 ValidatorSessionOptions::get_hash() const {
  ValidatorSessionConfig config;
  config.catchain_opts = catchain_opts;
  config.round_candidates = round_candidates;
  config.next_candidate_delay = next_candidate_delay;
  config.round_attempt_duration = round_attempt_duration;
  config.max_round_attempts = max_round_attempts;
  config.max_block_size = max_block_size;
  config.max_collated_data_size = max_collated_data_size;
  config.new_catchain_ids = new_catchain_ids;
  config.use_quic = use_quic;
  config.proto_version = proto_version;
  return block::validator_session_options_hash(config);
}

}  // namespace tos::validator::consensus
