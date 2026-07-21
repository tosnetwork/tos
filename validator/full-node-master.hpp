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
#pragma once

#include "full-node-master.h"

namespace tos {

namespace validator {

namespace fullnode {

class FullNodeMasterImpl : public FullNodeMaster {
 public:
  static constexpr td::uint32 proto_version_major() {
    return 1;
  }
  static constexpr td::uint32 proto_version_minor() {
    return 0;
  }
  void start_up() override;

  template <class T>
  void process_query(adnl::AdnlNodeIdShort src, T &query, td::Promise<td::BufferSlice> promise) {
    promise.set_error(td::Status::Error(ErrorCode::error, "unknown query"));
  }
  void process_query(adnl::AdnlNodeIdShort src, tos_api::tosNode_getNextBlockDescription &query,
                     td::Promise<td::BufferSlice> promise);
  void process_query(adnl::AdnlNodeIdShort src, tos_api::tosNode_prepareBlockProof &query,
                     td::Promise<td::BufferSlice> promise);
  void process_query(adnl::AdnlNodeIdShort src, tos_api::tosNode_prepareKeyBlockProof &query,
                     td::Promise<td::BufferSlice> promise);
  void process_query(adnl::AdnlNodeIdShort src, tos_api::tosNode_downloadBlockProof &query,
                     td::Promise<td::BufferSlice> promise);
  void process_query(adnl::AdnlNodeIdShort src, tos_api::tosNode_downloadBlockProofLink &query,
                     td::Promise<td::BufferSlice> promise);
  void process_query(adnl::AdnlNodeIdShort src, tos_api::tosNode_downloadKeyBlockProof &query,
                     td::Promise<td::BufferSlice> promise);
  void process_query(adnl::AdnlNodeIdShort src, tos_api::tosNode_downloadKeyBlockProofLink &query,
                     td::Promise<td::BufferSlice> promise);
  void process_query(adnl::AdnlNodeIdShort src, tos_api::tosNode_prepareBlock &query,
                     td::Promise<td::BufferSlice> promise);
  void process_query(adnl::AdnlNodeIdShort src, tos_api::tosNode_downloadBlock &query,
                     td::Promise<td::BufferSlice> promise);
  void process_query(adnl::AdnlNodeIdShort src, tos_api::tosNode_downloadBlockFull &query,
                     td::Promise<td::BufferSlice> promise);
  void process_query(adnl::AdnlNodeIdShort src, tos_api::tosNode_downloadNextBlockFull &query,
                     td::Promise<td::BufferSlice> promise);
  void process_query(adnl::AdnlNodeIdShort src, tos_api::tosNode_downloadNextBlocksFull &query,
                     td::Promise<td::BufferSlice> promise);
  void process_query(adnl::AdnlNodeIdShort src, tos_api::tosNode_prepareZeroState &query,
                     td::Promise<td::BufferSlice> promise);
  void process_query(adnl::AdnlNodeIdShort src, tos_api::tosNode_preparePersistentState &query,
                     td::Promise<td::BufferSlice> promise);
  void process_query(adnl::AdnlNodeIdShort src, tos_api::tosNode_getNextKeyBlockIds &query,
                     td::Promise<td::BufferSlice> promise);
  void process_query(adnl::AdnlNodeIdShort src, tos_api::tosNode_downloadZeroState &query,
                     td::Promise<td::BufferSlice> promise);
  void process_query(adnl::AdnlNodeIdShort src, tos_api::tosNode_getCapabilities &query,
                     td::Promise<td::BufferSlice> promise);
  void process_query(adnl::AdnlNodeIdShort src, tos_api::tosNode_slave_sendExtMessage &query,
                     td::Promise<td::BufferSlice> promise);
  void process_query(adnl::AdnlNodeIdShort src, tos_api::tosNode_getArchiveInfo &query,
                     td::Promise<td::BufferSlice> promise);
  void process_query(adnl::AdnlNodeIdShort src, tos_api::tosNode_getShardArchiveInfo &query,
                     td::Promise<td::BufferSlice> promise);
  void process_query(adnl::AdnlNodeIdShort src, tos_api::tosNode_getArchiveSlice &query,
                     td::Promise<td::BufferSlice> promise);

  void process_query(adnl::AdnlNodeIdShort src, tos_api::tosNode_downloadPersistentStateSliceV2 &query,
                     td::Promise<td::BufferSlice> promise);
  void process_query(adnl::AdnlNodeIdShort src, tos_api::tosNode_getPersistentStateSizeV2 &query,
                     td::Promise<td::BufferSlice> promise);

  // void process_query(adnl::AdnlNodeIdShort src, tos_api::tosNode_prepareNextKeyBlockProof &query,
  //                   td::Promise<td::BufferSlice> promise);
  void receive_query(adnl::AdnlNodeIdShort src, td::BufferSlice query, td::Promise<td::BufferSlice> promise);

  FullNodeMasterImpl(adnl::AdnlNodeIdShort adnl_id, td::uint16 port, FileHash zero_state_file_hash,
                     td::actor::ActorId<keyring::Keyring> keyring, td::actor::ActorId<adnl::Adnl> adnl,
                     td::actor::ActorId<ValidatorManagerInterface> validator_manager);

 private:
  adnl::AdnlNodeIdShort adnl_id_;
  td::uint16 port_;
  FileHash zero_state_file_hash_;

  td::actor::ActorId<keyring::Keyring> keyring_;
  td::actor::ActorId<adnl::Adnl> adnl_;
  td::actor::ActorId<ValidatorManagerInterface> validator_manager_;
};

}  // namespace fullnode

}  // namespace validator

}  // namespace tos
