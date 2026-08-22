/*
    This file is part of TOS Blockchain source code.

    TOS Blockchain is free software; you can redistribute it and/or
    modify it under the terms of the GNU General Public License
    as published by the Free Software Foundation; either version 2
    of the License, or (at your option) any later version.

    TOS Blockchain is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with TOS Blockchain.  If not, see <http://www.gnu.org/licenses/>.

    In addition, as a special exception, the copyright holders give permission
    to link the code of portions of this program with the OpenSSL library.
    You must obey the GNU General Public License in all respects for all
    of the code used other than OpenSSL. If you modify file(s) with this
    exception, you may extend this exception to your version of the file(s),
    but you are not obligated to do so. If you do not wish to do so, delete this
    exception statement from your version. If you delete this exception statement
    from all source files in the program, then also delete it here.
*/
#include "common/delay.h"
#include "common/refint.h"
#include "block/block-auto.h"
#include "block/block-parse.h"
#include "smc-envelope/ManualDns.h"
#include "td/utils/overloaded.h"
#include "vm/boc.h"
#include "vm/cellslice.h"

#include "DNSResolver.h"

static const double CACHE_TIMEOUT_HARD = 300.0;
static const double CACHE_TIMEOUT_SOFT = 270.0;

DNSResolver::DNSResolver(td::actor::ActorId<toslib::ToslibClientWrapper> toslib_client)
    : toslib_client_(std::move(toslib_client)) {}

void DNSResolver::start_up() { sync(); }

void DNSResolver::sync() {
  auto obj = toslib_api::make_object<toslib_api::sync>();
  auto P = td::PromiseCreator::lambda([SelfId = actor_id(this)](
                                          td::Result<toslib_api::object_ptr<toslib_api::tos_blockIdExt>> R) {
    if (R.is_error()) {
      LOG(WARNING) << "Sync error: " << R.move_as_error();
      tos::delay_action([SelfId]() { td::actor::send_closure(SelfId, &DNSResolver::sync); }, td::Timestamp::in(5.0));
    }
  });
  td::actor::send_closure(toslib_client_, &toslib::ToslibClientWrapper::send_request<toslib_api::sync>, std::move(obj),
                          std::move(P));
}

void DNSResolver::resolve(std::string host, td::Promise<std::string> promise) {
  if (host.size() > tos::DnsInterface::get_default_max_name_size()) {
    promise.set_error(td::Status::Error("DNS host name is too long"));
    return;
  }
  auto it = cache_.find(host);
  if (it != cache_.end()) {
    const tos::dns::DnsCacheEntry &entry = it->second;
    double now = td::Time::now();
    if (now < entry.expires_at_) {
      promise.set_result(entry.address_);
      promise.reset();
      // refresh in the background only near expiry
      if (now < entry.expires_at_ - (CACHE_TIMEOUT_HARD - CACHE_TIMEOUT_SOFT)) {
        return;
      }
    }
  }

  // Coalesce equal lookups and bound the number of callback chains retained
  // by a stalled or hostile upstream. A near-expiry cache refresh has an empty
  // promise but still occupies one host slot, preventing duplicate refreshes.
  auto pending_it = pending_.find(host);
  if (pending_it != pending_.end()) {
    if (promise) {
      if (pending_it->second.size() >= max_waiters_per_host_) {
        promise.set_error(td::Status::Error("too many concurrent DNS waiters for this host"));
      } else {
        pending_it->second.push_back(std::move(promise));
      }
    }
    return;
  }
  if (pending_.size() >= max_inflight_hosts_) {
    if (promise) {
      promise.set_error(td::Status::Error("too many concurrent DNS host lookups"));
    }
    return;
  }
  auto &waiters = pending_[host];
  if (promise) {
    waiters.push_back(std::move(promise));
  }

  td::Bits256 category = td::sha256_bits256(td::Slice("site", 4));
  auto obj = toslib_api::make_object<toslib_api::dns_resolve>(nullptr, host, category, tos::DNS_MAX_RESOLVER_HOPS);
  auto P = td::PromiseCreator::lambda([SelfId = actor_id(this), host = std::move(host)](
                                          td::Result<toslib_api::object_ptr<toslib_api::dns_resolved>> R) mutable {
    if (R.is_error()) {
      td::actor::send_closure(SelfId, &DNSResolver::finish_error, std::move(host), R.move_as_error(), false);
      return;
    }
    auto obj = R.move_as_ok();
    std::string result;
    if (!obj->entries_.empty()) {
      toslib_api::downcast_call(
          *obj->entries_[0]->entry_,
          td::overloaded(
              [&](toslib_api::dns_entryDataAdnlAddress &x) {
                auto R = tos::adnl::AdnlNodeIdShort::parse(x.adnl_address_->adnl_address_);
                if (R.is_ok()) {
                  tos::adnl::AdnlNodeIdShort id = R.move_as_ok();
                  result = id.serialize() + ".adnl";
                }
              },
              [&](toslib_api::dns_entryDataStorageAddress &x) { result = td::to_lower(x.bag_id_.to_hex()) + ".bag"; },
              [&](auto &x) {}));
    }
    if (result.empty()) {
      td::actor::send_closure(SelfId, &DNSResolver::finish_error, std::move(host), td::Status::Error("no DNS entries"),
                              false);
      return;
    }
    if (!obj->block_id_) {
      td::actor::send_closure(SelfId, &DNSResolver::finish_error, std::move(host),
                              td::Status::Error("resolution block missing; cannot verify domain lifecycle"), true);
      return;
    }
    std::vector<std::string> resolver_path;
    resolver_path.reserve(obj->resolver_path_.size());
    for (auto &resolver : obj->resolver_path_) {
      if (!resolver) {
        td::actor::send_closure(SelfId, &DNSResolver::finish_error, std::move(host),
                                td::Status::Error("invalid resolver path; cannot verify domain lifecycle"), true);
        return;
      }
      resolver_path.push_back(resolver->account_address_);
    }
    auto r_domain_path = tos::dns::select_tos_domain_item(host, resolver_path);
    if (r_domain_path.is_error()) {
      td::actor::send_closure(SelfId, &DNSResolver::finish_error, std::move(host), r_domain_path.move_as_error(), true);
      return;
    }
    td::actor::send_closure(SelfId, &DNSResolver::check_lifecycle, std::move(host), std::move(result),
                            r_domain_path.move_as_ok(), std::move(obj->block_id_));
  });
  td::actor::send_closure(toslib_client_, &toslib::ToslibClientWrapper::send_request<toslib_api::dns_resolve>,
                          std::move(obj), std::move(P));
}

namespace {

td::Result<td::int64> stack_number(const toslib_api::object_ptr<toslib_api::tvm_StackEntry> &entry) {
  auto *num = dynamic_cast<toslib_api::tvm_stackEntryNumber *>(entry.get());
  if (num == nullptr || !num->number_) {
    return td::Status::Error("stack entry is not a number");
  }
  return td::to_integer_safe<td::int64>(num->number_->number_);
}

toslib_api::object_ptr<toslib_api::tos_blockIdExt> clone_block_id(const toslib_api::tos_blockIdExt &id) {
  return toslib_api::make_object<toslib_api::tos_blockIdExt>(id.workchain_, id.shard_, id.seqno_, id.root_hash_,
                                                             id.file_hash_);
}

td::Result<block::StdAddress> stack_address(const toslib_api::object_ptr<toslib_api::tvm_StackEntry> &entry) {
  auto *slice_entry = dynamic_cast<toslib_api::tvm_stackEntrySlice *>(entry.get());
  if (slice_entry == nullptr || !slice_entry->slice_) {
    return td::Status::Error("stack entry is not an address slice");
  }
  TRY_RESULT(cell, vm::std_boc_deserialize(slice_entry->slice_->bytes_));
  auto cs = vm::load_cell_slice_ref(std::move(cell));
  tos::WorkchainId workchain;
  tos::StdSmcAddress address;
  if (!block::tlb::t_MsgAddressInt.extract_std_address(std::move(cs), workchain, address)) {
    return td::Status::Error("stack slice is not a standard internal address");
  }
  return block::StdAddress{workchain, address};
}

}  // namespace

void DNSResolver::check_lifecycle(std::string host, std::string address, tos::dns::DomainItemPath domain_path,
                                  toslib_api::object_ptr<toslib_api::tos_blockIdExt> block_id) {
  auto self = actor_id(this);
  auto block_for_load = clone_block_id(*block_id);
  auto header_p = td::PromiseCreator::lambda(
      [self, host = std::move(host), address = std::move(address), domain_path = std::move(domain_path),
       block_id = std::move(block_for_load)](td::Result<toslib_api::object_ptr<toslib_api::blocks_header>> R) mutable {
        if (R.is_error()) {
          td::actor::send_closure(self, &DNSResolver::finish_error, std::move(host),
                                  R.move_as_error_prefix("cannot read resolution block time: "), true);
          return;
        }
        auto header = R.move_as_ok();
        td::actor::send_closure(self, &DNSResolver::load_lifecycle_at_block, std::move(host), std::move(address),
                                std::move(domain_path), std::move(block_id), header->gen_utime_);
      });
  td::actor::send_closure(toslib_client_, &toslib::ToslibClientWrapper::send_request<toslib_api::blocks_getBlockHeader>,
                          toslib_api::make_object<toslib_api::blocks_getBlockHeader>(std::move(block_id)),
                          std::move(header_p));
}

void DNSResolver::load_lifecycle_at_block(std::string host, std::string address, tos::dns::DomainItemPath domain_path,
                                          toslib_api::object_ptr<toslib_api::tos_blockIdExt> block_id,
                                          td::int64 block_utime) {
  // The Domain Item is the third canonical .tos hop, not the last hop (which
  // may be owner-controlled). Load it at the exact resolution checkpoint.
  auto toslib = toslib_client_;
  auto self = actor_id(this);
  auto load_p = td::PromiseCreator::lambda([toslib, self, host = std::move(host), address = std::move(address),
                                            expected_collection = std::move(domain_path.collection),
                                            expected_label = std::move(domain_path.label), block_utime](
                                               td::Result<toslib_api::object_ptr<toslib_api::smc_info>> R) mutable {
    if (R.is_error()) {
      td::actor::send_closure(self, &DNSResolver::finish_error, std::move(host),
                              R.move_as_error_prefix("cannot load domain item: "), true);
      return;
    }
    auto smc_id = R.move_as_ok()->id_;
    // Every exit after smc.load, including malformed getter results and lost
    // promises, releases the registered AccountState exactly once.
    tos::dns::SharedCleanup cleanup([toslib, smc_id]() {
      td::actor::send_closure(toslib, &toslib::ToslibClientWrapper::send_request<toslib_api::smc_forget>,
                              toslib_api::make_object<toslib_api::smc_forget>(smc_id),
                              td::PromiseCreator::lambda([](td::Result<toslib_api::object_ptr<toslib_api::ok>>) {}));
    });
    auto identity_p = td::PromiseCreator::lambda(
        [toslib, self, smc_id, cleanup, host = std::move(host), address = std::move(address),
         expected_collection = std::move(expected_collection), expected_label = std::move(expected_label),
         block_utime](td::Result<toslib_api::object_ptr<toslib_api::smc_runResult>> R) mutable {
          if (R.is_error()) {
            td::actor::send_closure(self, &DNSResolver::finish_error, std::move(host),
                                    R.move_as_error_prefix("cannot verify Domain Item identity: "), true);
            return;
          }
          auto res = R.move_as_ok();
          // get_nft_data returns (init, index, collection, owner, content),
          // bottom-first. Binding collection to the second canonical resolver
          // prevents an owner-controlled delegate from impersonating the item.
          if (res->exit_code_ != 0 || res->stack_.size() != 5) {
            td::actor::send_closure(self, &DNSResolver::finish_error, std::move(host),
                                    td::Status::Error("get_nft_data failed; refusing the record"), true);
            return;
          }
          auto r_collection = stack_address(res->stack_[2]);
          auto r_expected = block::StdAddress::parse(expected_collection);
          if (r_collection.is_error() || r_expected.is_error() ||
              r_collection.ok().workchain != r_expected.ok().workchain ||
              r_collection.ok().addr != r_expected.ok().addr) {
            td::actor::send_closure(
                self, &DNSResolver::finish_error, std::move(host),
                td::Status::Error("resolver path Domain Item does not belong to the .tos Collection"), true);
            return;
          }
          auto *index_entry = dynamic_cast<toslib_api::tvm_stackEntryNumber *>(res->stack_[1].get());
          auto actual_index = index_entry && index_entry->number_
                                  ? td::dec_string_to_int256(index_entry->number_->number_)
                                  : td::RefInt256{};
          auto label_cell = vm::CellBuilder().store_bytes(expected_label).finalize();
          auto expected_index = td::bits_to_refint(label_cell->get_hash().bits(), 256, false);
          if (actual_index.is_null() || td::cmp(actual_index, expected_index) != 0) {
            td::actor::send_closure(self, &DNSResolver::finish_error, std::move(host),
                                    td::Status::Error("resolver path Domain Item index does not match the .tos label"),
                                    true);
            return;
          }
          auto auction_p = td::PromiseCreator::lambda(
              [toslib, self, smc_id, cleanup, host = std::move(host), address = std::move(address),
               block_utime](td::Result<toslib_api::object_ptr<toslib_api::smc_runResult>> R) mutable {
                if (R.is_error()) {
                  td::actor::send_closure(self, &DNSResolver::finish_error, std::move(host),
                                          R.move_as_error_prefix("cannot read auction state: "), true);
                  return;
                }
                auto res = R.move_as_ok();
                // get_auction_info returns (max_bid_address, max_bid_amount,
                // auction_end_time), bottom-first: end time is the last entry
                if (res->exit_code_ != 0 || res->stack_.size() != 3) {
                  td::actor::send_closure(self, &DNSResolver::finish_error, std::move(host),
                                          td::Status::Error("get_auction_info failed; refusing the record"), true);
                  return;
                }
                auto r_end_time = stack_number(res->stack_[2]);
                if (r_end_time.is_error()) {
                  td::actor::send_closure(self, &DNSResolver::finish_error, std::move(host),
                                          r_end_time.move_as_error_prefix("bad auction state: "), true);
                  return;
                }
                auto end_time = r_end_time.move_as_ok();
                auto lfut_p = td::PromiseCreator::lambda(
                    [self, cleanup, host = std::move(host), address = std::move(address), end_time,
                     block_utime](td::Result<toslib_api::object_ptr<toslib_api::smc_runResult>> R) mutable {
                      if (R.is_error()) {
                        td::actor::send_closure(self, &DNSResolver::finish_error, std::move(host),
                                                R.move_as_error_prefix("cannot read renewal clock: "), true);
                        return;
                      }
                      auto res = R.move_as_ok();
                      if (res->exit_code_ != 0 || res->stack_.size() != 1) {
                        td::actor::send_closure(self, &DNSResolver::finish_error, std::move(host),
                                                td::Status::Error("get_last_fill_up_time failed; refusing the record"),
                                                true);
                        return;
                      }
                      auto r_lfut = stack_number(res->stack_[0]);
                      if (r_lfut.is_error()) {
                        td::actor::send_closure(self, &DNSResolver::finish_error, std::move(host),
                                                r_lfut.move_as_error_prefix("bad renewal clock: "), true);
                        return;
                      }
                      td::actor::send_closure(self, &DNSResolver::finish_lifecycle, std::move(host), std::move(address),
                                              end_time, r_lfut.move_as_ok(), block_utime);
                    });
                td::actor::send_closure(
                    toslib, &toslib::ToslibClientWrapper::send_request<toslib_api::smc_runGetMethod>,
                    toslib_api::make_object<toslib_api::smc_runGetMethod>(
                        smc_id, toslib_api::make_object<toslib_api::smc_methodIdName>("get_last_fill_up_time"),
                        std::vector<toslib_api::object_ptr<toslib_api::tvm_StackEntry>>()),
                    std::move(lfut_p));
              });
          td::actor::send_closure(toslib, &toslib::ToslibClientWrapper::send_request<toslib_api::smc_runGetMethod>,
                                  toslib_api::make_object<toslib_api::smc_runGetMethod>(
                                      smc_id, toslib_api::make_object<toslib_api::smc_methodIdName>("get_auction_info"),
                                      std::vector<toslib_api::object_ptr<toslib_api::tvm_StackEntry>>()),
                                  std::move(auction_p));
        });
    td::actor::send_closure(toslib, &toslib::ToslibClientWrapper::send_request<toslib_api::smc_runGetMethod>,
                            toslib_api::make_object<toslib_api::smc_runGetMethod>(
                                smc_id, toslib_api::make_object<toslib_api::smc_methodIdName>("get_nft_data"),
                                std::vector<toslib_api::object_ptr<toslib_api::tvm_StackEntry>>()),
                            std::move(identity_p));
  });
  td::actor::send_closure(toslib_client_, &toslib::ToslibClientWrapper::send_request_at_block<toslib_api::smc_load>,
                          std::move(block_id),
                          toslib_api::make_object<toslib_api::smc_load>(
                              toslib_api::make_object<toslib_api::accountAddress>(std::move(domain_path.item))),
                          std::move(load_p));
}

void DNSResolver::finish_lifecycle(std::string host, std::string address, td::int64 auction_end_time,
                                   td::int64 last_fill_up_time, td::int64 block_utime) {
  auto now_unix = static_cast<td::int64>(td::Clocks::system());
  // State is evaluated at its proved block time; the local clock is used only
  // conservatively so a stale finalized checkpoint cannot extend a lease.
  auto evaluation_time = std::max(now_unix, block_utime);
  auto r_deadline = tos::dns::check_domain_lifecycle(auction_end_time, last_fill_up_time, evaluation_time);
  if (r_deadline.is_error()) {
    finish_error(std::move(host), r_deadline.move_as_error(), true);
    return;
  }
  save_to_cache(host, address, r_deadline.move_as_ok());
  finish_success(std::move(host), std::move(address));
}

void DNSResolver::save_to_cache(std::string host, std::string address, td::int64 renewal_deadline) {
  double now = td::Time::now();
  auto now_unix = static_cast<td::int64>(td::Clocks::system());
  tos::dns::evict_for_insert(cache_, host, now, max_cache_entries_);
  tos::dns::DnsCacheEntry &entry = cache_[host];
  entry.address_ = std::move(address);
  entry.created_at_ = now;
  entry.expires_at_ = tos::dns::bounded_cache_expiry(now, CACHE_TIMEOUT_HARD, renewal_deadline, now_unix);
}

void DNSResolver::finish_success(std::string host, std::string address) {
  auto it = pending_.find(host);
  if (it == pending_.end()) {
    return;
  }
  auto waiters = std::move(it->second);
  pending_.erase(it);
  for (auto &waiter : waiters) {
    waiter.set_value(std::string(address));
  }
}

void DNSResolver::finish_error(std::string host, td::Status error, bool invalidate_cache) {
  if (invalidate_cache) {
    cache_.erase(host);
  }
  auto it = pending_.find(host);
  if (it == pending_.end()) {
    return;
  }
  auto waiters = std::move(it->second);
  pending_.erase(it);
  for (auto &waiter : waiters) {
    waiter.set_error(error.clone());
  }
}
