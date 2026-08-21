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
#include "smc-envelope/ManualDns.h"
#include "td/utils/overloaded.h"

#include "DNSResolver.h"

static const double CACHE_TIMEOUT_HARD = 300.0;
static const double CACHE_TIMEOUT_SOFT = 270.0;

DNSResolver::DNSResolver(td::actor::ActorId<toslib::ToslibClientWrapper> toslib_client)
    : toslib_client_(std::move(toslib_client)) {
}

void DNSResolver::start_up() {
  sync();
}

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

  td::Bits256 category = td::sha256_bits256(td::Slice("site", 4));
  auto obj = toslib_api::make_object<toslib_api::dns_resolve>(nullptr, host, category, tos::DNS_MAX_RESOLVER_HOPS);
  auto P = td::PromiseCreator::lambda([SelfId = actor_id(this), promise = std::move(promise), host = std::move(host)](
                                          td::Result<toslib_api::object_ptr<toslib_api::dns_resolved>> R) mutable {
    if (R.is_error()) {
      if (promise) {
        promise.set_result(R.move_as_error());
      }
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
      if (promise) {
        promise.set_error(td::Status::Error("no DNS entries"));
      }
      return;
    }
    if (obj->resolver_path_.empty()) {
      // without the answering item's address its lifecycle cannot be
      // verified: fail closed rather than serve unverifiable records
      if (promise) {
        promise.set_error(td::Status::Error("resolver path missing; cannot verify domain lifecycle"));
      }
      return;
    }
    auto item_address = obj->resolver_path_.back()->account_address_;
    td::actor::send_closure(SelfId, &DNSResolver::check_lifecycle, std::move(host), std::move(result),
                            std::move(item_address), std::move(promise));
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

}  // namespace

void DNSResolver::check_lifecycle(std::string host, std::string address, std::string item_address,
                                  td::Promise<std::string> promise) {
  // fail-closed lifecycle gate (DNS.md §6.5): read the answering item's
  // auction state and renewal clock before serving or caching its records
  auto toslib = toslib_client_;
  auto self = actor_id(this);
  auto load_p = td::PromiseCreator::lambda([toslib, self, host = std::move(host), address = std::move(address),
                                            promise = std::move(promise)](
                                               td::Result<toslib_api::object_ptr<toslib_api::smc_info>> R) mutable {
    if (R.is_error()) {
      promise.set_error(R.move_as_error_prefix("cannot load domain item: "));
      return;
    }
    auto smc_id = R.move_as_ok()->id_;
    auto auction_p = td::PromiseCreator::lambda(
        [toslib, self, smc_id, host = std::move(host), address = std::move(address), promise = std::move(promise)](
            td::Result<toslib_api::object_ptr<toslib_api::smc_runResult>> R) mutable {
          if (R.is_error()) {
            promise.set_error(R.move_as_error_prefix("cannot read auction state: "));
            return;
          }
          auto res = R.move_as_ok();
          // get_auction_info returns (max_bid_address, max_bid_amount,
          // auction_end_time), bottom-first: end time is the last entry
          if (res->exit_code_ != 0 || res->stack_.size() != 3) {
            promise.set_error(td::Status::Error("get_auction_info failed; refusing the record"));
            return;
          }
          auto r_end_time = stack_number(res->stack_[2]);
          if (r_end_time.is_error()) {
            promise.set_error(r_end_time.move_as_error_prefix("bad auction state: "));
            return;
          }
          auto end_time = r_end_time.move_as_ok();
          auto lfut_p = td::PromiseCreator::lambda(
              [toslib, self, smc_id, host = std::move(host), address = std::move(address), end_time,
               promise = std::move(promise)](
                  td::Result<toslib_api::object_ptr<toslib_api::smc_runResult>> R) mutable {
                // release the toslib-side contract instance either way
                td::actor::send_closure(
                    toslib, &toslib::ToslibClientWrapper::send_request<toslib_api::smc_forget>,
                    toslib_api::make_object<toslib_api::smc_forget>(smc_id),
                    td::PromiseCreator::lambda([](td::Result<toslib_api::object_ptr<toslib_api::ok>>) {}));
                if (R.is_error()) {
                  promise.set_error(R.move_as_error_prefix("cannot read renewal clock: "));
                  return;
                }
                auto res = R.move_as_ok();
                if (res->exit_code_ != 0 || res->stack_.size() != 1) {
                  promise.set_error(td::Status::Error("get_last_fill_up_time failed; refusing the record"));
                  return;
                }
                auto r_lfut = stack_number(res->stack_[0]);
                if (r_lfut.is_error()) {
                  promise.set_error(r_lfut.move_as_error_prefix("bad renewal clock: "));
                  return;
                }
                td::actor::send_closure(self, &DNSResolver::finish_lifecycle, std::move(host), std::move(address),
                                        end_time, r_lfut.move_as_ok(), std::move(promise));
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
  td::actor::send_closure(toslib_client_, &toslib::ToslibClientWrapper::send_request<toslib_api::smc_load>,
                          toslib_api::make_object<toslib_api::smc_load>(
                              toslib_api::make_object<toslib_api::accountAddress>(std::move(item_address))),
                          std::move(load_p));
}

void DNSResolver::finish_lifecycle(std::string host, std::string address, td::int64 auction_end_time,
                                   td::int64 last_fill_up_time, td::Promise<std::string> promise) {
  auto now_unix = static_cast<td::int64>(td::Clocks::system());
  auto r_deadline = tos::dns::check_domain_lifecycle(auction_end_time, last_fill_up_time, now_unix);
  if (r_deadline.is_error()) {
    // the name may have been cached while healthy: drop it now
    cache_.erase(host);
    promise.set_error(r_deadline.move_as_error());
    return;
  }
  save_to_cache(std::move(host), address, r_deadline.move_as_ok());
  promise.set_result(std::move(address));
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
