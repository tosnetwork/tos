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
#pragma once
#include "DNSLifecycle.h"
#include "adnl/adnl.h"
#include "td/actor/PromiseFuture.h"
#include "td/actor/actor.h"
#include "toslib/toslib/ToslibClientWrapper.h"

class DNSResolver : public td::actor::Actor {
 public:
  explicit DNSResolver(td::actor::ActorId<toslib::ToslibClientWrapper> toslib_client);

  void start_up() override;
  void resolve(std::string host, td::Promise<std::string> promise);

 private:
  void sync();
  void check_lifecycle(std::string host, std::string address, std::string item_address,
                       td::Promise<std::string> promise);
  void finish_lifecycle(std::string host, std::string address, td::int64 auction_end_time,
                        td::int64 last_fill_up_time, td::Promise<std::string> promise);
  void save_to_cache(std::string host, std::string address, td::int64 renewal_deadline);

  td::actor::ActorId<toslib::ToslibClientWrapper> toslib_client_;

  // Bounded: an attacker who can drive lookups must not be able to grow the
  // cache without limit. When full, expired entries are evicted first, then
  // the stalest live entry.
  static constexpr std::size_t max_cache_entries_ = 1024;
  std::map<std::string, tos::dns::DnsCacheEntry> cache_;
};
