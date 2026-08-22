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
#include "auto/tl/toslib_api.hpp"
#include "td/actor/actor.h"
#include "toslib/toslib/ToslibClient.h"

namespace toslib {

class ToslibClientWrapper : public td::actor::Actor {
 public:
  explicit ToslibClientWrapper(tos::tl_object_ptr<toslib_api::options> options);

  void start_up() override;

  template <typename F>
  void send_request(toslib_api::object_ptr<F> obj, td::Promise<typename F::ReturnType> promise) {
    auto id = next_request_id_++;
    auto P = promise.wrap([](toslib_api::object_ptr<toslib_api::Object> x) -> td::Result<typename F::ReturnType> {
      if (x->get_id() != F::ReturnType::element_type::ID) {
        return td::Status::Error("Invalid response from toslib");
      }
      return tos::move_tl_object_as<typename F::ReturnType::element_type>(std::move(x));
    });
    CHECK(requests_.emplace(id, std::move(P)).second);
    td::actor::send_closure(toslib_client_, &toslib::ToslibClient::request, id, std::move(obj));
  }

  // Execute a typed request under one explicit block context. `withBlock`
  // itself returns the untyped Object produced by the nested function, so the
  // wrapper restores the same type check provided by send_request().
  template <typename F>
  void send_request_at_block(toslib_api::object_ptr<toslib_api::tos_blockIdExt> block_id, toslib_api::object_ptr<F> obj,
                             td::Promise<typename F::ReturnType> promise) {
    auto id = next_request_id_++;
    auto P = promise.wrap([](toslib_api::object_ptr<toslib_api::Object> x) -> td::Result<typename F::ReturnType> {
      if (!x || x->get_id() != F::ReturnType::element_type::ID) {
        return td::Status::Error("Invalid response from toslib withBlock request");
      }
      return tos::move_tl_object_as<typename F::ReturnType::element_type>(std::move(x));
    });
    CHECK(requests_.emplace(id, std::move(P)).second);
    toslib_api::object_ptr<toslib_api::Function> function = std::move(obj);
    auto wrapped = toslib_api::make_object<toslib_api::withBlock>(std::move(block_id), std::move(function));
    td::actor::send_closure(toslib_client_, &toslib::ToslibClient::request, id, std::move(wrapped));
  }

 private:
  void receive_request_result(td::uint64 id, td::Result<toslib_api::object_ptr<toslib_api::Object>> R);

  tos::tl_object_ptr<toslib_api::options> options_;
  td::actor::ActorOwn<toslib::ToslibClient> toslib_client_;
  std::map<td::uint64, td::Promise<toslib_api::object_ptr<toslib_api::Object>>> requests_;
  td::uint64 next_request_id_{1};
};

}  // namespace toslib
