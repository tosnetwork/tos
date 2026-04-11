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
#include "auto/tl/toslib_api.h"

namespace toslib_api = tos::toslib_api;

namespace toslib {
class Client final {
 public:
  Client();
  struct Request {
    std::uint64_t id;
    toslib_api::object_ptr<toslib_api::Function> function;
  };

  void send(Request&& request);

  struct Response {
    std::uint64_t id;
    toslib_api::object_ptr<toslib_api::Object> object;
  };

  Response receive(double timeout);

  static Response execute(Request&& request);

  void cancel_requests();

  ~Client();
  Client(Client&& other);
  Client& operator=(Client&& other);

 private:
  class Impl;
  std::unique_ptr<Impl> impl_;
};
}  // namespace toslib
