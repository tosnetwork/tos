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

    Copyright 2025-2026 TOS Blockchain Teams
*/
#include "td/utils/port/config.h"

#if TD_PORT_POSIX

#include <functional>
#include <memory>
#include <sys/socket.h>
#include <unistd.h>
#include <utility>

#include "td/utils/Observer.h"
#include "td/utils/common.h"
#include "td/utils/port/Poll.h"
#include "td/utils/port/SocketFd.h"
#include "td/utils/port/detail/NativeFd.h"
#include "td/utils/port/detail/PollableFd.h"
#include "td/utils/tests.h"

// A poller dispatches one batch of ready events, and a callback may unsubscribe
// any fd of that batch, including its own, and free it. Every event of the batch
// that is still to be dispatched for such an fd must then be dropped: its
// PollableFdInfo is no longer the poller's to touch.

namespace {

class CallbackObserver final : public td::ObserverBase {
 public:
  explicit CallbackObserver(std::function<void()> on_notify) : on_notify_(std::move(on_notify)) {
  }
  void notify() override {
    calls++;
    on_notify_();
  }
  int calls = 0;

 private:
  std::function<void()> on_notify_;
};

class CountingObserver final : public td::ObserverBase {
 public:
  void notify() override {
    calls++;
  }
  int calls = 0;
};

// One end of a connected stream socket pair whose peer sent a byte and closed:
// the poller reports it readable, writable and at end of stream, as it reports
// a connection the remote side refused or reset. kqueue reports this as two
// events (EVFILT_READ and EVFILT_WRITE) for the same fd in one batch.
td::SocketFd make_peer_closed_socket() {
  int fds[2];
  CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);
  td::NativeFd peer(fds[1]);
  CHECK(::write(peer.fd(), "x", 1) == 1);
  peer.close();
  auto r_socket = td::SocketFd::from_native_fd(td::NativeFd(fds[0]));
  CHECK(r_socket.is_ok());
  return r_socket.move_as_ok();
}

// After unsubscribing, hands the fd's PollableFdInfo to `tripwire`, so any
// later dispatch of a stale event for it reaches the tripwire instead of
// silently touching an fd the poller no longer owns.
td::PollableFd unsubscribe_and_rearm(td::Poll &poll, td::SocketFd &socket, td::ObserverBase *tripwire) {
  poll.unsubscribe(socket.get_poll_info().get_pollable_fd_ref());
  return socket.get_poll_info().extract_pollable_fd(tripwire);
}

}  // namespace

TEST(Poll, UnsubscribeOwnFdFromCallbackDropsItsPendingEvents) {
  td::Poll poll;
  poll.init();
  auto socket = make_peer_closed_socket();
  CountingObserver tripwire;
  td::vector<td::PollableFd> rearmed;
  CallbackObserver observer([&] {
    if (rearmed.empty()) {
      rearmed.push_back(unsubscribe_and_rearm(poll, socket, &tripwire));
    }
  });
  poll.subscribe(socket.get_poll_info().extract_pollable_fd(&observer), td::PollFlags::ReadWrite());
  poll.run(1000);

  ASSERT_EQ(1, observer.calls);
  ASSERT_EQ(1u, rearmed.size());
  // A second event of the same batch for the unsubscribed fd must not be dispatched.
  ASSERT_EQ(0, tripwire.calls);

  rearmed.clear();
  poll.clear();
}

TEST(Poll, UnsubscribeOtherFdFromCallbackDropsItsPendingEvents) {
  td::Poll poll;
  poll.init();
  td::SocketFd sockets[2] = {make_peer_closed_socket(), make_peer_closed_socket()};
  bool subscribed[2] = {true, true};
  CountingObserver tripwire;
  td::vector<td::PollableFd> rearmed;
  // Whichever socket is dispatched first unsubscribes the other one, whose
  // event is then still pending in the same batch.
  auto make_observer = [&](int self) {
    return CallbackObserver([&, self] {
      int other = 1 - self;
      if (subscribed[self] && subscribed[other]) {
        subscribed[other] = false;
        rearmed.push_back(unsubscribe_and_rearm(poll, sockets[other], &tripwire));
      }
    });
  };
  CallbackObserver observers[2] = {make_observer(0), make_observer(1)};
  for (int i = 0; i < 2; i++) {
    poll.subscribe(sockets[i].get_poll_info().extract_pollable_fd(&observers[i]), td::PollFlags::ReadWrite());
  }
  poll.run(1000);

  ASSERT_EQ(1u, rearmed.size());
  ASSERT_TRUE(subscribed[0] != subscribed[1]);
  // The event still pending for the unsubscribed socket must not be dispatched.
  ASSERT_EQ(0, tripwire.calls);

  rearmed.clear();
  for (int i = 0; i < 2; i++) {
    if (subscribed[i]) {
      poll.unsubscribe(sockets[i].get_poll_info().get_pollable_fd_ref());
    }
  }
  poll.clear();
}

// The production shape: the callback closes the other socket, freeing its
// PollableFdInfo while the batch still holds an event for it. Without the
// guard this is a heap use-after-free (reported by AddressSanitizer).
TEST(Poll, CloseOtherFdFromCallbackDoesNotTouchIt) {
  td::Poll poll;
  poll.init();
  td::SocketFd sockets[2] = {make_peer_closed_socket(), make_peer_closed_socket()};
  bool subscribed[2] = {true, true};
  auto make_observer = [&](int self) {
    return CallbackObserver([&, self] {
      int other = 1 - self;
      if (subscribed[self] && subscribed[other]) {
        subscribed[other] = false;
        poll.unsubscribe(sockets[other].get_poll_info().get_pollable_fd_ref());
        sockets[other].close();
      }
    });
  };
  CallbackObserver observers[2] = {make_observer(0), make_observer(1)};
  for (int i = 0; i < 2; i++) {
    poll.subscribe(sockets[i].get_poll_info().extract_pollable_fd(&observers[i]), td::PollFlags::ReadWrite());
  }
  poll.run(1000);

  ASSERT_TRUE(subscribed[0] != subscribed[1]);
  for (int i = 0; i < 2; i++) {
    if (subscribed[i]) {
      ASSERT_TRUE(observers[i].calls > 0);
      poll.unsubscribe(sockets[i].get_poll_info().get_pollable_fd_ref());
    }
  }
  poll.clear();
}

#endif
