/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-or-later */
#include "td/utils/port/detail/PollableFd.h"

#include "index-source.h"
#include "service-common.h"

namespace tos::services {
namespace {
void raise_high_water(std::atomic<uint64_t>& high_water, uint64_t value) {
  auto seen = high_water.load(std::memory_order_relaxed);
  while (value > seen && !high_water.compare_exchange_weak(seen, value, std::memory_order_relaxed)) {
  }
}
}  // namespace

SourceTicket::SourceTicket(std::shared_ptr<SourceCore> core, SourceLane lane, uint64_t generation, size_t bytes,
                           Deadline deadline, uint64_t serial)
    : core_(std::move(core))
    , lane_(lane)
    , generation_(generation)
    , bytes_(bytes)
    , deadline_(deadline)
    , serial_(serial) {
}
SourceTicket::SourceTicket(SourceTicket&& other) noexcept
    : core_(std::move(other.core_))
    , lane_(other.lane_)
    , generation_(other.generation_)
    , bytes_(other.bytes_)
    , deadline_(other.deadline_)
    , serial_(other.serial_) {
  other.core_ = nullptr;
  other.bytes_ = 0;
}
SourceTicket& SourceTicket::operator=(SourceTicket&& other) noexcept {
  if (this != &other) {
    release();
    core_ = std::move(other.core_);
    lane_ = other.lane_;
    generation_ = other.generation_;
    bytes_ = other.bytes_;
    deadline_ = other.deadline_;
    serial_ = other.serial_;
    other.core_ = nullptr;
    other.bytes_ = 0;
  }
  return *this;
}
SourceTicket::~SourceTicket() {
  release();
}
void SourceTicket::release() {
  if (core_ == nullptr) {
    return;
  }
  auto core = std::move(core_);
  core_ = nullptr;
  core->release_ticket(lane_, generation_, bytes_, deadline_, serial_);
  bytes_ = 0;
}
void SourceTicket::completed_locked() {
  if (core_ == nullptr || serial_ == 0) {
    return;
  }
  core_->clear_deadline_locked(deadline_, serial_);
  serial_ = 0;
}
void SourceTicket::set_bytes_locked(size_t bytes) {
  if (core_ == nullptr || bytes == bytes_) {
    return;
  }
  core_->remove_bytes_locked(bytes_);
  core_->add_bytes_locked(bytes);
  bytes_ = bytes;
  core_->cv().notify_all();
}

SourceCharge::SourceCharge(std::shared_ptr<SourceCore> core, size_t bytes) : core_(std::move(core)), bytes_(bytes) {
  std::lock_guard<std::mutex> lock(core_->mutex());
  core_->add_bytes_locked(bytes_);
}
SourceCharge::SourceCharge(SourceCharge&& other) noexcept : core_(std::move(other.core_)), bytes_(other.bytes_) {
  other.core_ = nullptr;
  other.bytes_ = 0;
}
SourceCharge& SourceCharge::operator=(SourceCharge&& other) noexcept {
  if (this != &other) {
    release();
    core_ = std::move(other.core_);
    bytes_ = other.bytes_;
    other.core_ = nullptr;
    other.bytes_ = 0;
  }
  return *this;
}
SourceCharge::~SourceCharge() {
  release();
}
void SourceCharge::release() {
  if (core_ == nullptr) {
    return;
  }
  {
    std::lock_guard<std::mutex> lock(core_->mutex());
    core_->remove_bytes_locked(bytes_);
    core_->cv().notify_all();
  }
  core_ = nullptr;
  bytes_ = 0;
}

td::Result<std::shared_ptr<SourceCore>> SourceCore::create(SourceLimits limits) {
  if (limits.requests < 2 || limits.consumer_reserve == 0 || limits.consumer_reserve >= limits.requests) {
    return td::Status::Error("source limits need at least one consumer place and one prefetch place");
  }
  if (limits.prefetch_bytes == 0) {
    return td::Status::Error("source limits need a nonzero prefetch byte budget");
  }
  return std::shared_ptr<SourceCore>(new SourceCore(limits));
}

SourceCore::SourceCore(SourceLimits limits) : limits_(limits) {
  inbox_.init();
}

SourceCore::~SourceCore() {
  inbox_.destroy();
}

bool SourceCore::stopping_locked() const {
  return shut_down_ || stop_requested.load();
}

void SourceCore::shutdown() {
  std::lock_guard<std::mutex> lock(mutex_);
  shut_down_ = true;
  cv_.notify_all();
}

uint64_t SourceCore::reset_prefetch() {
  std::lock_guard<std::mutex> lock(mutex_);
  return reset_prefetch_locked();
}

uint64_t SourceCore::reset_prefetch_locked() {
  ++generation_;
  current_prefetch_ = 0;
  cv_.notify_all();
  return generation_;
}

uint64_t SourceCore::generation() {
  std::lock_guard<std::mutex> lock(mutex_);
  return generation_;
}

void SourceCore::wait_locked(std::unique_lock<std::mutex>& lock, std::chrono::steady_clock::time_point limit) {
  auto backstop = std::chrono::steady_clock::now() + std::chrono::milliseconds(100);
  cv_.wait_until(lock, std::min(limit, backstop));
  if (!deadlines_.empty() && deadlines_.begin()->first <= std::chrono::steady_clock::now()) {
    mark_timed_out_locked();
  }
}

td::Status SourceCore::cancelled_locked() const {
  if (timed_out_.load()) {
    return td::Status::Error("source request timed out; restart to retry from the durable checkpoint");
  }
  return td::Status::Error("source request cancelled");
}

void SourceCore::mark_timed_out_locked() {
  timed_out_.store(true);
  stop_requested.store(true);
  shut_down_ = true;
  cv_.notify_all();
}

td::Result<SourceTicket> SourceCore::acquire(SourceLane lane, uint64_t generation, size_t reserve_bytes,
                                             std::chrono::milliseconds timeout) {
  std::unique_lock<std::mutex> lock(mutex_);
  auto prefetch_places = limits_.requests - limits_.consumer_reserve;
  while (true) {
    if (stopping_locked()) {
      return cancelled_locked();
    }
    if (!current_locked(lane, generation)) {
      return td::Status::Error("source prefetch reset");
    }
    bool place = outstanding_ < limits_.requests;
    if (lane == SourceLane::Prefetch) {
      place = place && prefetch_outstanding_ < prefetch_places;
      // The earliest result of a generation is admitted even when results
      // from an earlier generation, or handles the replay thread has not
      // reached, hold the budget: it is the one the replay thread needs.
      bool bytes = current_prefetch_ == 0 || prefetch_bytes_ + reserve_bytes <= limits_.prefetch_bytes;
      place = place && bytes;
    }
    if (place) {
      break;
    }
    wait_locked(lock, std::chrono::steady_clock::time_point::max());
  }
  ++outstanding_;
  size_t bytes = 0;
  if (lane == SourceLane::Prefetch) {
    ++prefetch_outstanding_;
    ++current_prefetch_;
    bytes = reserve_bytes;
    add_bytes_locked(bytes);
  }
  raise_high_water(counters_.outstanding_high_water, outstanding_);
  counters_.requests.fetch_add(1, std::memory_order_relaxed);
  auto deadline = std::chrono::steady_clock::now() + timeout;
  auto serial = ++next_serial_;
  deadlines_.emplace(deadline, serial);
  return SourceTicket(shared_from_this(), lane, generation, bytes, deadline, serial);
}

void SourceCore::add_bytes_locked(size_t bytes) {
  prefetch_bytes_ += bytes;
  raise_high_water(counters_.prefetch_bytes_high_water, prefetch_bytes_);
}

void SourceCore::remove_bytes_locked(size_t bytes) {
  prefetch_bytes_ = bytes <= prefetch_bytes_ ? prefetch_bytes_ - bytes : 0;
}

void SourceCore::release_ticket(SourceLane lane, uint64_t generation, size_t bytes, SourceTicket::Deadline deadline,
                                uint64_t serial) {
  std::lock_guard<std::mutex> lock(mutex_);
  clear_deadline_locked(deadline, serial);
  if (outstanding_ > 0) {
    --outstanding_;
  }
  if (lane == SourceLane::Prefetch) {
    if (prefetch_outstanding_ > 0) {
      --prefetch_outstanding_;
    }
    if (generation == generation_ && current_prefetch_ > 0) {
      --current_prefetch_;
    }
    remove_bytes_locked(bytes);
  }
  cv_.notify_all();
}

void SourceCore::clear_deadline_locked(SourceTicket::Deadline deadline, uint64_t serial) {
  if (serial != 0) {
    deadlines_.erase({deadline, serial});
  }
}

bool SourceCore::push(std::function<void()> closure) {
  {
    std::lock_guard<std::mutex> lock(mutex_);
    if (stopping_locked()) {
      return false;
    }
  }
  inbox_.writer_put(std::move(closure));
  return true;
}

void SourceCore::run_inbox() {
  while (true) {
    auto ready = inbox_.reader_wait_nonblock();
    if (ready == 0) {
      return;
    }
    for (int i = 0; i < ready; ++i) {
      auto closure = inbox_.reader_get_unsafe();
      bool stopping;
      {
        std::lock_guard<std::mutex> lock(mutex_);
        stopping = stopping_locked();
      }
      // A closure not run is destroyed here, which releases its reply.
      if (!stopping && closure) {
        closure();
      }
    }
  }
}

void SourceInbox::start_up() {
  self_ = actor_id(this);
  td::actor::SchedulerContext::get().get_poll().subscribe(
      core_->inbox_event_fd().get_poll_info().extract_pollable_fd(this), td::PollFlags::Read());
  loop();
}

void SourceInbox::tear_down() {
  td::actor::SchedulerContext::get().get_poll().unsubscribe(
      core_->inbox_event_fd().get_poll_info().get_pollable_fd_ref());
}

void SourceInbox::loop() {
  core_->run_inbox();
}

void SourceInbox::notify() {
  td::actor::send_signals(self_, td::actor::ActorSignals::wakeup());
}

td::actor::ActorOwn<SourceInbox> SourceInbox::create(std::shared_ptr<SourceCore> core) {
  return td::actor::create_actor<SourceInbox>(td::actor::ActorOptions().with_name("index-source-inbox").with_poll(),
                                              std::move(core));
}

}  // namespace tos::services
