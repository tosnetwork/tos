/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
#pragma once

#include <functional>
#include <memory>

#include "control-getter.h"

namespace tos::control_getter {

// Slots are reserved before a caller starts asynchronous state lookup. The first
// two reservations belong to workers; only eight further reservations can queue.
// Snapshot acquisition and VM execution never hold the executor's bookkeeping lock.
class Executor {
  struct State;
  struct Job;

 public:
  using Work = std::function<td::Status()>;
  using Completion = std::function<void(td::Status)>;
  class Admission {
   public:
    ~Admission();
    Admission(const Admission&) = delete;
    Admission& operator=(const Admission&) = delete;
    td::Status dispatch(Work work, Completion completion);
    void cancel();

   private:
    friend class Executor;
    Admission(std::shared_ptr<State> state, std::shared_ptr<Job> job);
    std::shared_ptr<State> state_;
    std::shared_ptr<Job> job_;
    bool dispatched_{false};
  };
  struct Counts {
    std::size_t active;
    std::size_t queued;
  };
  static td::Result<std::unique_ptr<Executor>> create();
  ~Executor();
  Executor(const Executor&) = delete;
  Executor& operator=(const Executor&) = delete;
  td::Result<std::unique_ptr<Admission>> admit();
  Counts counts() const;
  // Shutdown belongs to the owning actor: it refuses new work, cancels pending
  // reservations and waits for running bounded getters before returning.
  void shutdown();

 private:
  Executor();
  std::shared_ptr<State> state_;
};

}  // namespace tos::control_getter
