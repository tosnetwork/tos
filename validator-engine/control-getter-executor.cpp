/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
#include <array>
#include <condition_variable>
#include <deque>
#include <mutex>
#include <thread>

#include "control-getter-executor.h"

namespace tos::control_getter {

struct Executor::Job {
  enum class Phase { Preparing, Ready, Running, Finished };
  Phase phase{Phase::Preparing};
  bool cancelled{false};
  Work work;
  Completion completion;
};

struct Executor::State {
  mutable std::mutex mutex;
  std::condition_variable ready;
  std::array<std::shared_ptr<Job>, kControlGetterActiveJobs> active;
  std::deque<std::shared_ptr<Job>> queued;
  std::array<std::thread, kControlGetterActiveJobs> threads;
  bool stopped{false};

  void serve(std::size_t lane) {
    for (;;) {
      Work work;
      Completion completion;
      std::shared_ptr<Job> job;
      bool cancelled = false;
      {
        std::unique_lock lock(mutex);
        ready.wait(lock, [&] {
          return (stopped && !active[lane]) ||
                 (active[lane] && (active[lane]->phase == Job::Phase::Ready || active[lane]->cancelled));
        });
        if (!active[lane]) {
          return;
        }
        job = active[lane];
        cancelled = job->cancelled;
        job->phase = Job::Phase::Running;
        work = std::move(job->work);
        completion = std::move(job->completion);
      }
      // Completion and destruction of captured snapshots happen on the worker,
      // before its reservation is released, including when the caller cancelled.
      td::Status result = td::Status::Error("control getter admission cancelled");
      if (work && !cancelled) {
        try {
          result = work();
        } catch (...) {
          result = td::Status::Error("control getter worker exception");
        }
      }
      work = {};
      if (completion) {
        completion(std::move(result));
      }
      completion = {};
      {
        std::lock_guard lock(mutex);
        job->phase = Job::Phase::Finished;
        active[lane].reset();
        if (!queued.empty()) {
          active[lane] = std::move(queued.front());
          queued.pop_front();
        }
      }
      ready.notify_all();
    }
  }
};

Executor::Admission::Admission(std::shared_ptr<State> state, std::shared_ptr<Job> job)
    : state_(std::move(state)), job_(std::move(job)) {
}

Executor::Admission::~Admission() {
  // Once dispatched, the worker owns the reservation. Dropping the caller's
  // handle cannot allow another getter to overlap a still-running one.
  if (!dispatched_) {
    cancel();
  }
}

void Executor::Admission::cancel() {
  {
    std::lock_guard lock(state_->mutex);
    job_->cancelled = true;
  }
  state_->ready.notify_all();
}

td::Status Executor::Admission::dispatch(Work work, Completion completion) {
  if (!work || !completion) {
    return td::Status::Error("empty control getter work");
  }
  {
    std::lock_guard lock(state_->mutex);
    if (state_->stopped || job_->cancelled) {
      return td::Status::Error("control getter admission cancelled");
    }
    if (job_->phase != Job::Phase::Preparing) {
      return td::Status::Error("control getter admission already dispatched");
    }
    job_->work = std::move(work);
    job_->completion = std::move(completion);
    job_->phase = Job::Phase::Ready;
    dispatched_ = true;
  }
  state_->ready.notify_all();
  return td::Status::OK();
}

Executor::Executor() : state_(std::make_shared<State>()) {
}

td::Result<std::unique_ptr<Executor>> Executor::create() {
  std::unique_ptr<Executor> executor{new Executor};
  try {
    for (std::size_t lane = 0; lane < kControlGetterActiveJobs; ++lane) {
      executor->state_->threads[lane] = std::thread([state = executor->state_, lane] { state->serve(lane); });
    }
    return executor;
  } catch (const std::system_error&) {
    executor->shutdown();
    return td::Status::Error("cannot start control getter executor threads");
  }
}

Executor::~Executor() {
  shutdown();
}

void Executor::shutdown() {
  {
    std::lock_guard lock(state_->mutex);
    state_->stopped = true;
    for (const auto& job : state_->active) {
      if (job) {
        job->cancelled = true;
      }
    }
    for (const auto& job : state_->queued) {
      job->cancelled = true;
    }
  }
  state_->ready.notify_all();
  for (auto& thread : state_->threads) {
    if (thread.joinable()) {
      thread.join();
    }
  }
}

td::Result<std::unique_ptr<Executor::Admission>> Executor::admit() {
  std::lock_guard lock(state_->mutex);
  if (state_->stopped) {
    return td::Status::Error("control getter executor stopped");
  }
  for (auto& slot : state_->active) {
    if (!slot) {
      auto job = std::make_shared<Job>();
      std::unique_ptr<Admission> admission{new Admission{state_, job}};
      slot = std::move(job);
      return admission;
    }
  }
  if (state_->queued.size() >= kControlGetterQueuedJobs) {
    return td::Status::Error("control getter executor busy");
  }
  auto job = std::make_shared<Job>();
  std::unique_ptr<Admission> admission{new Admission{state_, job}};
  state_->queued.push_back(std::move(job));
  return admission;
}

Executor::Counts Executor::counts() const {
  std::lock_guard lock(state_->mutex);
  std::size_t active = 0;
  for (const auto& job : state_->active) {
    if (job) {
      ++active;
    }
  }
  return {active, state_->queued.size()};
}

}  // namespace tos::control_getter
