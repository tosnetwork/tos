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

    Copyright 2025-2026 TOS Blockchain Teams
*/

// The in-memory cell database must stop on a decrement of a cell it has never
// stored, naming the cell, instead of dereferencing an empty lookup and carrying
// on with garbage reference counts.
//
// That stop is an abort, so the database work runs in a child: this executable
// re-executes itself with --child=<mode>, and the parent only judges how the
// child ended and what it wrote to stderr. The parent does no database work and
// starts no threads before spawning, and the child is a fresh exec, not a fork.
//
//   --child=dec-known    inc a cell, commit, dec it, commit; exits 0.
//                        The positive control: the child mode really runs the
//                        database, and the parent can tell success from failure.
//   --child=dec-unknown  dec a cell that was never stored, commit; must abort
//                        with "in-memory celldb: dec of unknown cell".

#include <cerrno>
#include <csignal>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <limits.h>
#include <spawn.h>
#include <string>
#include <sys/wait.h>
#include <unistd.h>
#include <vector>

#include "td/db/MemoryKeyValue.h"
#include "vm/cells/CellBuilder.h"
#include "vm/db/CellStorage.h"
#include "vm/db/DynamicBagOfCellsDb.h"

extern char** environ;

namespace {

constexpr const char* kUnknownCellMessage = "in-memory celldb: dec of unknown cell";

td::Ref<vm::Cell> make_cell(const char* payload) {
  vm::CellBuilder cb;
  cb.store_bytes(payload, std::strlen(payload));
  return cb.finalize();
}

std::unique_ptr<vm::DynamicBagOfCellsDb> create_db() {
  vm::DynamicBagOfCellsDb::CreateInMemoryOptions options;
  options.extra_threads = 0;
  options.verbose = false;
  return vm::DynamicBagOfCellsDb::create_in_memory(nullptr, options);
}

int fail(const char* what, const td::Status& status) {
  std::fprintf(stderr, "child: %s failed: %s\n", what, status.to_string().c_str());
  return 2;
}

int child_dec_known() {
  td::MemoryKeyValue kv;
  vm::CellStorer storer(kv);
  auto db = create_db();
  auto cell = make_cell("in-memory celldb dec: known cell");
  db->inc(cell);
  if (auto status = db->commit(storer); status.is_error()) {
    return fail("commit after inc", status);
  }
  db->dec(cell);
  if (auto status = db->commit(storer); status.is_error()) {
    return fail("commit after dec", status);
  }
  std::fprintf(stderr, "child: dec of a stored cell committed\n");
  return 0;
}

int child_dec_unknown() {
  td::MemoryKeyValue kv;
  vm::CellStorer storer(kv);
  auto db = create_db();
  db->dec(make_cell("in-memory celldb dec: never stored"));
  auto status = db->commit(storer);
  std::fprintf(stderr, "child: commit after dec of an unknown cell returned: %s\n", status.to_string().c_str());
  return 0;
}

struct ChildOutcome {
  int wait_status = 0;
  std::string err;
};

std::string self_executable(const char* argv0) {
  char buffer[PATH_MAX];
  auto n = ::readlink("/proc/self/exe", buffer, sizeof(buffer) - 1);
  if (n > 0) {
    return std::string(buffer, static_cast<std::size_t>(n));
  }
  return argv0;
}

bool run_child(const std::string& exe, const std::string& mode, ChildOutcome& outcome) {
  int pipe_fds[2];
  if (::pipe2(pipe_fds, O_CLOEXEC) != 0) {
    std::perror("pipe2");
    return false;
  }
  posix_spawn_file_actions_t actions;
  posix_spawn_file_actions_init(&actions);
  posix_spawn_file_actions_adddup2(&actions, pipe_fds[1], STDERR_FILENO);
  std::string arg = "--child=" + mode;
  std::vector<char*> args{const_cast<char*>(exe.c_str()), arg.data(), nullptr};
  pid_t pid = 0;
  int rc = ::posix_spawn(&pid, exe.c_str(), &actions, nullptr, args.data(), environ);
  posix_spawn_file_actions_destroy(&actions);
  ::close(pipe_fds[1]);
  if (rc != 0) {
    std::fprintf(stderr, "posix_spawn %s: %s\n", exe.c_str(), std::strerror(rc));
    ::close(pipe_fds[0]);
    return false;
  }
  char buffer[4096];
  while (true) {
    auto n = ::read(pipe_fds[0], buffer, sizeof(buffer));
    if (n > 0) {
      outcome.err.append(buffer, static_cast<std::size_t>(n));
    } else if (n == 0 || errno != EINTR) {
      break;
    }
  }
  ::close(pipe_fds[0]);
  while (::waitpid(pid, &outcome.wait_status, 0) < 0) {
    if (errno != EINTR) {
      std::perror("waitpid");
      return false;
    }
  }
  return true;
}

std::string describe(int wait_status) {
  if (WIFEXITED(wait_status)) {
    return "exit " + std::to_string(WEXITSTATUS(wait_status));
  }
  if (WIFSIGNALED(wait_status)) {
    return "signal " + std::to_string(WTERMSIG(wait_status));
  }
  return "status " + std::to_string(wait_status);
}

int parent(const char* argv0) {
  auto exe = self_executable(argv0);
  int failures = 0;

  ChildOutcome known;
  if (!run_child(exe, "dec-known", known)) {
    return 1;
  }
  if (!(WIFEXITED(known.wait_status) && WEXITSTATUS(known.wait_status) == 0)) {
    std::fprintf(stderr, "FAIL dec-known: expected exit 0, got %s\n%s\n", describe(known.wait_status).c_str(),
                 known.err.c_str());
    failures++;
  } else {
    std::printf("dec-known: exit 0 (positive control)\n");
  }

  ChildOutcome unknown;
  if (!run_child(exe, "dec-unknown", unknown)) {
    return 1;
  }
  bool abnormal =
      WIFSIGNALED(unknown.wait_status) || (WIFEXITED(unknown.wait_status) && WEXITSTATUS(unknown.wait_status) != 0);
  bool named = unknown.err.find(kUnknownCellMessage) != std::string::npos;
  if (!abnormal || !named) {
    std::fprintf(stderr, "FAIL dec-unknown: expected an abnormal end with \"%s\" on stderr, got %s\n%s\n",
                 kUnknownCellMessage, describe(unknown.wait_status).c_str(), unknown.err.c_str());
    failures++;
  } else {
    std::printf("dec-unknown: %s with \"%s\"\n", describe(unknown.wait_status).c_str(), kUnknownCellMessage);
  }

  if (failures != 0) {
    return 1;
  }
  std::printf("test-inmemory-celldb-dec: passed\n");
  return 0;
}

}  // namespace

int main(int argc, char** argv) {
  if (argc == 2 && std::strcmp(argv[1], "--child=dec-known") == 0) {
    return child_dec_known();
  }
  if (argc == 2 && std::strcmp(argv[1], "--child=dec-unknown") == 0) {
    return child_dec_unknown();
  }
  if (argc != 1) {
    std::fprintf(stderr, "usage: %s [--child=dec-known|--child=dec-unknown]\n", argv[0]);
    return 2;
  }
  return parent(argv[0]);
}
