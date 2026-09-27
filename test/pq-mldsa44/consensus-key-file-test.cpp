/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
// The validator node's consensus key, on disk.
//
// Every refusal here is about the local machine rather than the chain, so a node that
// meets one has been misconfigured and must not start. Each has an input only it
// refuses: a rule whose input is also refused by the rule before it is a rule nothing
// holds, and removing it would change no verdict.
#undef NDEBUG  // the build is Release, and an assert that is compiled out proves nothing
#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <string>
#include <sys/stat.h>
#include <unistd.h>

#include "consensus-key-file.h"

using namespace tos::pq;

namespace {

std::string scratch_directory() {
  std::string pattern = "/tmp/tos-consensus-key-XXXXXX";
  char* made = mkdtemp(pattern.data());
  assert(made != nullptr);
  return std::string(made);
}

ConsensusKeyFileError refusal(const std::variant<ValidatorPQKeyStore, ConsensusKeyFileError>& result) {
  assert(std::holds_alternative<ConsensusKeyFileError>(result));
  return std::get<ConsensusKeyFileError>(result);
}

void write_file(const std::string& path, const std::string& contents, mode_t mode) {
  std::ofstream out(path, std::ios::binary);
  out.write(contents.data(), static_cast<std::streamsize>(contents.size()));
  out.close();
  assert(::chmod(path.c_str(), mode) == 0);
}

}  // namespace

int main() {
  const std::string dir = scratch_directory();
  const std::string key = dir + "/consensus.key";

  // Creating one: owner-only from the moment it exists, and a real key comes back.
  auto created = create_consensus_key(key);
  assert(std::holds_alternative<ConsensusPQKey>(created));
  const auto& made = std::get<ConsensusPQKey>(created);
  assert(made.algorithm_id == PQAlgorithmId::mldsa44);
  assert(made.public_key.size() == mldsa44_public_key_bytes);
  {
    struct stat st{};
    assert(::stat(key.c_str(), &st) == 0);
    assert((st.st_mode & 077) == 0);
    assert(st.st_size == 32);
  }

  // The same file gives the same key every time, which is what lets a node restart
  // without its identity moving.
  auto loaded = load_consensus_key(key);
  assert(std::holds_alternative<ValidatorPQKeyStore>(loaded));
  assert(std::get<ValidatorPQKeyStore>(loaded).consensus_key().public_key == made.public_key);
  auto again = load_consensus_key(key);
  assert(std::holds_alternative<ValidatorPQKeyStore>(again));
  assert(std::get<ValidatorPQKeyStore>(again).consensus_key().public_key == made.public_key);

  // And it will not quietly replace a key that is there. Rotating one is a deliberate
  // removal, not an accident of running the command twice.
  auto twice = create_consensus_key(key);
  assert(std::holds_alternative<ConsensusKeyFileError>(twice));
  assert(std::get<ConsensusKeyFileError>(twice) == ConsensusKeyFileError::already_exists);

  // Absent.
  assert(refusal(load_consensus_key(dir + "/nothing-here")) == ConsensusKeyFileError::cannot_open);

  // A symlink to a perfectly good key: refused rather than followed, so the path an
  // operator configured is the file that is read.
  const std::string link = dir + "/link.key";
  assert(::symlink(key.c_str(), link.c_str()) == 0);
  assert(refusal(load_consensus_key(link)) == ConsensusKeyFileError::cannot_open);

  // A directory, inside a private one, so nothing about its surroundings can refuse it
  // and the rule under test is the only one left.
  const std::string inner = dir + "/inner";
  assert(::mkdir(inner.c_str(), 0700) == 0);
  assert(refusal(load_consensus_key(inner)) == ConsensusKeyFileError::not_a_regular_file);

  // Readable by the group: the right size, the right owner, one bit too many.
  const std::string shared = dir + "/shared.key";
  write_file(shared, std::string(32, 'k'), 0640);
  assert(refusal(load_consensus_key(shared)) == ConsensusKeyFileError::readable_by_others);

  // The right permissions and the wrong length, either way.
  const std::string short_key = dir + "/short.key";
  write_file(short_key, std::string(31, 'k'), 0600);
  assert(refusal(load_consensus_key(short_key)) == ConsensusKeyFileError::wrong_size);
  const std::string long_key = dir + "/long.key";
  write_file(long_key, std::string(33, 'k'), 0600);
  assert(refusal(load_consensus_key(long_key)) == ConsensusKeyFileError::wrong_size);

  // A directory anyone can write is a directory anyone can put a key in, so the key it
  // holds is refused however well protected the file itself is.
  const std::string open_dir = dir + "/open";
  assert(::mkdir(open_dir.c_str(), 0777) == 0);
  // `mkdir` is filtered by the process umask, so the mode asked for is not the mode
  // given. Without this the directory is often 0755, nothing refuses the key inside it,
  // and the case below stops being about the rule it names.
  assert(::chmod(open_dir.c_str(), 0777) == 0);
  {
    struct stat st{};
    assert(::stat(open_dir.c_str(), &st) == 0);
    assert((st.st_mode & (S_IWGRP | S_IWOTH)) == (S_IWGRP | S_IWOTH));
  }
  const std::string exposed = open_dir + "/consensus.key";
  write_file(exposed, std::string(32, 'k'), 0600);
  assert(refusal(load_consensus_key(exposed)) == ConsensusKeyFileError::directory_writable);
  // And one cannot be created there either.
  auto in_open = create_consensus_key(open_dir + "/new.key");
  assert(std::holds_alternative<ConsensusKeyFileError>(in_open));
  assert(std::get<ConsensusKeyFileError>(in_open) == ConsensusKeyFileError::directory_writable);

  // A key an operator saved and is putting back. It has to arrive at exactly the
  // identity it left with, or a restored validator is a different validator.
  const std::string restored = dir + "/restored.key";
  const std::string seed(consensus_seed_bytes, '\x2a');
  auto imported = import_consensus_key(restored, seed);
  assert(std::holds_alternative<ConsensusPQKey>(imported));
  const auto& put_back = std::get<ConsensusPQKey>(imported);
  {
    auto derived = ValidatorPQKeyStore::from_seed(seed);
    assert(derived.has_value());
    assert(derived->consensus_key().public_key == put_back.public_key);
    assert(derived->consensus_key().key_id == put_back.key_id);
  }
  // And the node reads back the same key from the file it wrote, under the same rules.
  {
    auto reread = load_consensus_key(restored);
    assert(std::holds_alternative<ValidatorPQKeyStore>(reread));
    assert(std::get<ValidatorPQKeyStore>(reread).consensus_key().public_key == put_back.public_key);
    struct stat st{};
    assert(::stat(restored.c_str(), &st) == 0);
    assert((st.st_mode & 077) == 0);
    assert(st.st_size == 32);
  }

  // A seed that is not a seed. Neither length is written, so a refused import leaves no
  // file for a later load to find and accept.
  for (std::size_t length : {std::size_t{0}, consensus_seed_bytes - 1, consensus_seed_bytes + 1}) {
    const std::string wrong = dir + "/wrong-" + std::to_string(length) + ".key";
    auto refused = import_consensus_key(wrong, std::string(length, '\x2a'));
    assert(std::holds_alternative<ConsensusKeyFileError>(refused));
    assert(std::get<ConsensusKeyFileError>(refused) == ConsensusKeyFileError::wrong_size);
    struct stat st{};
    assert(::stat(wrong.c_str(), &st) != 0);
  }

  // Putting a key back does not replace one that is there, and cannot be done into a
  // directory anyone can write: the same two rules a created key is held to.
  {
    auto over = import_consensus_key(restored, seed);
    assert(std::holds_alternative<ConsensusKeyFileError>(over));
    assert(std::get<ConsensusKeyFileError>(over) == ConsensusKeyFileError::already_exists);
    auto into_open = import_consensus_key(open_dir + "/restored.key", seed);
    assert(std::holds_alternative<ConsensusKeyFileError>(into_open));
    assert(std::get<ConsensusKeyFileError>(into_open) == ConsensusKeyFileError::directory_writable);
  }

  // Two rules have no input this test can build, and saying so is better than a case
  // that appears to cover them and does not:
  //
  //   the file is owned by this process   -- would mean creating a file as another user
  //   the directory flush succeeded       -- would mean a filesystem that fails fsync
  //
  // Both are held by reading the code rather than by running it. The second is the one
  // that decides whether a key reported as created survives a crash, so it is worth
  // knowing that it is the weaker of the checks here.

  std::printf(
      "CONSENSUS_KEY_FILE_OK create/load/import round-trips; symlink, directory, "
      "group-readable, short, long, and world-writable-directory each refused on their "
      "own; an import of the wrong length writes nothing\n");
  return 0;
}
