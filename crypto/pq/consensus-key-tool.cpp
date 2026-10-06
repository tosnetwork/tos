/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */

// Provisioning for the one post-quantum secret a validator host holds.
//
// The node reads its consensus key from a file it does not create. This puts one there,
// puts a saved one back, or says which key a file already holds -- under exactly the
// rules the node loads it by, so a key this reports as written is one the node will
// accept, and a key it refuses is one the node would have refused at startup.
//
// Nothing prints the expanded secret, and only one command prints the seed: `export`,
// which exists for the offline ceremony that binds a new key to its controller (the
// controller's `bind` needs the incoming key to cosign). It writes to a pipe and nowhere
// else, so the seed goes into `import` on the other side, or into an encryption program,
// and never onto a screen or into a file left behind by a redirect.
//
// It also points a stopped node at its key: `bind-node` writes the validator id and the
// key file into the node's configuration, after checking the key the way the node will;
// and, for a rotation without downtime, adds, removes and lists the further keys a node
// holds alongside it (`add-node-key`, `remove-node-key`, `list-node-keys`).

#include <array>
#include <cerrno>
#include <csignal>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <openssl/crypto.h>
#include <string>
#include <string_view>
#include <sys/stat.h>
#include <unistd.h>
#include <variant>

#include "consensus-key-file.h"
#include "consensus-node-config.h"
#include "seed-file.h"

namespace {

void print_hex(std::string_view bytes) {
  static const char digits[] = "0123456789abcdef";
  for (unsigned char c : bytes) {
    std::fputc(digits[c >> 4], stdout);
    std::fputc(digits[c & 15], stdout);
  }
}

// What a validator set records for this key, and nothing else. The identity is derived
// from the file every time rather than remembered, because the point of printing it is
// to compare it against what the chain says.
void report(const tos::pq::ConsensusPQKey& key) {
  std::fputs("algorithm mldsa44\nkey_id    ", stdout);
  print_hex(std::string_view(reinterpret_cast<const char*>(key.key_id.data()), key.key_id.size()));
  std::fputs("\npublic    ", stdout);
  print_hex(key.public_key);
  std::fputc('\n', stdout);
}

int refuse(tos::pq::ConsensusKeyFileError error, std::string_view path) {
  std::fprintf(stderr, "%.*s: %s\n", static_cast<int>(path.size()), path.data(), tos::pq::describe(error));
  return 1;
}

// A seed arrives as hexadecimal on standard input, never as an argument: an argument is
// visible to every process on the host for as long as this one runs.
//
// Whitespace is allowed around the digits and nowhere else. Allowing it between them
// would mean a seed could be written in more than one way, and two operators comparing
// what they typed against what a key derives would have no reason to expect the same
// answer.
bool read_seed_hex(std::string& seed) {
  constexpr std::size_t digits = 2 * tos::pq::consensus_seed_bytes;
  // Every ASCII space, not a chosen few: a seed pasted from a file that ends in a form
  // feed is the same seed, and refusing it would be a rule about the operator's editor.
  auto is_space = [](int c) { return c == ' ' || c == '\t' || c == '\n' || c == '\v' || c == '\f' || c == '\r'; };

  std::string text;
  bool ended = false;  // whitespace after the digits: nothing may follow it
  int c;
  while ((c = std::fgetc(stdin)) != EOF) {
    if (is_space(c)) {
      ended = !text.empty();
      continue;
    }
    if (ended || text.size() >= digits) {
      OPENSSL_cleanse(text.data(), text.size());
      return false;
    }
    text.push_back(static_cast<char>(c));
  }
  if (text.size() != digits) {
    OPENSSL_cleanse(text.data(), text.size());
    return false;
  }
  auto nibble = [](char h) -> int {
    if (h >= '0' && h <= '9') {
      return h - '0';
    }
    if (h >= 'a' && h <= 'f') {
      return h - 'a' + 10;
    }
    if (h >= 'A' && h <= 'F') {
      return h - 'A' + 10;
    }
    return -1;
  };
  seed.assign(tos::pq::consensus_seed_bytes, '\0');
  for (std::size_t i = 0; i < tos::pq::consensus_seed_bytes; i++) {
    const int hi = nibble(text[2 * i]);
    const int lo = nibble(text[2 * i + 1]);
    if (hi < 0 || lo < 0) {
      OPENSSL_cleanse(text.data(), text.size());
      OPENSSL_cleanse(seed.data(), seed.size());
      return false;
    }
    seed[i] = static_cast<char>(hi * 16 + lo);
  }
  OPENSSL_cleanse(text.data(), text.size());
  return true;
}

int usage() {
  std::fputs(
      "usage: tos-pq-consensus-key generate KEYFILE\n"
      "       tos-pq-consensus-key import KEYFILE   (64 hex characters on stdin)\n"
      "       tos-pq-consensus-key show KEYFILE\n"
      "       tos-pq-consensus-key export KEYFILE   (the seed to a pipe, never a terminal or file)\n"
      "       tos-pq-consensus-key bind-node [--replace] DB_ROOT KEYFILE VALIDATOR_ID\n"
      "       tos-pq-consensus-key add-node-key DB_ROOT KEYFILE VALID_FROM [EXPIRE_AT]\n"
      "       tos-pq-consensus-key remove-node-key DB_ROOT KEYFILE|KEY_ID\n"
      "       tos-pq-consensus-key list-node-keys DB_ROOT\n"
      "\n"
      "generate, import and show print the identity the validator set records for the\n"
      "key. Only export prints the key itself.\n"
      "\n"
      "bind-node sets extraconfig.pq_consensus in DB_ROOT/config.json, where DB_ROOT is\n"
      "the node's -D directory. Run it as the node's service account: it checks KEYFILE\n"
      "(an absolute path) under the rules the node loads it by. VALIDATOR_ID is the\n"
      "controller's account id, as 64 hex digits or -1:<64 hex digits>. A different\n"
      "binding already there is replaced only with --replace. It holds\n"
      "DB_ROOT/config.json.lock for the whole edit; a running node holds the same lock,\n"
      "so bind-node refuses while the node runs and the node refuses to start meanwhile.\n"
      "It refuses a configuration with content the engine's schema would drop. Exit\n"
      "status: 0 bound (or already bound), 1 refused, nothing written, 3 written but\n"
      "the directory flush failed, so durability is unconfirmed.\n"
      "\n"
      "add-node-key, remove-node-key and list-node-keys manage the several keys a bound\n"
      "node holds during a consensus key rotation. add-node-key and remove-node-key edit\n"
      "a stopped node's configuration exactly as bind-node does, with the same lock and\n"
      "exit statuses; a running node is changed with the console instead\n"
      "(add-pq-consensus-key, del-pq-consensus-key, get-pq-consensus-keys), which takes\n"
      "effect without a restart. VALID_FROM is the first election date (unix time) the\n"
      "key signs stakes for: a stake for an election is signed with the held key whose\n"
      "VALID_FROM is the greatest not after the election date, so two keys may not share\n"
      "one. EXPIRE_AT (unix time, default 0: never) is when the node stops using the key\n"
      "at all. A key signs for a validator group only when that group's validator set\n"
      "lists it. remove-node-key cannot see validator sets: it refuses only the last key.\n"
      "list-node-keys reads without the lock and works beside a running node.\n"
      "\n"
      "Rotating the consensus key from A to B (a kind 3 bind) without downtime. The node\n"
      "holds A and B together: A keeps signing for every validator set that lists A,\n"
      "and B signs every stake from the next election on.\n"
      "  1. offline:   tos-pq-consensus-key generate NEXT.seed   (note its key_id, B)\n"
      "  2. offline:   tos-pq-consensus-key export NEXT.seed | ENCRYPT > MEDIUM\n"
      "     host:      DECRYPT < MEDIUM | tos-pq-consensus-key import KEYDIR/pq-consensus-next.seed\n"
      "     (or, with a direct link, export | ssh HOST tos-pq-consensus-key import ...)\n"
      "  3. host:      add B alongside A, valid from the next election's date E (or any\n"
      "     time after the current election's date):\n"
      "       running node:  validator-engine-console: add-pq-consensus-key\n"
      "                        KEYDIR/pq-consensus-next.seed E 0\n"
      "       stopped node:  tos-pq-consensus-key add-node-key DB_ROOT\n"
      "                        KEYDIR/pq-consensus-next.seed E\n"
      "     and confirm with get-pq-consensus-keys (or list-node-keys) that both are held.\n"
      "  4. offline, before the stake for election E is due:\n"
      "                tos-pq-controller bind ROOTSEED GLOBAL_ID CONTROLLER_HEX EPOCH\n"
      "                  NONCE VALID_UNTIL NEXT.seed   and send the body from a wallet;\n"
      "     check that the controller_state getter shows B\n"
      "  5. the stake for election E is signed with B (create-stake-authorization picks\n"
      "     it by its window; create-stake-authorization-with-key names it explicitly).\n"
      "     Confirm the elector accepted it.\n"
      "  6. keep A until no validator set lists it any more: the set that lists A has\n"
      "     ended (its utime_until has passed and Config34, and Config36 while a next set\n"
      "     is pending, list this controller with B) and no stake is still held under A.\n"
      "  7. remove A: del-pq-consensus-key A on the running node (it refuses while a\n"
      "     current, previous or next set lists A), or remove-node-key on a stopped one.\n"
      "  8. destroy every other copy of A's seed and of B's seed except the encrypted\n"
      "     offline backup of B.\n",
      stderr);
  return 2;
}

// The seed, as the 64 digits `import` reads, to standard output -- but only when standard
// output is a pipe or a socket. A terminal would put the seed on a screen and in its
// scrollback; a regular file would leave it on a disk, readable under whatever umask the
// shell had. Both are refused before the key is read.
int export_seed(std::string_view path) {
  struct stat out{};
  if (::fstat(STDOUT_FILENO, &out) != 0 || ::isatty(STDOUT_FILENO) ||
      !(S_ISFIFO(out.st_mode) || S_ISSOCK(out.st_mode))) {
    std::fputs(
        "refusing to export: standard output is not a pipe. Pipe the seed into\n"
        "`tos-pq-consensus-key import` or an encryption program; it is never written to a\n"
        "terminal or a file.\n",
        stderr);
    return 1;
  }

  tos::pq::detail::SeedBuffer seed;
  if (auto refused = tos::pq::detail::read_protected_seed(path, seed)) {
    return refuse(tos::pq::consensus_key_refusal(*refused), path);
  }
  // The identity is derived from the bytes about to be written, not from a second read of
  // the file, so what the operator is told is what they sent.
  auto store = tos::pq::ValidatorPQKeyStore::from_seed(
      std::string_view(reinterpret_cast<const char*>(seed.bytes.data()), seed.bytes.size()));
  if (!store.has_value()) {
    return refuse(tos::pq::ConsensusKeyFileError::derivation_failed, path);
  }

  std::array<char, 2 * tos::pq::consensus_seed_bytes + 1> text{};
  static const char digits[] = "0123456789abcdef";
  for (std::size_t i = 0; i < seed.bytes.size(); i++) {
    text[2 * i] = digits[seed.bytes[i] >> 4];
    text[2 * i + 1] = digits[seed.bytes[i] & 15];
  }
  text[text.size() - 1] = '\n';

  // A reader that goes away must be an error this reports, not a signal that ends the
  // process before it can say the seed did not arrive.
  std::signal(SIGPIPE, SIG_IGN);
  std::size_t written = 0;
  bool complete = true;
  while (written < text.size()) {
    const auto n = ::write(STDOUT_FILENO, text.data() + written, text.size() - written);
    if (n < 0 && errno == EINTR) {
      continue;
    }
    if (n <= 0) {
      complete = false;
      break;
    }
    written += static_cast<std::size_t>(n);
  }
  OPENSSL_cleanse(text.data(), text.size());
  if (!complete) {
    std::fputs("the seed could not be written in full to standard output\n", stderr);
    return 1;
  }

  const auto& key_id = store->consensus_key().key_id;
  std::fputs(
      "WARNING: the consensus seed for this key was written to standard output.\n"
      "WARNING: whoever holds it can sign as this validator. Import it, or encrypt it,\n"
      "WARNING: and leave no other copy.\n"
      "key_id    ",
      stderr);
  for (unsigned char c : key_id) {
    std::fputc(digits[c >> 4], stderr);
    std::fputc(digits[c & 15], stderr);
  }
  std::fputc('\n', stderr);
  return 0;
}

int bind_node(int argc, char** argv) {
  tos::pq::NodeConsensusBinding binding;
  int next = 2;
  if (argc == 6 && std::string_view(argv[2]) == "--replace") {
    binding.replace = true;
    next = 3;
  } else if (argc != 5) {
    return usage();
  }
  binding.db_root = argv[next];
  binding.key_file = argv[next + 1];
  std::string why;
  if (!tos::pq::parse_validator_id(argv[next + 2], binding.validator_id, why)) {
    std::fprintf(stderr, "%s\n", why.c_str());
    return 1;
  }
  tos::pq::NodeConsensusBindingResult result;
  const auto outcome = tos::pq::bind_node_consensus_key(binding, result, why);
  const char* state = nullptr;
  switch (outcome) {
    case tos::pq::NodeBindingOutcome::refused:
      std::fprintf(stderr, "%s\n", why.c_str());
      return 1;
    case tos::pq::NodeBindingOutcome::unchanged:
      state = "unchanged";
      break;
    case tos::pq::NodeBindingOutcome::applied:
    case tos::pq::NodeBindingOutcome::applied_not_durable:
      state = "updated";
      break;
  }
  std::fputs("validator_id ", stdout);
  print_hex(std::string_view(reinterpret_cast<const char*>(binding.validator_id.data()), binding.validator_id.size()));
  std::fputs("\nkey_id       ", stdout);
  print_hex(std::string_view(reinterpret_cast<const char*>(result.key_id.data()), result.key_id.size()));
  std::fprintf(stdout, "\nkey_file     %s\nconfig       %s %s\n", binding.key_file.c_str(), result.config_path.c_str(),
               state);
  if (outcome == tos::pq::NodeBindingOutcome::applied_not_durable) {
    // The binding is in place and the node will read it; only its survival of a crash is
    // unconfirmed. A distinct status lets a script tell this from both success and refusal.
    std::fprintf(stderr,
                 "%s\nthe new configuration is in place, but not confirmed durable: run `sync` before relying "
                 "on it\n",
                 why.c_str());
    return 3;
  }
  return 0;
}

// A unix time as an operator types it: decimal digits, nothing else, at most 2^32 - 1.
bool parse_unix_time(std::string_view text, std::uint32_t& out) {
  if (text.empty() || text.size() > 10) {
    return false;
  }
  std::uint64_t value = 0;
  for (char c : text) {
    if (c < '0' || c > '9') {
      return false;
    }
    value = value * 10 + static_cast<std::uint64_t>(c - '0');
  }
  if (value > 0xffffffffULL) {
    return false;
  }
  out = static_cast<std::uint32_t>(value);
  return true;
}

std::uint32_t unix_now() {
  const auto now = std::time(nullptr);
  if (now <= 0) {
    return 0;
  }
  return static_cast<std::uint64_t>(now) > 0xffffffffULL ? 0xffffffffU : static_cast<std::uint32_t>(now);
}

// What every configuration edit reports: the key, the file, and whether anything changed.
int report_edit(tos::pq::NodeBindingOutcome outcome, const tos::pq::NodeConsensusBindingResult& result,
                std::string_view key_file, const std::string& why) {
  const char* state = nullptr;
  switch (outcome) {
    case tos::pq::NodeBindingOutcome::refused:
      std::fprintf(stderr, "%s\n", why.c_str());
      return 1;
    case tos::pq::NodeBindingOutcome::unchanged:
      state = "unchanged";
      break;
    case tos::pq::NodeBindingOutcome::applied:
    case tos::pq::NodeBindingOutcome::applied_not_durable:
      state = "updated";
      break;
  }
  std::fputs("key_id       ", stdout);
  print_hex(std::string_view(reinterpret_cast<const char*>(result.key_id.data()), result.key_id.size()));
  std::fprintf(stdout, "\nkey_file     %.*s\nconfig       %s %s\n", static_cast<int>(key_file.size()), key_file.data(),
               result.config_path.c_str(), state);
  if (outcome == tos::pq::NodeBindingOutcome::applied_not_durable) {
    std::fprintf(stderr,
                 "%s\nthe new configuration is in place, but not confirmed durable: run `sync` before relying "
                 "on it\n",
                 why.c_str());
    return 3;
  }
  return 0;
}

int add_node_key(int argc, char** argv) {
  if (argc != 5 && argc != 6) {
    return usage();
  }
  tos::pq::NodeConsensusKeyAddition addition;
  addition.db_root = argv[2];
  addition.key_file = argv[3];
  if (!parse_unix_time(argv[4], addition.valid_from)) {
    std::fputs("VALID_FROM is a unix time: decimal digits, at most 4294967295\n", stderr);
    return 1;
  }
  if (argc == 6 && !parse_unix_time(argv[5], addition.expire_at)) {
    std::fputs("EXPIRE_AT is a unix time: decimal digits, at most 4294967295 (0: never)\n", stderr);
    return 1;
  }
  addition.now = unix_now();
  tos::pq::NodeConsensusBindingResult result;
  std::string why;
  const auto outcome = tos::pq::add_node_consensus_key(addition, result, why);
  return report_edit(outcome, result, addition.key_file, why);
}

int remove_node_key(int argc, char** argv) {
  if (argc != 4) {
    return usage();
  }
  tos::pq::NodeConsensusKeyRemoval removal;
  removal.db_root = argv[2];
  removal.key = argv[3];
  tos::pq::NodeConsensusBindingResult result;
  std::string why;
  const auto outcome = tos::pq::remove_node_consensus_key(removal, result, why);
  return report_edit(outcome, result, removal.key, why);
}

int list_node_keys(int argc, char** argv) {
  if (argc != 3) {
    return usage();
  }
  tos::pq::NodeConsensusKeyListing listing;
  std::string why;
  if (!tos::pq::list_node_consensus_keys(argv[2], unix_now(), listing, why)) {
    std::fprintf(stderr, "%s\n", why.c_str());
    return 1;
  }
  std::fputs("validator_id ", stdout);
  print_hex(std::string_view(reinterpret_cast<const char*>(listing.validator_id.data()), listing.validator_id.size()));
  std::fputc('\n', stdout);
  for (const auto& key : listing.keys) {
    std::fputs("key ", stdout);
    if (key.loaded) {
      print_hex(std::string_view(reinterpret_cast<const char*>(key.key_id.data()), key.key_id.size()));
    } else {
      std::fputs("unreadable", stdout);
    }
    std::fprintf(stdout, " valid_from %u expire_at %u%s%s file %s\n", key.entry.valid_from, key.entry.expire_at,
                 key.expired ? " expired" : "", key.entry.primary ? " primary" : "", key.entry.key_file.c_str());
    if (!key.loaded) {
      std::fprintf(stdout, "  (%s)\n", key.refusal.c_str());
    }
  }
  return 0;
}

}  // namespace

int main(int argc, char** argv) {
  if (argc >= 2 && std::string_view(argv[1]) == "bind-node") {
    return bind_node(argc, argv);
  }
  if (argc >= 2 && std::string_view(argv[1]) == "add-node-key") {
    return add_node_key(argc, argv);
  }
  if (argc >= 2 && std::string_view(argv[1]) == "remove-node-key") {
    return remove_node_key(argc, argv);
  }
  if (argc >= 2 && std::string_view(argv[1]) == "list-node-keys") {
    return list_node_keys(argc, argv);
  }
  if (argc != 3) {
    return usage();
  }
  const std::string_view command(argv[1]);
  const std::string_view path(argv[2]);

  if (command == "export") {
    return export_seed(path);
  }

  if (command == "generate") {
    auto made = tos::pq::create_consensus_key(path);
    if (std::holds_alternative<tos::pq::ConsensusKeyFileError>(made)) {
      return refuse(std::get<tos::pq::ConsensusKeyFileError>(made), path);
    }
    report(std::get<tos::pq::ConsensusPQKey>(made));
    return 0;
  }

  if (command == "import") {
    std::string seed;
    if (!read_seed_hex(seed)) {
      std::fputs("a consensus key is 64 hexadecimal characters, and nothing but space around them\n", stderr);
      return 1;
    }
    auto placed = tos::pq::import_consensus_key(path, seed);
    OPENSSL_cleanse(seed.data(), seed.size());
    if (std::holds_alternative<tos::pq::ConsensusKeyFileError>(placed)) {
      return refuse(std::get<tos::pq::ConsensusKeyFileError>(placed), path);
    }
    report(std::get<tos::pq::ConsensusPQKey>(placed));
    return 0;
  }

  if (command == "show") {
    auto loaded = tos::pq::load_consensus_key(path);
    if (std::holds_alternative<tos::pq::ConsensusKeyFileError>(loaded)) {
      return refuse(std::get<tos::pq::ConsensusKeyFileError>(loaded), path);
    }
    report(std::get<tos::pq::ValidatorPQKeyStore>(loaded).consensus_key());
    return 0;
  }

  return usage();
}
