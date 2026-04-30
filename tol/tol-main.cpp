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
#include "tol-version.h"
#include "compiler-state.h"
#include "compiler-settings.h"
#include "td/utils/port/path.h"
#include <getopt.h>
#include <cerrno>
#include <cctype>
#include <fstream>
#include <set>
#include <sys/stat.h>
#include <vector>
#ifdef TD_DARWIN
#include <mach-o/dyld.h>
#elif TD_WINDOWS
#include <windows.h>
#include <direct.h>
#else  // linux
#include <unistd.h>
#endif
#include "git.h"
#include "json-output.h"

using namespace tol;

enum LongOnlyOptions {
  OPT_BOC_OUTPUT = 256,
  OPT_PATH_MAPPING,
  OPT_NO_STACK_COMMENTS,
  OPT_NO_LINE_COMMENTS,
  OPT_JSON_ERRORS,
  OPT_CHECK_ONLY,
  OPT_ALLOW_NO_ENTRYPOINT,
};

static struct option long_options[] = {
  {"output", required_argument, nullptr, 'o'},
  {"boc-output", required_argument, nullptr, OPT_BOC_OUTPUT},
  {"opt-level", required_argument, nullptr, 'O'},
  {"path-mapping", required_argument, nullptr, OPT_PATH_MAPPING},
  {"no-stack-comments", no_argument, nullptr, OPT_NO_STACK_COMMENTS},
  {"no-line-comments", no_argument, nullptr, OPT_NO_LINE_COMMENTS},
  {"json-errors", no_argument, nullptr, OPT_JSON_ERRORS},
  {"check-only", no_argument, nullptr, OPT_CHECK_ONLY},
  {"allow-no-entrypoint", no_argument, nullptr, OPT_ALLOW_NO_ENTRYPOINT},
  {"verbose", no_argument, nullptr, 'e'},
  {"version", no_argument, nullptr, 'V'},
  {"help", no_argument, nullptr, 'h'},
  {nullptr, 0, nullptr, 0}
};

void usage(const char* progname) {
  std::cerr
      << "usage: " << progname << " [options] <filename.tol>\n"
            "       " << progname << " new --pattern <jetton|nft|wallet|multisig> [--name <Name>] [--output <dir>] [--force]\n"
            "\tGenerates Fift TVM assembler code from a .tol file\n"
         "new --pattern <name>\n"
            "\tCreate a Slice 3 stdlib scaffold project for a supported pattern\n"
         "-o, --output <fif-filename>\n"
            "\tWrite generated code into specified .fif file instead of stdout\n"
         "--boc-output <boc-filename>\n"
            "\tGenerate Fift instructions to save TVM bytecode into .boc file\n"
         "-O, --opt-level <level>\n"
            "\tSet optimization level (2 by default)\n"
         "--path-mapping <mapping>\n"
            "\tRegister @name -> path mapping (e.g. @mylib=/path/to/lib)\n"
         "--no-stack-comments\n"
            "\tDon't include stack layout comments into Fift output\n"
         "--no-line-comments\n"
            "\tDon't include original lines from Tol src into Fift output\n"
         "--json-errors\n"
            "\tShow compilation errors in JSON (not human-readable) format\n"
         "--check-only\n"
            "\tCheck sources for errors without generating code (for IDE in background)\n"
         "--allow-no-entrypoint\n"
            "\tDo not require main/onInternalMessage (e.g. to compile only get-methods)\n"
         "-e, --verbose\n"
            "\tIncrease verbosity level (extra output into stderr)\n"
         "-v, --version\n"
            "\tOutput version of Tol and exit\n"
         "-h, --help\n"
            "\tShow this help message\n";
  std::exit(2);
}

static bool is_supported_new_pattern(const std::string& pattern) {
  static const std::set<std::string> supported = {"jetton", "nft", "wallet", "multisig"};
  return supported.count(pattern) != 0;
}

static std::string default_scaffold_name(const std::string& pattern) {
  if (pattern == "jetton") {
    return "JettonScaffold";
  }
  if (pattern == "nft") {
    return "NftScaffold";
  }
  if (pattern == "wallet") {
    return "WalletScaffold";
  }
  return "MultisigScaffold";
}

static bool is_tol_ident(const std::string& name) {
  if (name.empty() || !(std::isalpha(static_cast<unsigned char>(name[0])) || name[0] == '_')) {
    return false;
  }
  for (char c : name) {
    if (!(std::isalnum(static_cast<unsigned char>(c)) || c == '_')) {
      return false;
    }
  }
  return true;
}

static std::string replace_all(std::string s, const std::string& needle, const std::string& replacement) {
  size_t pos = 0;
  while ((pos = s.find(needle, pos)) != std::string::npos) {
    s.replace(pos, needle.size(), replacement);
    pos += replacement.size();
  }
  return s;
}

static bool path_exists(const std::string& path) {
  struct stat f_stat;
  return stat(path.c_str(), &f_stat) == 0;
}

static bool mkdir_one(const std::string& path) {
  if (path.empty() || path_exists(path)) {
    return true;
  }
#ifdef TD_WINDOWS
  int res = _mkdir(path.c_str());
#else
  int res = mkdir(path.c_str(), 0755);
#endif
  return res == 0 || errno == EEXIST;
}

static bool mkdir_recursive(const std::string& path) {
  std::string current;
  for (char c : path) {
    current.push_back(c);
    if (c == '/' || c == '\\') {
      if (!mkdir_one(current)) {
        return false;
      }
    }
  }
  return mkdir_one(path);
}

static std::string join_scaffold_path(const std::string& dir, const std::string& child) {
  if (dir.empty() || dir.back() == '/' || dir.back() == '\\') {
    return dir + child;
  }
  return dir + "/" + child;
}

static bool write_scaffold_file(const std::string& path, const std::string& content, bool force) {
  if (!force && path_exists(path)) {
    std::cerr << "tol new: refusing to overwrite existing file " << path << " (use --force)\n";
    return false;
  }
  std::ofstream out(path);
  if (!out.is_open()) {
    std::cerr << "tol new: failed to create " << path << "\n";
    return false;
  }
  out << content;
  return true;
}

static std::string scaffold_source_template(const std::string& pattern) {
  if (pattern == "jetton") {
    return R"TOL(import "@stdlib/jetton"

struct {{NAME}}Storage {
    totalSupply: coins;
    adminAddress: any_address;
    content: cell;
    jettonWalletCode: cell;
}

struct (JETTON_OP_MINT) {{NAME}}Mint {
    queryId: uint64;
    toAddress: any_address;
    amount: coins;
    masterMsg: cell;
}

fun scaffoldPatternId(): int {
    return jettonPatternManifestHeader().patternId;
}

contract {{NAME}} {
    storage: {{NAME}}Storage
    @unknown_throw(65535);

    @disclaim_query_id
    receive(msg: {{NAME}}Mint) {
        require(jettonSameInternalAndAnyAddressBits(in.senderAddress, storage.adminAddress),
                ErrorClass.Authorization, JETTON_MINTER_FUNC_THROW_ADMIN_REQUIRED);
        msg.masterMsg;
        save(storage);
    }
}
)TOL";
  }
  if (pattern == "nft") {
    return R"TOL(import "@stdlib/nft"

struct {{NAME}}Storage {
    ownerAddress: any_address;
    nextItemIndex: uint64;
    collectionContent: cell;
    nftItemCode: cell;
}

struct (NFT_COLLECTION_OP_MINT) {{NAME}}Mint {
    queryId: uint64;
    itemIndex: uint64;
    amount: coins;
    owner: any_address;
    individualContent: cell;
}

fun scaffoldPatternId(): int {
    return nftPatternManifestHeader().patternId;
}

contract {{NAME}} {
    storage: {{NAME}}Storage
    @unknown_throw(65535);

    @disclaim_query_id
    receive(msg: {{NAME}}Mint) {
        require(nftSameAddressBits(in.senderAddress, storage.ownerAddress),
                ErrorClass.Authorization, NFT_COLLECTION_FUNC_THROW_UNAUTHORIZED);
        val stateInit = nftItemStateInit(msg.itemIndex, contract.getAddress(), storage.nftItemCode);
        val itemAddress = nftItemAddress(BASECHAIN, stateInit);
        val itemContent = nftMintItemContent(msg.owner, msg.individualContent);
        sendRawMessage(nftBuildDeployItemMessage(itemAddress, msg.amount, stateInit, itemContent),
                       SEND_MODE_PAY_FEES_SEPARATELY);
        if (msg.itemIndex == storage.nextItemIndex) {
            save({{NAME}}Storage {
                ownerAddress: storage.ownerAddress,
                nextItemIndex: storage.nextItemIndex + 1,
                collectionContent: storage.collectionContent,
                nftItemCode: storage.nftItemCode,
            });
        }
    }
}
)TOL";
  }
  if (pattern == "wallet") {
    return R"TOL(import "@stdlib/wallet"

struct {{NAME}}Storage {
    isSignatureAllowed: bool;
    seqno: uint32;
    walletId: uint32;
    publicKey: uint256;
    extensions: dict;
}

struct (WALLET_V5_PREFIX_EXTENSION_ACTION) {{NAME}}ExtensionAction {
    queryId: uint64;
    actions: RemainingBitsAndRefs;
}

struct (WALLET_V5_PREFIX_SIGNED_INTERNAL) {{NAME}}SignedInternal {
    signedBody: RemainingBitsAndRefs;
}

fun scaffoldPatternId(): int {
    return walletPatternManifestHeader().patternId;
}

@on_bounced_policy("manual")
contract {{NAME}} {
    storage: {{NAME}}Storage
    @unknown_silent_drop;

    @disclaim_query_id
    receive(msg: {{NAME}}ExtensionAction) {
        var actions = msg.actions;
        val c5Actions = actions.loadMaybeRef();
        if (c5Actions != null) {
            walletV5VerifyC5Actions(c5Actions!, false);
        }
    }

    receive(msg: {{NAME}}SignedInternal) {
        if (in.body.remainingBitsCount() < WALLET_V5_SIZE_MESSAGE_OPERATION_PREFIX + WALLET_V5_SIZE_GLOBAL_ID + WALLET_V5_SIZE_WALLET_ID + WALLET_V5_SIZE_VALID_UNTIL + WALLET_V5_SIZE_SEQNO + WALLET_V5_SIZE_SIGNATURE) {
            return;
        }
        walletV5ParseSignedRequestHeader(in.body);
    }

    receive_external(msg: UnknownOpcode) {
        throw WALLET_V5_FUNC_THROW_INVALID_MESSAGE_OPERATION;
    }
}
)TOL";
  }
  return R"TOL(import "@stdlib/multisig"

struct {{NAME}}Storage {
    config: MultisigConfig;
    pending: dict;
}

struct (0x4d534947) {{NAME}}Submit {
    queryId: uint64;
    validUntil: uint32;
    signer: uint256;
    actions: cell;
}

fun scaffoldPatternId(): int {
    return multisigPatternManifestHeader().patternId;
}

contract {{NAME}} {
    storage: {{NAME}}Storage
    @unknown_throw(1807);

    @disclaim_query_id
    receive(msg: {{NAME}}Submit) {
        multisigRequireValidThreshold(storage.config.threshold, storage.config.signerCount);
        multisigRequireSigner(storage.config.signers, msg.signer);
        multisigRequireNewProposal(storage.pending, msg.queryId);
        multisigRequireNotExpired(msg.validUntil, blockchain.now());
        multisigValidateActions(msg.actions, false);
        save({{NAME}}Storage {
            config: storage.config,
            pending: multisigAddPendingProposal(storage.pending, msg.queryId),
        });
    }
}
)TOL";
}

static std::string scaffold_test_template(const std::string& pattern) {
  return R"TOL(import "@stdlib/slice3-common"
import "../src/main"

@method_id(101)
fun test_scaffold_pattern(): int {
    return scaffoldPatternId();
}

/**
@testcase | 101 | | {{PATTERN_ID}}
 */
)TOL";
}

static std::string scaffold_manifest_template(const std::string& pattern, const std::string& name) {
  return R"JSON({
  "version": 1,
  "schema": "slice-3-generated-project",
  "pattern": "{{PATTERN}}",
  "contract": "{{NAME}}",
  "stdlib_import": "@stdlib/{{PATTERN}}",
  "source": "src/main.tol",
  "tests": [
    "tests/{{PATTERN}}-positive.tol"
  ],
  "replay_fixtures": [
    "replay/{{PATTERN}}-replay.json"
  ],
  "observability": {
    "opcodes": "artifacts/opcodes.json",
    "method_ids": "artifacts/method-ids.json",
    "error_codes": "artifacts/error-codes.json",
    "replay_trace": "artifacts/replay-trace.json"
  }{{BEHAVIOUR_CONFORMANCE}}
}
)JSON";
}

static std::string scaffold_behaviour_conformance(const std::string& pattern) {
  std::string behaviour = "request_server";
  std::string mode = "raw";
  if (pattern == "jetton") {
    behaviour = "jetton_wallet";
    mode = "generated";
  } else if (pattern == "nft") {
    behaviour = "nft_item";
    mode = "generated";
  } else if (pattern == "multisig") {
    behaviour = "multisig";
    mode = "generated";
  }
  return std::string(",\n") +
         "  \"behaviour_conformance\": [\n" +
         "    {\n" +
         "      \"behaviour\": \"" + behaviour + "\",\n" +
         "      \"manifest\": \"doc/slice4-behaviours/" + behaviour + ".json\",\n" +
         "      \"mode\": \"" + mode + "\"\n" +
         "    }\n" +
         "  ]";
}

static std::string scaffold_replay_template(const std::string& pattern, const std::string& name) {
  return R"JSON({
  "version": 1,
  "schema": "slice-3-generated-replay-trace",
  "pattern": "{{PATTERN}}",
  "contract": "{{NAME}}",
  "cases": [
    {
      "name": "compile-and-positive-test",
      "kind": "tol-tester",
      "source": "tests/{{PATTERN}}-positive.tol",
      "expected_exit_code": 0
    }
  ]
}
)JSON";
}

static std::string scaffold_readme_template(const std::string& pattern, const std::string& name) {
  return R"MD(# {{NAME}}

Generated by `tol new --pattern {{PATTERN}}`.

## Build

```sh
tol --check-only src/main.tol
```

## Test

```sh
tol-tester tests {{PATTERN}}-positive
```

## Files

- `src/main.tol` - scaffold contract using `@stdlib/{{PATTERN}}`
- `tests/{{PATTERN}}-positive.tol` - smoke test for the generated pattern
- `replay/{{PATTERN}}-replay.json` - deterministic replay trace stub
- `deploy/deploy.json` - deployment skeleton
- `artifacts/*.json` - opcode, method-id, error-code, and replay observability maps
)MD";
}

static int scaffold_pattern_id(const std::string& pattern) {
  if (pattern == "jetton") return 2;
  if (pattern == "nft") return 3;
  if (pattern == "wallet") return 4;
  return 5;
}

static std::string scaffold_opcode_map(const std::string& pattern) {
  if (pattern == "jetton") {
    return R"JSON({
  "opcodes": [
    {"name": "JETTON_OP_MINT", "hex": "0x00000015"},
    {"name": "JETTON_OP_TRANSFER", "hex": "0x0f8a7ea5"},
    {"name": "JETTON_OP_INTERNAL_TRANSFER", "hex": "0x178d4519"},
    {"name": "JETTON_OP_BURN", "hex": "0x595f07bc"}
  ]
}
)JSON";
  }
  if (pattern == "nft") {
    return R"JSON({
  "opcodes": [
    {"name": "NFT_COLLECTION_OP_MINT", "hex": "0x00000001"},
    {"name": "NFT_OP_TRANSFER", "hex": "0x5fcc3d14"},
    {"name": "NFT_OP_OWNERSHIP_ASSIGNED", "hex": "0x05138d91"},
    {"name": "NFT_OP_REPORT_STATIC_DATA", "hex": "0x8b771735"}
  ]
}
)JSON";
  }
  if (pattern == "wallet") {
    return R"JSON({
  "opcodes": [
    {"name": "WALLET_V5_PREFIX_SIGNED_EXTERNAL", "hex": "0x7369676e"},
    {"name": "WALLET_V5_PREFIX_SIGNED_INTERNAL", "hex": "0x73696e74"},
    {"name": "WALLET_V5_PREFIX_EXTENSION_ACTION", "hex": "0x6578746e"}
  ]
}
)JSON";
  }
  return R"JSON({
  "opcodes": [
    {"name": "MULTISIG_SUBMIT", "hex": "0x4d534947"}
  ]
}
)JSON";
}

static bool materialize_scaffold(const std::string& output_dir, const std::string& pattern, const std::string& name, bool force) {
  for (const std::string& dir : {"src", "tests", "replay", "deploy", "artifacts"}) {
    if (!mkdir_recursive(join_scaffold_path(output_dir, dir))) {
      std::cerr << "tol new: failed to create directory " << join_scaffold_path(output_dir, dir) << "\n";
      return false;
    }
  }

  auto fill = [&](std::string content) {
    content = replace_all(std::move(content), "{{PATTERN}}", pattern);
    content = replace_all(std::move(content), "{{NAME}}", name);
    content = replace_all(std::move(content), "{{PATTERN_ID}}", std::to_string(scaffold_pattern_id(pattern)));
    content = replace_all(std::move(content), "{{BEHAVIOUR_CONFORMANCE}}", scaffold_behaviour_conformance(pattern));
    return content;
  };

  std::vector<std::pair<std::string, std::string>> files = {
      {"src/main.tol", fill(scaffold_source_template(pattern))},
      {"tests/" + pattern + "-positive.tol", fill(scaffold_test_template(pattern))},
      {"replay/" + pattern + "-replay.json", fill(scaffold_replay_template(pattern, name))},
      {"deploy/deploy.json", fill(R"JSON({
  "version": 1,
  "pattern": "{{PATTERN}}",
  "contract": "{{NAME}}",
  "source": "src/main.tol",
  "network": "local",
  "state_init": {
    "code": "build/{{NAME}}.code.boc",
    "data": "build/{{NAME}}.data.boc"
  }
}
)JSON")},
      {"manifest.json", fill(scaffold_manifest_template(pattern, name))},
      {"README.md", fill(scaffold_readme_template(pattern, name))},
      {"artifacts/opcodes.json", scaffold_opcode_map(pattern)},
      {"artifacts/method-ids.json", "{\n  \"method_ids\": []\n}\n"},
      {"artifacts/error-codes.json", "{\n  \"error_codes\": []\n}\n"},
      {"artifacts/replay-trace.json", fill(scaffold_replay_template(pattern, name))},
  };

  for (const auto& [relative, content] : files) {
    if (!write_scaffold_file(join_scaffold_path(output_dir, relative), content, force)) {
      return false;
    }
  }
  return true;
}

static int tol_new_usage(const char* progname) {
  std::cerr << "usage: " << progname << " new --pattern <jetton|nft|wallet|multisig> [--name <Name>] [--output <dir>] [--force]\n";
  return 2;
}

static int run_new_command(int argc, char* const argv[]) {
  std::string pattern;
  std::string name;
  std::string output_dir;
  bool force = false;
  for (int i = 2; i < argc; ++i) {
    std::string arg = argv[i];
    auto read_value = [&](const char* option) -> std::string {
      if (i + 1 >= argc) {
        std::cerr << "tol new: " << option << " requires a value\n";
        return {};
      }
      return argv[++i];
    };
    if (arg == "--pattern") {
      pattern = read_value("--pattern");
    } else if (arg.rfind("--pattern=", 0) == 0) {
      pattern = arg.substr(strlen("--pattern="));
    } else if (arg == "--name") {
      name = read_value("--name");
    } else if (arg.rfind("--name=", 0) == 0) {
      name = arg.substr(strlen("--name="));
    } else if (arg == "--output" || arg == "-o") {
      output_dir = read_value(arg.c_str());
    } else if (arg.rfind("--output=", 0) == 0) {
      output_dir = arg.substr(strlen("--output="));
    } else if (arg == "--force") {
      force = true;
    } else if (arg == "--help" || arg == "-h") {
      return tol_new_usage(argv[0]);
    } else {
      std::cerr << "tol new: unknown option " << arg << "\n";
      return tol_new_usage(argv[0]);
    }
  }
  if (!is_supported_new_pattern(pattern)) {
    std::cerr << "tol new: --pattern must be one of jetton, nft, wallet, multisig\n";
    return 2;
  }
  if (name.empty()) {
    name = default_scaffold_name(pattern);
  }
  if (!is_tol_ident(name)) {
    std::cerr << "tol new: --name must be a Tol identifier\n";
    return 2;
  }
  if (output_dir.empty()) {
    output_dir = pattern + "-project";
  }
  if (!mkdir_recursive(output_dir)) {
    std::cerr << "tol new: failed to create output directory " << output_dir << "\n";
    return 2;
  }
  if (!materialize_scaffold(output_dir, pattern, name, force)) {
    return 2;
  }
  std::cout << "Created Tol " << pattern << " scaffold at " << output_dir << "\n";
  return 0;
}

static bool stdlib_folder_exists(const char* stdlib_folder) {
  struct stat f_stat;
  int res = stat(stdlib_folder, &f_stat);
  return res == 0 && (f_stat.st_mode & S_IFMT) == S_IFDIR;
}

// getting current executable path is a complicated and not cross-platform task
// for instance, we can't just use argv[0] or even filesystem::canonical
// https://stackoverflow.com/questions/1023306/finding-current-executables-path-without-proc-self-exe/1024937
static bool get_current_executable_filename(std::string& out) {
#ifdef TD_DARWIN
  char name_buf[1024];
  unsigned int size = 1024;
  if (0 == _NSGetExecutablePath(name_buf, &size)) {   // may contain ../, so normalize it
    char *exe_path = realpath(name_buf, nullptr);
    if (exe_path != nullptr) {
      out = exe_path;
      return true;
    }
  }
#elif TD_WINDOWS
  char exe_path[1024];
  if (GetModuleFileNameA(nullptr, exe_path, 1024)) {
    out = exe_path;
    std::replace(out.begin(), out.end(), '\\', '/');    // modern Windows correctly deals with / separator
    return true;
  }
#else  // linux
  char exe_path[1024];
  ssize_t res = readlink("/proc/self/exe", exe_path, 1024 - 1);
  if (res >= 0) {
    exe_path[res] = 0;
    out = exe_path;
    return true;
  }
#endif
  return false;
}

// simple join "/some/folder/" (guaranteed to end with /) and "../relative/path"
static std::string join_path(std::string dir, const char* relative) {
  while (relative[0] == '.' && relative[1] == '.' && relative[2] == '/') {
    size_t slash_pos = dir.find_last_of('/', dir.size() - 2);   // last symbol is slash, find before it
    if (slash_pos != std::string::npos) {
      dir = dir.substr(0, slash_pos + 1);
    }
    relative += 3;
  }

  return dir + relative;
}

static std::string auto_discover_stdlib_folder() {
  // if the user launches tol compiler from a package installed (e.g. /usr/bin/tol),
  // locate stdlib in /usr/share/tos/smartcont (this folder exists on package installation)
  // (note, that paths are not absolute, they are relative to the launched binary)
  // consider https://github.com/tos-blockchain/packages for actual paths
  std::string executable_filename;
  if (!get_current_executable_filename(executable_filename)) {
    return {};
  }

  // extract dirname to concatenate with relative paths (separator / is ok even for windows)
  size_t slash_pos = executable_filename.find_last_of('/');
  std::string executable_dir = executable_filename.substr(0, slash_pos + 1);

#ifdef TD_DARWIN
  std::string def_location = join_path(executable_dir, "../share/tos/tos/smartcont/tol-stdlib");
#elif TD_WINDOWS
  std::string def_location = join_path(executable_dir, "smartcont/tol-stdlib");
#else  // linux
  std::string def_location = join_path(executable_dir, "../share/tos/smartcont/tol-stdlib");
#endif

  if (stdlib_folder_exists(def_location.c_str())) {
    return def_location;
  }

  // so, the binary is not from a system package
  // maybe it's just built from sources? e.g. ~/tos/cmake-build-debug/tol/tol
  // then, check the ~/tos/crypto/smartcont folder
  std::string near_when_built_from_sources = join_path(executable_dir, "../../crypto/smartcont/tol-stdlib");
  if (stdlib_folder_exists(near_when_built_from_sources.c_str())) {
    return near_when_built_from_sources;
  }

  // no idea of where to find stdlib; let's show an error for the user, he should provide env var above
  return {};
}

td::Result<std::string> fs_read_callback(CompilerSettings::FsReadCallbackKind kind, const char* query, void* callback_payload) {
  switch (kind) {
    case CompilerSettings::FsReadCallbackKind::Realpath: {
      std::string path;
      if (query[0] == '@' && strlen(query) > 8 && !strncmp(query, "@stdlib/", 8)) {
        path = G_settings.stdlib_folder + static_cast<std::string>(query + 7);
      } else if (query[0] == '@') {
        const char* slash = strchr(query, '/');
        if (slash == nullptr || slash[1] == '\0') {
          return td::Status::Error("import path with @ prefix must specify a file, e.g. @third_party/math-utils");
        }
        std::string_view at_prefix(query, slash);
        std::string_view abs_folder = G_settings.get_path_mapping(at_prefix);
        if (abs_folder.empty()) {
          return td::Status::Error("path mapping " + std::string{at_prefix} + " was not registered");
        }
        path = std::string(abs_folder) + slash;
      } else {
        path = query;
      }

      // reject `import "some/dir/"`, do not try to load "some/dir/.tol"
      if (path.back() == '/' || path.back() == '\\') {
        return td::Status::Error("import path must specify a file, not a directory");
      }

      if (path.size() < 4 || path.compare(path.size() - 4, 4, ".tol") != 0) {
        path += ".tol";
      }
      td::Result<std::string> res_realpath = td::realpath(td::CSlice(path.c_str()));
      if (res_realpath.is_error()) {
        // note, that for non-existing files, `realpath()` on Linux/Mac returns an error,
        // whereas on Windows, it returns okay, but fails after, on reading, with a message "cannot open file"
        return td::Status::Error("cannot find file \"" + path + "\"");
      }
      // files with the same realpath are considered equal (imported only once)
      return res_realpath;
    }
    case CompilerSettings::FsReadCallbackKind::ReadFile: {
      struct stat f_stat;
      int res = stat(query, &f_stat);   // query here is already resolved realpath
      if (res != 0 || (f_stat.st_mode & S_IFMT) != S_IFREG) {
        return td::Status::Error(std::string{"cannot open file "} + query);
      }

      size_t file_size = static_cast<size_t>(f_stat.st_size);
      std::string str;
      str.resize(file_size);
      FILE* f = fopen(query, "rb");
      if (!f) {
        return td::Status::Error(std::string{"cannot open file "} + query);
      }
      fread(str.data(), file_size, 1, f);
      fclose(f);
      return std::move(str);
    }
    default: {
      return td::Status::Error("unknown query kind");
    }
  }

  // callback_payload is not used in CLI mode, it's for library mode, see tol-wasm.cpp
  static_cast<void>(callback_payload);
}

GNU_ATTRIBUTE_NOINLINE
static void compilation_failed_output_errors(const std::vector<ThrownParseError>& errors) {
  constexpr int JSON_ERROR_LIMIT = 50;
  constexpr int CONSOLE_ERROR_LIMIT = 20;
  int shown = 0;

  if (G_settings.show_errors_as_json) {
    JsonPrettyOutput json(std::cerr);
    json.start_object();
    json.key_value("status", "error");
    json.start_array("errors");
    for (const ThrownParseError& error : errors) {
      if (shown >= JSON_ERROR_LIMIT) break;
      error.output_to_json(json);
      shown++;
    }
    json.end_array();
    json.end_object();

  } else {
    for (const ThrownParseError& error : errors) {
      if (shown >= CONSOLE_ERROR_LIMIT) break;
      if (shown++) std::cerr << std::endl;  // separator between errors
      error.output_to_console(std::cerr);
    }
  }
}

static void compilation_failed_with_fatal(const std::string& message) {
  // no location, no pretty header, no json output, just "fatal", something unexpected happened
  std::cerr << "fatal: " << message << std::endl;
}

static void compilation_succeed_after_output_done() {
  if (G_settings.show_errors_as_json) {
    std::cerr << R"({"status":"ok"})";
  }
}

int main(int argc, char* const argv[]) {
  if (argc >= 2 && std::string(argv[1]) == "new") {
    return run_new_command(argc, argv);
  }

  int i;
  while ((i = getopt_long(argc, argv, "o:O:evVh", long_options, nullptr)) != -1) {
    switch (i) {
      case 'o':
        G_settings.output_filename = optarg;
        break;
      case OPT_BOC_OUTPUT:
        G_settings.boc_output_filename = optarg;
        break;
      case 'O':
        G_settings.optimization_level = std::max(0, atoi(optarg));
        break;
      case OPT_PATH_MAPPING:
        if (!G_settings.parse_path_mapping_cmd_arg(optarg)) {
          return 2;   // the error was printed to std::cerr
        }
        break;
      case OPT_NO_STACK_COMMENTS:
        G_settings.stack_layout_comments = false;
        break;
      case OPT_NO_LINE_COMMENTS:
        G_settings.tol_src_as_line_comments = false;
        break;
      case OPT_JSON_ERRORS:
        G_settings.show_errors_as_json = true;
        break;
      case OPT_CHECK_ONLY:
        G_settings.check_only_no_output = true;
        break;
      case OPT_ALLOW_NO_ENTRYPOINT:
        G_settings.allow_no_entrypoint = true;
        break;
      case 'e':
        G_settings.verbosity++;
        break;
      case 'v':
      case 'V':
        std::cout << "Tol compiler v" << TOL_VERSION << std::endl;
        std::cout << "Build commit: " << GitMetadata::CommitSHA1() << std::endl;
        std::cout << "Build date: " << GitMetadata::CommitDate() << std::endl;
        std::exit(0);
      case 'h':
      default:
        usage(argv[0]);
    }
  }

  // locate tol-stdlib/ based on env or default system paths
  if (const char* env_var = getenv("TOL_STDLIB")) {
    std::string stdlib_filename = static_cast<std::string>(env_var) + "/common.tol";
    td::Result<std::string> res = td::realpath(td::CSlice(stdlib_filename.c_str()));
    if (res.is_error()) {
      std::cerr << "Environment variable TOL_STDLIB is invalid: " << res.move_as_error().message().c_str() << std::endl;
      return 2;
    }
    G_settings.stdlib_folder = env_var;
  } else {
    G_settings.stdlib_folder = auto_discover_stdlib_folder();
  }
  if (G_settings.stdlib_folder.empty()) {
    std::cerr << "Failed to discover Tol stdlib.\n"
                 "Probably, you have a non-standard Tol installation.\n"
                 "Please, provide env variable TOL_STDLIB referencing to tol-stdlib/ folder.\n";
    return 2;
  }
  if (G_settings.verbosity >= 2) {
    std::cerr << "stdlib folder: " << G_settings.stdlib_folder << std::endl;
  }

  if (optind != argc - 1) {
    std::cerr << "invalid usage: should specify exactly one input file.tol" << std::endl;
    return 2;
  }

  G_settings.read_callback = fs_read_callback;

  TolCompilationResult result = tol_proceed(argv[optind]);
  if (!result.fatal_msg.empty()) {
    compilation_failed_with_fatal(result.fatal_msg);
    return 2;
  }
  if (!result.errors.empty()) {
    compilation_failed_output_errors(result.errors);
    return 2;
  }

  // for IDE in background: no codegen, do not create or truncate output files
  if (G_settings.check_only_no_output) {
    compilation_succeed_after_output_done();
    return 0;
  }

  // if output filename is empty, no files are written (only Fift code is written into stdout)
  if (G_settings.output_filename.empty()) {
    std::cout << result.fift_code;
    compilation_succeed_after_output_done();
    return 0;
  }

  std::ofstream fif_out_file(G_settings.output_filename);
  if (!fif_out_file.is_open()) {
    std::cerr << "Failed to create output file " << G_settings.output_filename << std::endl;
    return 2;
  }
  fif_out_file << result.fift_code;

  compilation_succeed_after_output_done();
  return 0;
}
