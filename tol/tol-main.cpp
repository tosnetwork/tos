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
            "       " << progname << " new --pattern <jetton|nft|wallet|multisig|auction|governance|oracle|payment-channel> [--name <Name>] [--output <dir>] [--force]\n"
            "\tGenerates Fift TVM assembler code from a .tol file\n"
         "new --pattern <name>\n"
            "\tCreate a stdlib scaffold project for a supported pattern\n"
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
  static const std::set<std::string> supported = {
      "jetton", "nft", "wallet", "multisig",
      "auction", "governance", "oracle", "payment-channel"};
  return supported.count(pattern) != 0;
}

static bool is_slice5_new_pattern(const std::string& pattern) {
  static const std::set<std::string> supported = {"auction", "governance", "oracle", "payment-channel"};
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
  if (pattern == "auction") {
    return "AuctionScaffold";
  }
  if (pattern == "governance") {
    return "GovernanceScaffold";
  }
  if (pattern == "oracle") {
    return "OracleScaffold";
  }
  if (pattern == "payment-channel") {
    return "PaymentChannelScaffold";
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
  if (pattern == "auction") {
    return R"TOL(import "@stdlib/auction"

fun scaffoldPatternId(): int {
    return slice5AuctionManifestHeader().patternId;
}

fun main(): int {
    return scaffoldPatternId();
}
)TOL";
  }
  if (pattern == "governance") {
    return R"TOL(import "@stdlib/governance"

fun scaffoldPatternId(): int {
    return slice5GovernanceManifestHeader().patternId;
}

fun main(): int {
    return scaffoldPatternId();
}
)TOL";
  }
  if (pattern == "oracle") {
    return R"TOL(import "@stdlib/oracle"

fun scaffoldPatternId(): int {
    return slice5OracleManifestHeader().patternId;
}

fun main(): int {
    return scaffoldPatternId();
}
)TOL";
  }
  if (pattern == "payment-channel") {
    return R"TOL(import "@stdlib/payment-channel"

fun scaffoldPatternId(): int {
    return slice5PaymentManifestHeader().patternId;
}

fun main(): int {
    return scaffoldPatternId();
}
)TOL";
  }
  return R"TOL(// Multisig proposal scaffold.
//
// What it does: records a proposal under its query id when the submission is
// signed by one of the configured signers. The signature (Ed25519, by the key
// in `signer`) covers [multisigSubmitSigningHash]: a versioned domain tag, the
// network's global id, this contract's address, the query id, the expiry and
// the actions cell. Anyone may relay the message; only the signature decides
// who is speaking.
//
// What it does not do: it never executes the actions, does not record which
// signer proposed or approved, does not count approvals toward the threshold,
// and has no way to change the signer set or remove a proposal. It is a
// starting point, not a wallet: do not hold funds with it.
//
// To grow it into a wallet, store a `MultisigProposal` per query id (actions
// and approvals), add an approve message authenticated the same way, count
// approvals with `MultisigProposal.recordApproval`, and execute only after
// `multisigRequireThresholdReached`, marking the proposal executed in the same
// transaction.
import "@stdlib/multisig"

struct {{NAME}}Storage {
    config: MultisigConfig;
    pending: dict;
}

struct (0x4d534947) {{NAME}}Submit {
    queryId: uint64;
    validUntil: uint32;
    signer: uint256;
    signature: bits512;
    actions: cell;
}

fun scaffoldPatternId(): int {
    return multisigPatternManifestHeader().patternId;
}

/// Returns the storage that records `msg` as a pending proposal, or throws.
/// Network, contract address and time come from the chain, never from the
/// message. Cheap checks run first, the signature before anything is
/// recorded, and the actions walk only for an authenticated signer.
fun {{NAME}}Storage.acceptSubmit(self, msg: {{NAME}}Submit): {{NAME}}Storage {
    multisigRequireValidThreshold(self.config.threshold, self.config.signerCount);
    multisigRequireNotExpired(msg.validUntil, blockchain.now());
    // Membership, and refusal of a weak key anyone could sign for.
    multisigRequireSigner(self.config.signers, msg.signer);
    val hash = multisigSubmitSigningHash(contract.getAddress(), msg.queryId, msg.validUntil, msg.actions);
    multisigRequireSubmitSignature(hash, msg.signature, msg.signer);
    multisigRequireNewProposal(self.pending, msg.queryId);
    multisigValidateActions(msg.actions, false);
    return {{NAME}}Storage {
        config: self.config,
        pending: multisigAddPendingProposal(self.pending, msg.queryId),
    };
}

contract {{NAME}} {
    storage: {{NAME}}Storage
    @unknown_throw(1807);

    @disclaim_query_id
    receive(msg: {{NAME}}Submit) {
        save(storage.acceptSubmit(msg));
    }
}
)TOL";
}

static std::string scaffold_test_template(const std::string& pattern) {
  if (pattern == "multisig") {
    return R"TOL(import "@stdlib/slice3-common"
import "@stdlib/tvm-dicts"
import "@stdlib/multisig"
import "../src/main"

// Deterministic Ed25519 fixtures: private key i = sha256("quorum-key-i"). Each
// testSigKi() is Ki's signature of the submit hash of the base request below
// (TEST_QUERY_ID, TEST_VALID_UNTIL, an empty actions cell) on network
// TEST_GLOBAL_ID at the contract address testSelf(). They are test vectors
// only: never configure these keys on a real network.
const TEST_K1 = 0xA0E39282B780E9EF18283DD09ED1CABA55B468EB9C5014967EA5CAA3256C6795
const TEST_K2 = 0x282D5E174AB2122F1538944E31BEA38FAFE5A622656E6BE63CFAB47D16EE57BB
const TEST_K3 = 0xECD0DF7591957F3EDA016B66417B8B1165138154D2AFA7184E1517AA324BECE9
const TEST_GLOBAL_ID = 42
const TEST_NOW = 1000
const TEST_QUERY_ID = 7
const TEST_VALID_UNTIL = 2000

fun testSigK1(): bits512 { return "3DF5140949D36ABF758E8C2BD2ADE02ACEC99A3941694A67BDE955D7332B42D7E5B257602EC752207B050593C5EAFF2F761A0E29BF907EE6EA454E048495A003".hexToSlice() as bits512; }
fun testSigK2(): bits512 { return "78F1DBD829E7B08E1FF696817C915223B05C82A81B6BEF95AD83AF63494CB978049A421F3D9DAAC27B5B6497FF6436E786D3C66DE10D735EBBB4D057DEF9960C".hexToSlice() as bits512; }
fun testSigK3(): bits512 { return "6AE6D6AD85500DE5A60DA16CBAA555D1143A59132F5ABD6FB91617814EBB049CDA48F827D130F313EDA42A5666D0DE2F595FCB7D3A84A7892B9405477277D706".hexToSlice() as bits512; }

/// Not a well-formed action list.
fun testBadActions(): cell {
    return beginCell().storeUint(1, 8).endCell();
}

/// K1's signature of the base request with testBadActions() in place of the
/// empty actions cell.
fun testSigK1BadActions(): bits512 { return "2EC68FB68340184C91D4F40419F2D93C51E76757200C58C1E1B6D372E25E8D1A25D2E6737EF4830EAE37B046F204B0FEB3B2F2877091C95465F4D2FC3BF89608".hexToSlice() as bits512; }

// The identity point spelled with the sign bit set, a weak key the signature
// verifier accepts: R = identity, S = 0 verifies under it for every message,
// with no secret behind it.
const TEST_WEAK = 0x0100000000000000000000000000000000000000000000000000000000000080

fun testForged(): bits512 { return "01000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000".hexToSlice() as bits512; }

fun testSelf(): address {
    return address("0:1111111111111111111111111111111111111111111111111111111111111111");
}

fun testOther(): address {
    return address("0:2222222222222222222222222222222222222222222222222222222222222222");
}

fun setC7(c7: array<unknown>): void
    asm "c7 POP"

/// Installs the chain context a transaction would see: the network's global
/// id (c7[0][14][1]), the current time (c7[0][3]) and this contract's address
/// (c7[0][8]).
fun installChain(globalId: int, nowTs: int, own: address): void {
    var unpacked: array<unknown> = [];
    var i = 0;
    while (i < 7) {
        unpacked.push(i == 1 ? beginCell().storeInt(globalId, 32).endCell().beginParse() as unknown : null);
        i += 1;
    }
    var params: array<unknown> = [];
    i = 0;
    while (i < 17) {
        params.push(null);
        i += 1;
    }
    params.set(nowTs, 3);
    params.set(own as unknown, 8);
    params.set(unpacked, 14);
    var c7: array<unknown> = [];
    c7.push(params);
    setC7(c7);
}

fun installBaseChain(): void {
    installChain(TEST_GLOBAL_ID, TEST_NOW, testSelf());
}

fun testSigners(): dict {
    var signers = createEmptyDict();
    signers = multisigAddSigner(signers, TEST_K1);
    signers = multisigAddSigner(signers, TEST_K2);
    return signers;
}

fun testStorage(signers: dict): {{NAME}}Storage {
    return {{NAME}}Storage {
        config: MultisigConfig { threshold: 2, signerCount: 2, signers },
        pending: createEmptyDict(),
    };
}

fun testSubmit(signer: int, signature: bits512): {{NAME}}Submit {
    return {{NAME}}Submit {
        queryId: TEST_QUERY_ID,
        validUntil: TEST_VALID_UNTIL,
        signer,
        signature,
        actions: createEmptyCell(),
    };
}

/// The code `msg` is refused with, or 0 when it is accepted.
fun refusal(storage: {{NAME}}Storage, msg: {{NAME}}Submit): int {
    try {
        storage.acceptSubmit(msg);
    } catch (code) {
        return code;
    }
    return 0;
}

fun expectRefused(storage: {{NAME}}Storage, msg: {{NAME}}Submit, expected: int, failCode: int): void {
    assert(refusal(storage, msg) == expected) throw failCode;
}

@method_id(101)
fun test_scaffold_pattern(): int {
    return scaffoldPatternId();
}

@method_id(102)
fun test_fixtures_are_real(): int {
    // Guards the fixtures themselves: if these stop verifying, every refusal
    // below would pass for the wrong reason.
    installBaseChain();
    val hash = multisigSubmitSigningHash(testSelf(), TEST_QUERY_ID, TEST_VALID_UNTIL, createEmptyCell());
    assert(isSignatureValid(hash, testSigK1() as slice, TEST_K1)) throw 201;
    assert(isSignatureValid(hash, testSigK2() as slice, TEST_K2)) throw 202;
    assert(isSignatureValid(hash, testSigK3() as slice, TEST_K3)) throw 203;
    assert(isSignatureValid(hash, testForged() as slice, TEST_WEAK)) throw 204;
    assert(!isSignatureValid(hash + 1, testSigK1() as slice, TEST_K1)) throw 205;
    return 2;
}

@method_id(103)
fun test_signed_submission_recorded(): int {
    installBaseChain();
    val storage = testStorage(testSigners());
    assert(!multisigHasPendingProposal(storage.pending, TEST_QUERY_ID)) throw 301;
    val next = storage.acceptSubmit(testSubmit(TEST_K1, testSigK1()));
    assert(multisigHasPendingProposal(next.pending, TEST_QUERY_ID)) throw 302;
    // Either configured signer can propose.
    val viaK2 = storage.acceptSubmit(testSubmit(TEST_K2, testSigK2()));
    assert(multisigHasPendingProposal(viaK2.pending, TEST_QUERY_ID)) throw 303;
    return 3;
}

@method_id(104)
fun test_unsigned_submission_refused(): int {
    installBaseChain();
    val storage = testStorage(testSigners());
    val zero = beginCell().storeUint(0, 256).storeUint(0, 256).endCell().beginParse() as bits512;
    expectRefused(storage, testSubmit(TEST_K1, zero), MULTISIG_FUNC_THROW_BAD_SIGNATURE, 401);
    // A real signature by the right key, of something else.
    val unrelated = "A2622A17A2AFAB596F3E424967925F73908AC39299D77CFCC462EFC9FA8A72EBF11D44355287786746C3F25431DBCC9B8E8C2EB2777FE26254AA2B6BBB512C01".hexToSlice() as bits512;
    expectRefused(storage, testSubmit(TEST_K1, unrelated), MULTISIG_FUNC_THROW_BAD_SIGNATURE, 402);
    return 4;
}

@method_id(105)
fun test_signature_by_another_signer_refused(): int {
    installBaseChain();
    val storage = testStorage(testSigners());
    // Both keys are configured and both signatures are real; neither speaks
    // for the other.
    expectRefused(storage, testSubmit(TEST_K1, testSigK2()), MULTISIG_FUNC_THROW_BAD_SIGNATURE, 501);
    expectRefused(storage, testSubmit(TEST_K2, testSigK1()), MULTISIG_FUNC_THROW_BAD_SIGNATURE, 502);
    return 5;
}

@method_id(106)
fun test_signature_for_another_contract_refused(): int {
    installChain(TEST_GLOBAL_ID, TEST_NOW, testOther());
    expectRefused(testStorage(testSigners()), testSubmit(TEST_K1, testSigK1()), MULTISIG_FUNC_THROW_BAD_SIGNATURE, 601);
    return 6;
}

@method_id(107)
fun test_signature_for_another_network_refused(): int {
    installChain(TEST_GLOBAL_ID + 1, TEST_NOW, testSelf());
    expectRefused(testStorage(testSigners()), testSubmit(TEST_K1, testSigK1()), MULTISIG_FUNC_THROW_BAD_SIGNATURE, 701);
    return 7;
}

@method_id(108)
fun test_weak_signer_refused(): int {
    installBaseChain();
    // A signer set as it could sit in storage, never passed through
    // multisigAddSigner.
    var signers = testSigners();
    signers.uDictSetBuilder(MULTISIG_SIGNER_KEY_BITS, TEST_WEAK, beginCell().storeInt(-1, 1));
    val storage = {{NAME}}Storage {
        config: MultisigConfig { threshold: 2, signerCount: 3, signers },
        pending: createEmptyDict(),
    };
    expectRefused(storage, testSubmit(TEST_WEAK, testForged()), MULTISIG_FUNC_THROW_WEAK_SIGNER, 801);
    // The signature check refuses the weak key on its own as well.
    val hash = multisigSubmitSigningHash(testSelf(), TEST_QUERY_ID, TEST_VALID_UNTIL, createEmptyCell());
    var refused = false;
    try {
        multisigRequireSubmitSignature(hash, testForged(), TEST_WEAK);
    } catch (code) {
        assert(code == MULTISIG_FUNC_THROW_WEAK_SIGNER) throw 802;
        refused = true;
    }
    assert(refused) throw 803;
    return 8;
}

@method_id(109)
fun test_expired_submission_refused(): int {
    val storage = testStorage(testSigners());
    installChain(TEST_GLOBAL_ID, TEST_VALID_UNTIL - 1, testSelf());
    expectRefused(storage, testSubmit(TEST_K1, testSigK1()), 0, 901);
    installChain(TEST_GLOBAL_ID, TEST_VALID_UNTIL, testSelf());
    expectRefused(storage, testSubmit(TEST_K1, testSigK1()), MULTISIG_FUNC_THROW_EXPIRED, 902);
    installChain(TEST_GLOBAL_ID, TEST_VALID_UNTIL + 1, testSelf());
    expectRefused(storage, testSubmit(TEST_K1, testSigK1()), MULTISIG_FUNC_THROW_EXPIRED, 903);
    return 9;
}

@method_id(110)
fun test_duplicate_query_id_refused(): int {
    installBaseChain();
    val storage = testStorage(testSigners()).acceptSubmit(testSubmit(TEST_K1, testSigK1()));
    expectRefused(storage, testSubmit(TEST_K1, testSigK1()), MULTISIG_FUNC_THROW_PROPOSAL_REPLAY, 1001);
    expectRefused(storage, testSubmit(TEST_K2, testSigK2()), MULTISIG_FUNC_THROW_PROPOSAL_REPLAY, 1002);
    return 10;
}

@method_id(111)
fun test_signed_fields_cannot_change(): int {
    installBaseChain();
    val storage = testStorage(testSigners());
    var msg = testSubmit(TEST_K1, testSigK1());
    msg.queryId = TEST_QUERY_ID + 1;
    expectRefused(storage, msg, MULTISIG_FUNC_THROW_BAD_SIGNATURE, 1101);
    msg = testSubmit(TEST_K1, testSigK1());
    msg.validUntil = TEST_VALID_UNTIL + 1;
    expectRefused(storage, msg, MULTISIG_FUNC_THROW_BAD_SIGNATURE, 1102);
    msg = testSubmit(TEST_K1, testSigK1());
    msg.actions = testBadActions();
    expectRefused(storage, msg, MULTISIG_FUNC_THROW_BAD_SIGNATURE, 1103);
    return 11;
}

@method_id(112)
fun test_unconfigured_signer_refused(): int {
    installBaseChain();
    // A real signature of the right request, by a key outside the set.
    expectRefused(testStorage(testSigners()), testSubmit(TEST_K3, testSigK3()), MULTISIG_FUNC_THROW_NOT_SIGNER, 1201);
    return 12;
}

@method_id(113)
fun test_submit_hash_layout(): int {
    // Pins what an off-chain signer must reproduce: the representation hash
    // of one cell holding tag (uint32), global id (int32), target address,
    // query id (uint64) and valid-until (uint32), with the actions cell as its
    // only reference. Recomputed outside the VM for the base request.
    installBaseChain();
    val hash = multisigSubmitSigningHash(testSelf(), TEST_QUERY_ID, TEST_VALID_UNTIL, createEmptyCell());
    assert(hash == 0xdef505c688732e7ca2a0ed27a32fad57f02eb622a16581632cd02c4e4eb1b8cb) throw 1301;
    return 13;
}

@method_id(114)
fun test_actions_checked_after_authentication(): int {
    installBaseChain();
    val storage = testStorage(testSigners());
    var bad = testSubmit(TEST_K1, testSigK1BadActions());
    bad.actions = testBadActions();
    // Authenticated, but not a well-formed action list.
    expectRefused(storage, bad, MULTISIG_FUNC_THROW_INVALID_ACTIONS, 1401);
    // Unauthenticated: refused before the actions are looked at.
    var forged = bad;
    forged.signature = testSigK2();
    expectRefused(storage, forged, MULTISIG_FUNC_THROW_BAD_SIGNATURE, 1402);
    // A query id already pending is refused before the actions are walked.
    val pending = storage.acceptSubmit(testSubmit(TEST_K1, testSigK1()));
    expectRefused(pending, bad, MULTISIG_FUNC_THROW_PROPOSAL_REPLAY, 1403);
    return 14;
}

/**
@testcase | 101 | | {{PATTERN_ID}}
@testcase | 102 | | 2
@testcase | 103 | | 3
@testcase | 104 | | 4
@testcase | 105 | | 5
@testcase | 106 | | 6
@testcase | 107 | | 7
@testcase | 108 | | 8
@testcase | 109 | | 9
@testcase | 110 | | 10
@testcase | 111 | | 11
@testcase | 112 | | 12
@testcase | 113 | | 13
@testcase | 114 | | 14
 */
)TOL";
  }
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
  "schema": "{{PROJECT_SCHEMA}}",
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
  }
}
)JSON";
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

static std::string scaffold_readme_scope(const std::string& pattern) {
  if (pattern == "multisig") {
    return R"MD(
## Scope

This scaffold records authenticated proposals. It is not a wallet and must not
hold funds.

What it does:

- accepts a submit message only with an Ed25519 signature by the key named in
  `signer`, over `multisigSubmitSigningHash`: a versioned domain tag, the
  network's global id, this contract's address, the query id, the expiry and
  the actions cell. Anyone may relay the message; the signature decides who
  is speaking;
- refuses a signer outside the configured set, a weak signer key anyone could
  sign for, a bad signature, an expired request, a query id already pending,
  and an actions cell that is not a well-formed action list;
- records the query id as pending.

What it does not do:

- execute the actions, or send any message;
- record which signer proposed, or count approvals toward the threshold;
- change the signer set or threshold, or remove a pending proposal.

To grow it into a wallet, store a `MultisigProposal` per query id (actions and
approvals), add an approve message authenticated the same way, count approvals
with `MultisigProposal.recordApproval`, and execute only after
`multisigRequireThresholdReached`, marking the proposal executed in the same
transaction.

## Signing

The signed hash is the representation hash of one cell holding the tag
`0x6d737631` (uint32), the global id (int32), the contract address, the query
id (uint64) and the expiry (uint32), with the actions cell as its only
reference. `tests/multisig-positive.tol` pins one such hash and its
signatures.
)MD";
  }
  return "";
}

static std::string scaffold_readme_template(const std::string& pattern, const std::string& name) {
  return R"MD(# {{NAME}}

Generated by `tol new --pattern {{PATTERN}}`.
)MD" + scaffold_readme_scope(pattern) +
         R"MD(
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
  if (pattern == "multisig") return 5;
  if (pattern == "auction") return 6;
  if (pattern == "governance") return 7;
  if (pattern == "oracle") return 8;
  if (pattern == "payment-channel") return 9;
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
  if (pattern == "auction") {
    return R"JSON({
  "opcodes": [
    {"name": "SLICE5_AUCTION_OP_BID", "hex": "0x41554301"},
    {"name": "SLICE5_AUCTION_OP_CLOSE", "hex": "0x41554302"},
    {"name": "SLICE5_AUCTION_OP_EXPIRE", "hex": "0x41554303"},
    {"name": "SLICE5_AUCTION_OP_SETTLE", "hex": "0x41554304"}
  ]
}
)JSON";
  }
  if (pattern == "governance") {
    return R"JSON({
  "opcodes": [
    {"name": "SLICE5_GOVERNANCE_OP_PROPOSE", "hex": "0x474f5601"},
    {"name": "SLICE5_GOVERNANCE_OP_VOTE", "hex": "0x474f5602"},
    {"name": "SLICE5_GOVERNANCE_OP_EXECUTE", "hex": "0x474f5603"},
    {"name": "SLICE5_GOVERNANCE_OP_CANCEL", "hex": "0x474f5604"}
  ]
}
)JSON";
  }
  if (pattern == "oracle") {
    return R"JSON({
  "opcodes": [
    {"name": "SLICE5_ORACLE_OP_REPORT", "hex": "0x4f524301"},
    {"name": "SLICE5_ORACLE_OP_FINALIZE", "hex": "0x4f524302"}
  ]
}
)JSON";
  }
  if (pattern == "payment-channel") {
    return R"JSON({
  "opcodes": [
    {"name": "SLICE5_PAYMENT_OP_COOPERATIVE_CLOSE", "hex": "0x50434801"},
    {"name": "SLICE5_PAYMENT_OP_CHALLENGE_CLOSE", "hex": "0x50434802"},
    {"name": "SLICE5_PAYMENT_OP_SETTLE", "hex": "0x50434803"}
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

static std::string scaffold_error_code_map(const std::string& pattern) {
  if (pattern == "auction") {
    return "{\n  \"error_codes\": [\n    {\"name\": \"SLICE5_AUCTION_THROW_LOW_BID\", \"code\": 2817},\n    {\"name\": \"SLICE5_AUCTION_THROW_QUEUE_FULL\", \"code\": 2819},\n    {\"name\": \"SLICE5_AUCTION_THROW_STALE_CLOSE\", \"code\": 2820},\n    {\"name\": \"SLICE5_AUCTION_THROW_UNAUTHORIZED_SELLER\", \"code\": 2825}\n  ]\n}\n";
  }
  if (pattern == "governance") {
    return "{\n  \"error_codes\": [\n    {\"name\": \"SLICE5_GOVERNANCE_THROW_UNAUTHORIZED_PROPOSER\", \"code\": 3073},\n    {\"name\": \"SLICE5_GOVERNANCE_THROW_INVALID_ACTION\", \"code\": 3078}\n  ]\n}\n";
  }
  if (pattern == "oracle") {
    return "{\n  \"error_codes\": [\n    {\"name\": \"SLICE5_ORACLE_THROW_UNAUTHORIZED_REPORTER\", \"code\": 3329},\n    {\"name\": \"SLICE5_ORACLE_THROW_OUTLIER\", \"code\": 3333},\n    {\"name\": \"SLICE5_ORACLE_THROW_UNAUTHORIZED_STARTER\", \"code\": 3338}\n  ]\n}\n";
  }
  if (pattern == "payment-channel") {
    return "{\n  \"error_codes\": [\n    {\"name\": \"SLICE5_PAYMENT_THROW_SIGNATURE_FAILURE\", \"code\": 3585},\n    {\"name\": \"SLICE5_PAYMENT_THROW_SEQNO_REPLAY\", \"code\": 3586}\n  ]\n}\n";
  }
  if (pattern == "multisig") {
    return R"JSON({
  "error_codes": [
    {"name": "MULTISIG_FUNC_THROW_BAD_THRESHOLD", "code": 1801},
    {"name": "MULTISIG_FUNC_THROW_NOT_SIGNER", "code": 1802},
    {"name": "MULTISIG_FUNC_THROW_PROPOSAL_REPLAY", "code": 1805},
    {"name": "MULTISIG_FUNC_THROW_EXPIRED", "code": 1806},
    {"name": "MULTISIG_FUNC_THROW_INVALID_ACTIONS", "code": 1807},
    {"name": "MULTISIG_FUNC_THROW_WEAK_SIGNER", "code": 1808},
    {"name": "MULTISIG_FUNC_THROW_BAD_SIGNATURE", "code": 1809}
  ]
}
)JSON";
  }
  return "{\n  \"error_codes\": []\n}\n";
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
    content = replace_all(std::move(content), "{{PROJECT_SCHEMA}}", is_slice5_new_pattern(pattern) ? "slice-5-generated-project" : "slice-3-generated-project");
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
      {"artifacts/error-codes.json", scaffold_error_code_map(pattern)},
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
  std::cerr << "usage: " << progname << " new --pattern <jetton|nft|wallet|multisig|auction|governance|oracle|payment-channel> [--name <Name>] [--output <dir>] [--force]\n";
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
    std::cerr << "tol new: --pattern must be one of jetton, nft, wallet, multisig, auction, governance, oracle, payment-channel\n";
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
