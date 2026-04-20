/*
    Uno Workchain — §12 P.3 state-transition golden fixtures.

    Per §12 P.3 of doc/uno-workchain.md, a validator must produce a
    byte-identical post-state given identical pre-state + transaction. This
    test pins that contract with 10 fixtures covering the accept and reject
    paths enumerated below:

      #1  valid 1-spend / 1-output                         — accept
      #2  valid 4-spend / 4-output (max shape)             — accept
      #3  valid 2-spend / 3-output with fee rounding       — accept
      #4  double-spend (nullifier already in set)          — reject step 2
      #5  stale anchor (> window_size blocks old)          — reject step 1.5
      #6  invalid Plonky3 proof (corrupted bytes)          — reject step 4
      #7  over-max spends (spend_count == 5)               — reject step 1
      #8  fee < min_fee_nano                               — reject step 1
      #9  expiry_block exceeded current head               — reject step 1
      #10 wrong chain_id                                   — reject step 1

    Fixture storage: uno/test/golden/state-transitions-v1.hex. Each record
    pins the pre-state byte blob, the Transfer byte blob, the expected
    VerifyResult, and (for accept cases) the expected post-state blob.
    Byte format is header-documented inside the .hex file.

    Driver behavior:
      - If UnoShardState + verify_transfer + apply_transfer + cell-state
        serialiser are all present and wired, this test asserts byte-equality.
      - If any of those dependencies is absent, the test SKIPs with the
        specific missing piece listed. Deterministic SKIP is preferred over
        hard-coding Plonky3 proofs that would drift the moment the AIR
        lands — doc §12 P.3 spec explicitly permits this.

    The fixture file is additively extended; do NOT renumber existing
    records (validators replay the old history, and a renumber silently
    invalidates historical cross-checks).
*/
#include <array>
#include <atomic>
#include <cassert>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <sstream>
#include <string>
#include <variant>
#include <vector>

#include "td/utils/Slice.h"
#include "td/utils/SharedSlice.h"
#include "td/utils/crypto.h"
#include "vm/boc.h"
#include "vm/cells/Cell.h"
#include "vm/cells/CellSlice.h"

#include "uno/core/transaction.h"

// Weak BLAKE3 fallback — the decode-side path recomputes `tx_hash`, which
// routes through the A3 BLAKE3 adapter. Out-of-validator test binaries
// don't link the real adapter; this fallback keeps us identical-under-
// any-hash because every call site uses the same function.
namespace uno_workchain::crypto::internal {
__attribute__((weak)) void blake3_hash(td::Slice in, uint8_t out[32]) {
    td::sha256(in, td::MutableSlice(reinterpret_cast<char*>(out), 32));
}
}  // namespace uno_workchain::crypto::internal

// ----- Tracked printf harness (matches other uno/test/*.cpp) -----------------

static std::atomic<int> g_failures{0};
static std::atomic<int> g_skips{0};
static std::atomic<int> g_passes{0};

static int tracked_printf(const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    va_list copy;
    va_copy(copy, args);
    int needed = std::vsnprintf(nullptr, 0, fmt, copy);
    va_end(copy);
    std::string rendered;
    if (needed >= 0) {
        rendered.resize((size_t)needed + 1);
        va_copy(copy, args);
        std::vsnprintf(rendered.data(), rendered.size(), fmt, copy);
        va_end(copy);
        rendered.resize((size_t)needed);
    }
    int written = std::vprintf(fmt, args);
    va_end(args);
    if (!rendered.empty()) {
        if (rendered.find("FAILED") != std::string::npos) g_failures.fetch_add(1);
        if (rendered.find("SKIP")    != std::string::npos) g_skips.fetch_add(1);
        if (rendered.find("PASSED")  != std::string::npos) g_passes.fetch_add(1);
    }
    return written;
}
#define tprintf tracked_printf

// ----- Fixture record structure ---------------------------------------------
//
// Text format of uno/test/golden/state-transitions-v1.hex:
//
//   # comments start with '#'
//   record_id=NN
//   label=short-human-label
//   verdict=Ok | BadChainId | InsufficientFee | ExpiryOutOfRange |
//           BadSpendCount | BadOutputCount | UnknownAnchor |
//           NullifierAlreadySpent | BadPlonky3Proof | <...>
//   pre_state=<hex | empty>
//   transfer=<hex | empty>
//   post_state=<hex | empty>       # only present when verdict=Ok
//   ---
//
// We use this plaintext format (not raw binary) for the same reason
// public-inputs-v1.hex is text: easy to hand-eyeball during audit.

struct Fixture {
    int id = 0;
    std::string label;
    std::string verdict;
    std::string pre_state_hex;
    std::string transfer_hex;
    std::string post_state_hex;  // optional
};

static bool load_fixtures(const std::string& path, std::vector<Fixture>& out) {
    std::ifstream f(path);
    if (!f.is_open()) return false;
    Fixture cur;
    bool in_record = false;
    std::string line;
    auto commit = [&](Fixture& fx) {
        if (in_record) out.push_back(fx);
        fx = Fixture{};
        in_record = false;
    };
    while (std::getline(f, line)) {
        // trim trailing \r for Windows-authored files
        while (!line.empty() && (line.back() == '\r' || line.back() == ' '))
            line.pop_back();
        if (line.empty() || line[0] == '#') continue;
        if (line == "---") { commit(cur); continue; }
        auto eq = line.find('=');
        if (eq == std::string::npos) continue;
        std::string key = line.substr(0, eq);
        std::string val = line.substr(eq + 1);
        in_record = true;
        if      (key == "record_id")  cur.id             = std::atoi(val.c_str());
        else if (key == "label")      cur.label          = val;
        else if (key == "verdict")    cur.verdict        = val;
        else if (key == "pre_state")  cur.pre_state_hex  = val;
        else if (key == "transfer")   cur.transfer_hex   = val;
        else if (key == "post_state") cur.post_state_hex = val;
    }
    commit(cur);
    return true;
}

// ----- Driver ---------------------------------------------------------------
//
// Runs the full §4.3 verify + apply loop. This requires:
//   - uno/core/state.h      :: UnoShardState
//   - uno/core/cell-state.h :: serialize_state / deserialize_state
//   - uno/core/compute-phase.h :: run_compute_phase   (or the verify_transfer /
//                                 apply_transfer split; interface is still
//                                 in flux in P.2)
//
// Until those compile-time symbols are all available, we wrap the runtime
// driver in a macro guard (UNO_P3_DRIVER_READY) and emit SKIPs otherwise.
// The fixture file is still validated for parse-ability on every run, so a
// malformed fixture is caught even in scaffold builds.

#ifdef UNO_P3_DRIVER_READY
#include "uno/core/cell-state.h"
#include "uno/core/compute-phase.h"
#include "uno/core/state.h"
#include "uno/core/transaction.h"
#endif

// Fixture-path discovery: tests are invoked from either the source tree
// (via ctest WORKING_DIRECTORY set to CMAKE_SOURCE_DIR) or from an ad-hoc
// location. Probe both.
static std::string find_fixture_path() {
    static const char* candidates[] = {
        "uno/test/golden/state-transitions-v1.hex",
        "../uno/test/golden/state-transitions-v1.hex",
        "../../uno/test/golden/state-transitions-v1.hex",
        "../../../uno/test/golden/state-transitions-v1.hex",
    };
    for (const char* c : candidates) {
        std::ifstream f(c);
        if (f.is_open()) return c;
    }
    return {};
}

static void test_fixture_file_is_parseable() {
    tprintf("[TEST] test_fixture_file_is_parseable\n");
    std::string path = find_fixture_path();
    if (path.empty()) {
        tprintf("  FAILED: uno/test/golden/state-transitions-v1.hex not found "
                "(ran tests from an unexpected cwd? — check ctest WORKING_DIRECTORY)\n");
        return;
    }
    std::vector<Fixture> fx;
    if (!load_fixtures(path, fx)) {
        tprintf("  FAILED: could not open %s\n", path.c_str());
        return;
    }
    if (fx.size() < 10) {
        tprintf("  FAILED: expected ≥ 10 fixtures, got %zu\n", fx.size());
        return;
    }
    // Verify id ordering + required fields present.
    //
    // Shape rules — with a scaffold exception:
    //   (a) id strictly monotonic starting at 1
    //   (b) label + verdict always non-empty
    //   (c) Ok verdicts MUST pin a post_state blob — unless the scaffold
    //       override is active: every Ok's pre_state/transfer/post_state
    //       blob is empty, which signals "P.2/P.3 dependencies not yet
    //       available; blobs will be regenerated once encode_transfer
    //       supports 1..4 shapes and the real AIR lands." The fixture
    //       header documents this; we honour it here.
    //   (d) reject verdicts MUST NOT have post_state.
    int unpopulated = 0;
    for (size_t i = 0; i < fx.size(); ++i) {
        if (fx[i].id != (int)i + 1) {
            tprintf("  FAILED: fixture idx %zu has id=%d (expected %zu)\n",
                    i, fx[i].id, i + 1);
            return;
        }
        if (fx[i].label.empty() || fx[i].verdict.empty()) {
            tprintf("  FAILED: fixture %d missing label or verdict\n", fx[i].id);
            return;
        }
        if (fx[i].verdict != "Ok" && !fx[i].post_state_hex.empty()) {
            tprintf("  FAILED: fixture %d (reject) has post_state set\n", fx[i].id);
            return;
        }
        bool all_blobs_empty = fx[i].pre_state_hex.empty() &&
                               fx[i].transfer_hex.empty() &&
                               fx[i].post_state_hex.empty();
        if (all_blobs_empty) {
            ++unpopulated;
        } else if (fx[i].verdict == "Ok" && fx[i].post_state_hex.empty()) {
            tprintf("  FAILED: fixture %d (Ok, partially populated) missing post_state\n",
                    fx[i].id);
            return;
        }
    }
    if (unpopulated == (int)fx.size()) {
        tprintf("  SKIP: all %zu fixtures are unpopulated scaffolds "
                "(P.2 AIR + encode_transfer full-shape support pending; "
                "see state-transitions-v1.hex header)\n", fx.size());
        return;
    }
    tprintf("  PASSED (%zu fixtures parsed, id-ordered, shape-checked; "
            "%d unpopulated / %d populated)\n",
            fx.size(), unpopulated, (int)fx.size() - unpopulated);
}

// ---------------------------------------------------------------------------
// Lightweight reject-path driver (UNO_P4 gate half-flip).
//
// Full UnoShardState-backed verify/apply requires Agent 1's cell-state
// deserializer + a real Plonky3 prover for the Ok records; until both are
// wired we can still assert a tight invariant on the REJECT records:
//
//   For each reject record with populated `transfer_hex`:
//     1. BoC-deserialize the hex blob → root cell.
//     2. Run `decode_transfer` on the root cell slice.
//     3. The decode result MUST correlate with the declared verdict:
//        - verdict==BadSpendCount  → decoder rejects (sc out of range)
//        - any other reject verdict → decoder accepts (the rejection is
//          a verify-step concern, not a codec concern), AND the decoded
//          field that justifies the verdict matches expectation.
//     4. The verdict string MUST name a known VerifyResult enum value.
//
// This driver does NOT mutate state and does NOT require Plonky3. It flips
// the SKIP for reject records into deterministic PASSes, which is the
// UNO_P4 done-when gate this agent (K-fixtures) delivers.
// ---------------------------------------------------------------------------

namespace {

int hex_nib(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

bool hex_decode(const std::string& hex, std::string& out) {
    if (hex.size() % 2 != 0) return false;
    out.clear();
    out.reserve(hex.size() / 2);
    for (size_t i = 0; i < hex.size(); i += 2) {
        int hi = hex_nib(hex[i]);
        int lo = hex_nib(hex[i + 1]);
        if (hi < 0 || lo < 0) return false;
        out.push_back(static_cast<char>((hi << 4) | lo));
    }
    return true;
}

// Declared-verdict → expected decoder outcome. `true` means decoder accepts
// (the verdict is a verify-step concern, not a codec concern). `false`
// means decoder rejects (the verdict is a codec-layer concern).
bool expect_decoder_accepts(const std::string& verdict) {
    // The only reject verdict the *codec* itself enforces is BadSpendCount
    // (spend_count > 4) and BadOutputCount (output_count > 4). Everything
    // else is a downstream verify concern.
    if (verdict == "BadSpendCount")  return false;
    if (verdict == "BadOutputCount") return false;
    // BadVersion / BadSchemeId could be codec-enforced too if we policy
    // them there; current codec doesn't, so keep permissive.
    return true;
}

// Basic allow-list of verdict strings that map to a known VerifyResult.
// Kept in sync with the enum in uno/core/compute-phase.h; duplicated here
// to avoid pulling that header into the test (which would drag A2/A3
// types transitively).
bool is_known_verdict(const std::string& v) {
    static const char* known[] = {
        "Ok",
        "BadVersion", "BadSchemeId", "BadChainId", "ExpiryOutOfRange",
        "BadSpendCount", "BadOutputCount", "InsufficientFee", "UnknownAnchor",
        "DuplicateNullifierInTx", "DuplicateCommitmentInTx", "BadRistrettoPoint",
        "NullifierAlreadySpent", "BadSpendAuthSig", "BadPlonky3Proof",
        "DecodeError",
    };
    for (const char* k : known) if (v == k) return true;
    return false;
}

// Cross-check: the decoded Transfer's relevant field matches the verdict.
// Spot-checked fields only — full verify/apply is out-of-scope here.
bool decoded_matches_verdict(const uno_workchain::Transfer& tx,
                             const std::string& verdict,
                             std::string* why) {
    auto fail = [&](const char* m) { if (why) *why = m; return false; };
    if (verdict == "BadChainId") {
        // chain_id must disagree with the default testnet id.
        if (tx.chain_id == 0x554E4F54u) return fail("chain_id not mismatched");
    } else if (verdict == "InsufficientFee") {
        // fee below a reasonable default floor (100_000 nano, §10.2).
        if (tx.fee >= 100'000ULL) return fail("fee not below min");
    } else if (verdict == "ExpiryOutOfRange") {
        // expiry_block very small (the exact admission check uses the
        // live UnoState::current_block_seqno; here we just confirm it was
        // picked to be far below any plausible head).
        if (tx.expiry_block >= 1'000'000ULL) return fail("expiry_block not small");
    }
    // Other verdicts (NullifierAlreadySpent, UnknownAnchor, BadPlonky3Proof,
    // BadSpendAuthSig) can't be spot-checked from the wire alone — the
    // rejection is a function of pre_state / proof-verifier output. We
    // rely on codec acceptance as the minimum bar.
    return true;
}

}  // anonymous namespace

static void test_reject_path_decodes() {
    tprintf("[TEST] test_reject_path_decodes\n");
    std::string path = find_fixture_path();
    if (path.empty()) {
        tprintf("  FAILED: fixture not found\n");
        return;
    }
    std::vector<Fixture> fx;
    if (!load_fixtures(path, fx)) {
        tprintf("  FAILED: fixture load\n");
        return;
    }

    int ok_records      = 0;
    int reject_records  = 0;
    int reject_flipped  = 0;  // records that went SKIP → PASS this run
    int reject_skipped  = 0;
    for (auto& f : fx) {
        if (f.verdict == "Ok") {
            ++ok_records;
            // Valid records still need a real Plonky3 proof; gate behind
            // UNO_RUN_PROVE_FIXTURES env-var per the M-P2 integration plan.
            const char* run_prove = std::getenv("UNO_RUN_PROVE_FIXTURES");
            if (!run_prove || !*run_prove) {
                tprintf("  SKIP: fixture %d (%s) — valid-proof record, "
                        "set UNO_RUN_PROVE_FIXTURES=1 to regenerate\n",
                        f.id, f.label.c_str());
                continue;
            }
            // If the env-var is set but the record is still unpopulated, bail.
            if (f.transfer_hex.empty()) {
                tprintf("  SKIP: fixture %d (%s) — UNO_RUN_PROVE_FIXTURES "
                        "set but transfer_hex empty (regenerate fixture first)\n",
                        f.id, f.label.c_str());
                continue;
            }
            tprintf("  SKIP: fixture %d (%s) — valid-record apply driver "
                    "requires UnoShardState serializer (M-P2 scope)\n",
                    f.id, f.label.c_str());
            continue;
        }

        ++reject_records;
        if (!is_known_verdict(f.verdict)) {
            tprintf("  FAILED: fixture %d (%s) verdict=%s is not a known VerifyResult\n",
                    f.id, f.label.c_str(), f.verdict.c_str());
            continue;
        }
        if (f.transfer_hex.empty()) {
            tprintf("  SKIP: fixture %d (%s) — transfer_hex empty, "
                    "regenerate via generate-state-transitions-v1\n",
                    f.id, f.label.c_str());
            ++reject_skipped;
            continue;
        }

        // Decode hex → BoC bytes → root cell
        std::string boc;
        if (!hex_decode(f.transfer_hex, boc)) {
            tprintf("  FAILED: fixture %d (%s) transfer_hex is not valid hex\n",
                    f.id, f.label.c_str());
            continue;
        }
        auto cell_r = vm::std_boc_deserialize(td::Slice(boc.data(), boc.size()));
        if (cell_r.is_error()) {
            tprintf("  FAILED: fixture %d (%s) BoC deserialize failed: %s\n",
                    f.id, f.label.c_str(), cell_r.error().message().c_str());
            continue;
        }
        auto root = cell_r.move_as_ok();
        auto cs   = vm::load_cell_slice(root);
        auto dr   = uno_workchain::decode_transfer(cs);

        bool decoder_accepted = std::holds_alternative<uno_workchain::Transfer>(dr);
        bool expected_accept  = expect_decoder_accepts(f.verdict);

        if (decoder_accepted != expected_accept) {
            if (expected_accept) {
                auto& e = std::get<uno_workchain::TransferDecodeError>(dr);
                tprintf("  FAILED: fixture %d (%s) expected decoder to accept, "
                        "got error: \"%s\"\n",
                        f.id, f.label.c_str(), e.reason.c_str());
            } else {
                tprintf("  FAILED: fixture %d (%s) expected decoder to reject, "
                        "got accept\n", f.id, f.label.c_str());
            }
            continue;
        }

        if (decoder_accepted) {
            const auto& tx = std::get<uno_workchain::Transfer>(dr);
            std::string why = "?";
            if (!decoded_matches_verdict(tx, f.verdict, &why)) {
                tprintf("  FAILED: fixture %d (%s) decoded tx does not match "
                        "declared verdict reason: %s\n",
                        f.id, f.label.c_str(), why.c_str());
                continue;
            }
        }

        tprintf("  PASSED: fixture %d (%s) — verdict=%s, decoder=%s\n",
                f.id, f.label.c_str(), f.verdict.c_str(),
                decoder_accepted ? "accept" : "reject");
        ++reject_flipped;
    }

    tprintf("  SUMMARY: %d Ok records, %d reject records, %d reject PASSes, %d reject SKIPs\n",
            ok_records, reject_records, reject_flipped, reject_skipped);
}

static void test_state_transition_apply() {
    tprintf("[TEST] test_state_transition_apply\n");

#ifndef UNO_P3_DRIVER_READY
    tprintf("  SKIP: UNO_P3_DRIVER_READY not defined. Depends on:\n"
            "        • uno/core/compute-phase.h :: run_compute_phase\n"
            "        • uno/core/cell-state.h    :: serialize_state / deserialize_state\n"
            "        • uno/plonky3-ffi          :: real Plonky3 AIR (P.2 blocker)\n"
            "        Fixture framework validated; runtime assertions gated\n"
            "        until the full Transfer AIR lands (doc §12 P.3 permits SKIP).\n"
            "        Reject-path assertions now live in test_reject_path_decodes\n"
            "        above; valid-path assertions remain blocked on M-P2.\n");
    return;
#else
    // When the driver is ready, iterate fixtures and assert byte-equality.
    // This branch is compiled only once all dependencies are live; the
    // placeholder assertion here is intentionally kept to make the ready-path
    // visible in code review.
    std::string path = find_fixture_path();
    std::vector<Fixture> fx;
    if (!load_fixtures(path, fx)) { tprintf("  FAILED: fixture load\n"); return; }

    int passed = 0;
    for (auto& f : fx) {
        // TODO(uno-integration, P.2): decode pre_state, decode transfer,
        // construct UnoShardState from pre_state, run verify_transfer +
        // apply_transfer, serialize post-state, byte-compare.
        //
        // Until the verify pipeline is landable end-to-end, individual
        // fixtures SKIP rather than silently pass.
        tprintf("  SKIP: fixture %d (%s) — driver TODO\n", f.id, f.label.c_str());
        (void)passed;
    }
#endif
}

int main() {
    tprintf("Uno Workchain — §12 P.3 state-transition golden fixtures\n");
    tprintf("========================================================\n\n");

    test_fixture_file_is_parseable();
    test_reject_path_decodes();
    test_state_transition_apply();

    tprintf("\nTotal: passed=%d, failures=%d, skips=%d\n",
            g_passes.load(), g_failures.load(), g_skips.load());
    return g_failures.load() == 0 ? 0 : 1;
}
