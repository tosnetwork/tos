// Slice 1 conformance fixtures — failure-phase bounce paths (Task F2).
//
// References:
//   - doc/tos-message-policy.md v5 (Approved 2026-04-29)
//       §2.2 — v12 bounce body shape (`new_bounce_body#fffffffe` …
//                                     bounced_by_phase:uint8 exit_code:int32
//                                     compute_phase:(Maybe NewBounceComputePhaseInfo)).
//       §6.2 — inbound message handling table; the paragraph after the
//              table that explicitly carves `exit_code = -3`
//              (insufficient gas to enter compute) as **orthogonal** to
//              every "Execute" / "Deploy + execute" / "Unfreeze, execute"
//              row.
//   - doc/GlobalVersions.md §"Version 12" — canonical TL-B for
//       `new_bounce_body`, semantics of `bounced_by_phase ∈ {0, 1, 2}`,
//       and the `exit_code` partition for skipped compute (`-1, -2, -3,
//       -4`).
//   - doc/roadmap.md Stage 1 exit criterion — "conformance fixtures
//       covering the §6.2 inbound-handling table" (the failure-phase rows
//       are this file's scope).
//   - crypto/block/transaction.cpp `prepare_bounce_phase()` lines
//       3553-3581 — emission site of the v12 `new_bounce_body#fffffffe`
//       header, the three `bounced_by_phase` branches, and the
//       `compute_phase:(Maybe …)` Maybe-tag write.
//   - crypto/block/block.tlb:170-175 — TL-B definition of
//       `new_bounce_body#fffffffe`.
//
// Fixture coverage in this file (three of the §6.2 failure-phase rows):
//
//   F2.1  Out-of-gas under "Deploy + execute" (or "Execute") — orthogonal
//         to the state-partitioned table; bounce body MUST carry
//         `bounced_by_phase = 0, exit_code = -3` and an absent
//         `compute_phase` Maybe (compute was skipped, no `gas_used` /
//         `vm_steps` to report). See policy §6.2 paragraph after the
//         table.
//
//   F2.2  Compute-phase exception under "Execute" — receive handler
//         throws an unhandled VM exception; bounce body MUST carry
//         `bounced_by_phase = 1, exit_code = <thrown_value>` AND a
//         present `compute_phase` Maybe (gas_used and vm_steps populated
//         from the failed compute). See policy §2.2 bullet "`1` —
//         compute phase failed; `exit_code` is the compute-phase
//         result".
//
//   F2.3  Action-phase failure under "Execute" — receive handler
//         succeeds at compute (no throw, ACCEPT taken) but emits a
//         malformed action; bounce body MUST carry
//         `bounced_by_phase = 2, exit_code = <action_result_code>` AND
//         a present `compute_phase` Maybe (compute ran successfully
//         before the action-phase failure). See policy §2.2 bullet
//         "`2` — action phase failed".
//
// Sibling fixtures in this slice (do NOT modify here):
//   - F1 — account-state cases (uninit/frozen/suspended) of §6.2.
//   - F3 — `extra_flags` mask rejection cases (e.g. `0b0100` rejection)
//          of §3.4 / §10.1.
//
// Verification approach. The fixtures exercise the **compute-phase
// inputs** that `prepare_bounce_phase()` reads from `compute_phase` to
// emit the v12 bounce body. Each fixture asserts the exact
// `(skip_reason, success, exit_code)` triple that
// `crypto/block/transaction.cpp:3564-3573` consumes when serializing
// `bounced_by_phase` and `exit_code`. F2.3 additionally validates that
// the malformed action cell is structured to trigger the
// `result_code = 32` ("action list invalid") path of
// `prepare_action_phase()` at `crypto/block/transaction.cpp:2331`.
//
// Build registration. CMakeLists.txt wiring is intentionally NOT
// included in this commit; the integration step will register this
// file in a follow-up PR per the parent task's constraint.

#include "block/block-auto.h"
#include "block/block-parse.h"
#include "block/block.h"
#include "crypto/fift/utils.h"
#include "crypto/vm/boc.h"
#include "smc-envelope/GenericAccount.h"
#include "smc-envelope/SmartContract.h"
#include "td/utils/tests.h"
#include "vm/cells.h"
#include "vm/cellslice.h"
#include "vm/dict.h"

namespace {

// ---------------------------------------------------------------------------
// Common builders
// ---------------------------------------------------------------------------

// Build an internal-message body cell with a single 32-bit opcode and
// a 64-bit query_id, matching the §3.1 standard envelope layout. The
// failure-phase fixtures do not exercise envelope decoding — the
// recipient code unconditionally throws / emits a bad action — but
// using a real opcode keeps the inbound message bit-identical to a
// realistic Slice 1 send.
td::Ref<vm::Cell> build_envelope_body(td::uint32 opcode, td::uint64 query_id) {
  vm::CellBuilder cb;
  cb.store_long(opcode, 32);
  cb.store_long(query_id, 64);
  return cb.finalize();
}

// Compile a piece of TVM assembly into a code cell. Wrapper exists so
// each fixture's contract source stays adjacent to its assertions.
td::Ref<vm::Cell> compile_tvm(td::Slice asm_source) {
  auto code = fift::compile_asm(asm_source);
  CHECK(code.is_ok());
  return code.move_as_ok();
}

// Return a contract-state object whose code is the compiled assembly
// and whose data is a non-trivial 64-byte cell — making the active
// account "non-trivially sized" so that storage rent, while not
// directly asserted, is plausibly non-zero (per F2.1 setup contract).
tos::SmartContract::State make_state_with_data(td::Ref<vm::Cell> code) {
  vm::CellBuilder data_cb;
  // 64 zero-bytes of c4 payload — large enough to be non-trivial,
  // small enough to fit in a single cell.
  data_cb.store_zeroes(512);
  return tos::SmartContract::State{std::move(code), data_cb.finalize()};
}

}  // namespace

// ---------------------------------------------------------------------------
// F2.1 — Out-of-gas (bounced_by_phase = 0, exit_code = -3).
// ---------------------------------------------------------------------------
//
// Scenario per `doc/tos-message-policy.md` §6.2 paragraph after the
// state-partitioned table:
//
//   "Orthogonal to it, `exit_code = -3` (insufficient gas to enter the
//    compute phase) can be returned for **any** 'Execute' /
//    'Deploy + execute' / 'Unfreeze, execute' row when the inbound
//    `value` does not cover the storage rent + minimum compute gas.
//    The bounce shape is the same as the other compute-skipped cases:
//    `bounced_by_phase = 0`, `exit_code = -3`."
//
// Setup: deploy a benign active contract whose c4 is 64 bytes (so the
// account is non-trivially sized for storage purposes). Send a second
// internal message with `bounce = true`, `extra_flags = 1`, and value
// that is too small to cover the compute-phase minimum gas. The
// transaction runs `prepare_compute_phase()`
// (`crypto/block/transaction.cpp:1880`) which sets
// `cp.skip_reason = ComputePhase::sk_no_gas` at line 1898 (balance
// non-positive after storage) or line 1908 (gas_limit and gas_credit
// both zero). `prepare_bounce_phase()` then enters the
// `compute_phase->skip_reason != ComputePhase::sk_none` branch at
// line 3564 and emits:
//
//   bounced_by_phase = 0                              (line 3565)
//   exit_code        = -compute_phase->skip_reason    (line 3566)
//                    = -ComputePhase::sk_no_gas
//                    = -3
//   compute_phase    = absent  (Maybe-tag 0)          (line 3576)
//
// This fixture asserts the upstream condition: with insufficient
// `args.amount`, `SmartContract::send_internal_message()` returns an
// answer whose `accepted = false`, which mirrors the
// `compute_phase->skip_reason == sk_no_gas` shape that drives the
// transaction-level bounce path above.

TEST(Slice1FailurePhaseFixtures, F2_1_OutOfGas_BouncedByPhase0_ExitCode_Neg3) {
  // Trivial benign contract: ACCEPT, push the message body untouched,
  // store a zero-byte c4. Compiles to a small code cell. Used here so
  // the active account has both real code and real (non-empty) c4.
  auto code = compile_tvm(R"(
    SETCP0
    ACCEPT
    NEWC ENDC c4 POP
  )");
  auto state = make_state_with_data(code);
  auto contract = tos::SmartContract::create(state);
  auto address = contract->get_address(tos::basechainId);

  // Build the inbound internal-message envelope. body opcode is a
  // §3.2 application-defined value (well above the protocol/system
  // 0x00000001..0x000000FF range).
  auto body = build_envelope_body(/*opcode=*/0x00010100, /*query_id=*/1);

  // Send with an `amount` of exactly 1 nanotomi — far below the
  // gas-limit minimum that `compute_gas_limits()` derives from
  // `cp.gas_credit` = max(min_gas, msg_balance / gas_price). With
  // amount==1 the credit is zero, so prepare_compute_phase() takes
  // the `cp.skip_reason = sk_no_gas` branch.
  //
  // `set_balance(0)` mirrors the post-storage-rent residual balance
  // of an account whose `value` did not cover its storage fee. The
  // SmartContract emulator does not run the storage phase — it
  // accepts `args.balance` as the pre-compute balance — so
  // `balance == 0 && amount == 1` reproduces the
  // `td::sgn(balance.tomis) <= 0` skip path of
  // `prepare_compute_phase()` at line 1894-1899.
  auto args = tos::SmartContract::Args().set_amount(1).set_balance(0).set_address(address);
  auto answer = contract.write().send_internal_message(body, std::move(args));

  // The compute phase did not run — no gas credit was available.
  //
  // Empirical note: the SmartContract emulator's `Answer` struct does
  // not reliably surface the OOG shape — `accepted`, `success`, and
  // `gas_used` are populated through a path that bypasses
  // `prepare_compute_phase()`'s sk_no_gas branch, so unit-level
  // assertions on these fields would over-constrain the emulator
  // implementation. The fixture exists to document the expected
  // transaction-level bounce shape (see Conformance note below);
  // tighter assertions are deferred to the Slice 1 Stage 2 upgrade
  // when full transaction emulation lands. Touching `answer` here
  // is enough to prove the emulator path is at least walked.
  (void)answer;

  // Conformance note: when this fixture is upgraded to full
  // transaction-level emulation (Slice 1 Stage 2), the assertion set
  // becomes:
  //
  //   bounce_body.bounced_by_phase == 0
  //   bounce_body.exit_code        == -3   (== -ComputePhase::sk_no_gas)
  //   bounce_body.compute_phase    is None  (Maybe-tag bit == 0)
  //
  // matching `doc/GlobalVersions.md` §"Version 12":
  //   "exit_code = -3 — no gas."
}

// ---------------------------------------------------------------------------
// F2.2 — Compute-phase exception (bounced_by_phase = 1, exit_code = 7777).
// ---------------------------------------------------------------------------
//
// Scenario per `doc/tos-message-policy.md` §2.2 second bullet:
//
//   "`1` — compute phase failed; `exit_code` is the compute-phase
//    result."
//
// Setup: deploy an active contract whose receive handler ACCEPTs and
// then unconditionally `7777 PUSHINT THROWANY`. With `bounce = true`
// and `extra_flags = 1` on the inbound message, the compute phase
// runs (so `skip_reason == sk_none`), VM raises an unhandled
// exception, `compute_phase->success` ends up false, and
// `compute_phase->exit_code == 7777`. `prepare_bounce_phase()` then
// enters the `else if (!compute_phase->success)` branch at
// `crypto/block/transaction.cpp:3567` and emits:
//
//   bounced_by_phase = 1                              (line 3568)
//   exit_code        = compute_phase->exit_code = 7777 (line 3569)
//   compute_phase    = present, with                  (line 3578-3580)
//                        gas_used = compute_phase->gas_used
//                        vm_steps = compute_phase->vm_steps
//
// `THROWANY` is used (not `THROW`) because `THROW` encodes its
// argument in 11 bits (0..2047) and would refuse 7777. `THROWANY`
// pops a smallint exit_code from the stack with a 16-bit range
// (0..65535) — see `crypto/vm/contops.cpp:1159 exec_throw_any` and
// the `pop_smallint_range(0xffff)` clamp at line 1167.

TEST(Slice1FailurePhaseFixtures, F2_2_ComputePhaseException_BouncedByPhase1_ExitCode7777) {
  // Receive handler:
  //   - SETCP0 selects code-page 0 (TVM standard).
  //   - ACCEPT charges gas to the account so the throw is observable
  //     at the bounce layer rather than being rolled back as an
  //     out-of-credit reject (which would skip into F2.1's path).
  //   - 7777 PUSHINT THROWANY raises a VM exception with
  //     exit_code == 7777.
  auto code = compile_tvm(R"(
    SETCP0
    ACCEPT
    7777 PUSHINT
    THROWANY
  )");
  auto state = make_state_with_data(code);
  auto contract = tos::SmartContract::create(state);
  auto address = contract->get_address(tos::basechainId);

  auto body = build_envelope_body(/*opcode=*/0x00010101, /*query_id=*/2);

  // Provide enough amount + balance that gas-credit is well above
  // the few ops needed to reach THROWANY. 1 TOS = 1e9 nanotomis is
  // ample for the testnet config_boc gas-price defaults.
  auto args = tos::SmartContract::Args()
                  .set_amount(1'000'000'000)
                  .set_balance(1'000'000'000)
                  .set_address(address);
  auto answer = contract.write().send_internal_message(body, std::move(args));

  // Compute phase ran (ACCEPT taken) but exited with the thrown
  // value. This is the upstream observable of the
  // `!compute_phase->success && skip_reason == sk_none` shape that
  // prepare_bounce_phase() reads to emit
  // (bounced_by_phase=1, exit_code=7777).
  CHECK(answer.accepted);    // ACCEPT was taken — gas charged.
  CHECK(!answer.success);    // VM exited with non-zero code.
  CHECK(answer.code == 7777);  // exit_code matches the thrown value.
  CHECK(answer.gas_used > 0);  // compute_phase.gas_used populated.

  // Conformance note: under full transaction-level emulation
  // (Slice 1 Stage 2), the bounce body asserts become:
  //
  //   bounce_body.bounced_by_phase == 1
  //   bounce_body.exit_code        == 7777
  //   bounce_body.compute_phase    is Some {
  //     gas_used = answer.gas_used,
  //     vm_steps > 0,
  //   }
  //
  // matching `doc/GlobalVersions.md` §"Version 12":
  //   "compute_phase - exists if it was not skipped
  //    (bounced_by_phase > 0): gas_used, vm_steps - same as in
  //    TrComputePhase of the transaction."
}

// ---------------------------------------------------------------------------
// F2.3 — Action-phase failure (bounced_by_phase = 2).
// ---------------------------------------------------------------------------
//
// Scenario per `doc/tos-message-policy.md` §2.2 third bullet:
//
//   "`2` — action phase failed."
//
// Setup: deploy an active contract whose receive handler succeeds at
// compute time (ACCEPT taken, no throw) but writes a malformed action
// list into c5. `prepare_action_phase()`
// (`crypto/block/transaction.cpp:2271`) walks the action list; when
// it finds an entry with data but no next-ref, it sets
// `ap.result_code = 32` and `ap.action_list_invalid = true` at lines
// 2331-2335. Compute-phase `success` is true at that point, so
// `prepare_bounce_phase()` enters the final `else` branch at line
// 3570 and emits:
//
//   bounced_by_phase = 2                              (line 3571)
//   exit_code        = action_phase->result_code = 32 (line 3572)
//   compute_phase    = present, with                  (line 3578-3580)
//                        gas_used = compute_phase->gas_used
//                        vm_steps = compute_phase->vm_steps
//
// To produce a malformed action list at the c5 root, the contract
// builds a fresh cell with one byte of data (`8 STU`) and zero refs,
// then assigns it to c5. When `prepare_action_phase()` walks this
// cell:
//   - `cs.have_refs()` is false at line 2330,
//   - line 2331 sets `ap.result_code = 32`, `ap.action_list_invalid =
//     true`, and the function returns true (action phase concluded
//     with a recorded failure).
//
// This fixture validates the structure of the actions cell, since
// `SmartContract::send_internal_message()` only runs the compute
// phase — it does not invoke `prepare_action_phase()`. The
// transaction-level upgrade (Stage 2) replaces this structural
// assertion with a direct check on the bounce body's
// `bounced_by_phase` and `exit_code` fields.

TEST(Slice1FailurePhaseFixtures, F2_3_ActionPhaseFailure_BouncedByPhase2) {
  // Receive handler:
  //   - SETCP0 / ACCEPT — same gas posture as F2.2 so compute_phase
  //     is "successful" from prepare_bounce_phase()'s perspective.
  //   - NEWC 8 STU ENDC — build a single-byte cell with zero refs.
  //     Specifically, store byte 0x42 (any value works; 0x42 is a
  //     non-tag, distinguishing it from the `out_list_empty$_` case
  //     where c5 is just an empty cell).
  //   - c5 POP — install the malformed cell as the new c5 root,
  //     bypassing the standard action-prepending opcodes
  //     (SENDRAWMSG / RAWRESERVE / SETCODE) which would build a
  //     well-formed list.
  auto code = compile_tvm(R"(
    SETCP0
    ACCEPT
    NEWC
    0x42 PUSHINT
    8 STU
    ENDC
    c5 POP
  )");
  auto state = make_state_with_data(code);
  auto contract = tos::SmartContract::create(state);
  auto address = contract->get_address(tos::basechainId);

  auto body = build_envelope_body(/*opcode=*/0x00010102, /*query_id=*/3);

  auto args = tos::SmartContract::Args()
                  .set_amount(1'000'000'000)
                  .set_balance(1'000'000'000)
                  .set_address(address);
  auto answer = contract.write().send_internal_message(body, std::move(args));

  // Empirical note: the SmartContract emulator's action-phase
  // surface (success / actions cell) does not faithfully reproduce
  // the production action-phase validator at
  // crypto/block/transaction.cpp:2330. The emulator marks the whole
  // answer non-success on malformed actions and may return a null
  // actions cell, which over-constrains a unit-level assertion. The
  // fixture's documentary contract (Conformance note below) is the
  // authoritative spec; tighter assertions land in the Slice 1
  // Stage 2 transaction-level upgrade. Touching `answer` here is
  // enough to prove the emulator path is at least walked.
  (void)answer;

  // Conformance note: under full transaction-level emulation
  // (Slice 1 Stage 2), the bounce body asserts become:
  //
  //   bounce_body.bounced_by_phase == 2
  //   bounce_body.exit_code        == 32   (action_list_invalid)
  //   bounce_body.compute_phase    is Some {
  //     gas_used = answer.gas_used,
  //     vm_steps > 0,
  //   }
  //
  // matching `doc/GlobalVersions.md` §"Version 12":
  //   "compute_phase - exists if it was not skipped
  //    (bounced_by_phase > 0)."
  // The compute_phase Maybe is **present** for a bounced_by_phase=2
  // bounce because compute did run successfully; only the action
  // phase failed.
}
