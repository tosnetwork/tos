# Replaceable authentication for Wallet V5 and Agent Account

## Scope and security claim

This change enhances the existing contracts before the public testnet. It does
not introduce a Wallet V6, an Agent Account V2, an on-chain code upgrade, a
post-quantum signature algorithm, or a consensus/network cryptography change.
Recompile the existing templates and regenerate their SDK bytecode. Their code
hashes, and therefore newly derived deployment addresses, change.

The result is **post-quantum-ready authorization**, not a claim of end-to-end
post-quantum security. A separately implemented and audited PQ verification
contract is still required. The Ed25519 relay in the regression tests is only
a test fixture and MUST NOT be used as a PQ module.

## One replaceable authorization root

Each account optionally stores one authentication root module. A root may
implement PQ signatures, thresholds or scoped delegates internally. This
iteration deliberately does not provide a dictionary of independently powerful
extensions or a capability registry: every registered root is trusted to
exercise the account's supported execution and management permissions.
Agent Account still independently enforces its spending and action policies.

The root must be a canonical, non-anycast standard address in the account's
workchain, and cannot be the account itself. An address commits to initial
StateInit, not necessarily to the module's current code. Use immutable modules
or PQ-protected upgrade/recovery policies; an Ed25519 backdoor in a verifier
would defeat module-only protection even if the account itself is correct.

## Storage and modes

Existing legacy initialization data remains valid. An optional **raw trailing
reference** is appended to the account data cell; it is detected by remaining
references and does not add a Maybe-presence bit. In Agent Account it follows
the policy reference; in Wallet V5 it follows the extension dictionary.
The referenced cell contains:

```
mode:uint2 epoch:uint64 nonce:uint64 module_hash:uint256
```

Absent reference means legacy authentication. Modes are:

| Value | Meaning | Classic entry points |
| --- | --- | --- |
| 1 | Staged: legacy OR module | Available; NOT PQ-only |
| 2 | Module only | Disabled |
| 3 | Module AND Ed25519 cosignature | Disabled as standalone authorizers |

Legacy authority may only stage a module. The staged module must authenticate
an actual request before switching the account to a strict mode. Once strict,
neither the module nor old owner/controller/extension paths can restore staged
or legacy mode. Strict modes may rotate the root and switch between 2 and 3.
Rotation increments the authentication epoch and resets its nonce. A uint64
counter at its maximum is rejected before writing state; rotate before exhaustion.

Strict-mode activation must happen while bootstrap authority is trustworthy.
For new PQ accounts, put the strict authentication cell directly in StateInit
and use a PQ-authenticated root from the beginning. Do not mistake the presence
of a module alongside an enabled classic path for AND authentication.

## Authenticated internal envelope

```
auth#41555448 request:^Cell cosignature:(Maybe ^Cell)

request$_ global_id:int32 account:MsgAddressInt
          epoch:uint64 nonce:uint64 valid_until:uint32
          kind:uint8 payload:^Cell
```

The module MUST verify its own proof over the entire request, including its
payload reference, chain ID, destination account, epoch, nonce, expiry and kind.
The account independently checks the sender, exact destination and network,
current epoch and nonce, expiry and maximum TTL. Wallet V5 caps TTL at 3,600
seconds; Agent Account uses its existing default_task_timeout. Bounced internal
messages are ignored. Trailing envelope/request data is rejected.

In mode 3, the account additionally verifies an exact 512-bit Ed25519 cosignature
(no references) over the representation hash of:

```
uint64(0x544f532d41555448) | ^request    # ASCII domain: TOS-AUTH
```

Both authorizations cover the SAME request. The account rejects missing, wrong,
mismatched and unexpectedly supplied cosignatures, as well as known weak
classical keys. Authentication nonces are independent from legacy wallet seqno
and Agent Account controller_epoch/seqno.

## Execution and management

`kind = 0` executes. Wallet V5's payload is a C5 OutList containing only
SENDRAWMSG actions, at most 255, with the ignore-action-errors bit required.
Unsupported flag bits, simultaneous carry-all modes, SETCODE and the destroy
flag are rejected. It does not accept arbitrary extended-management actions.
The wallet increments both its authentication nonce and ordinary seqno.

For Agent Account, payload is the existing unsigned controller-action body,
including global_id, controller_epoch, seqno and valid_until. The same limits,
exact deployment StateInit binding, balance/fee preflight, supported-action
checks and replay counters still apply. Authentication does not create an
unrestricted SENDRAWMSG bypass. Failed checks do not commit auth nonce or
account data; a successful mode-3 send retains the existing ignore-action-errors
semantics and may consume the action/nonce even when the action phase skips a
send. Integrators must inspect the transaction result, not only acceptance.

A refusal can also arrive after the account has accepted the request. Agent
Account accepts, commits the consumed seqno, and only then measures the
attached trees and reserves the exact fee, because that measurement is priced
by the caller's payload rather than by the contract and so cannot be charged
to the fixed external admission credit. A refusal on that side of the commit
moves no value and leaves the daily budget untouched, but it does spend the
seqno and the authentication nonce, and the transaction is not aborted --
so no bounce is produced. A module must read the account state to distinguish
this outcome from a completed send; waiting for a bounce will wait forever.
Spending the counters is deliberate: leaving them unspent is what would make
the refused request replayable until its expiry.

`kind = 1` reconfigures the root. Payload is `mode:uint2 module:MsgAddressInt`.
It is authorized by the CURRENT mode/root. Strict-to-staged downgrade is
forbidden. Wallet V5 clears its old extension dictionary and signature flag in
strict mode. Agent Account also advances controller_epoch and seqno, invalidating
old controller requests. Provision and validate a replacement verifier before
rotating: an unusable root can lock the account permanently. Once the mode is
strict, the owner cannot stage a replacement, rotate the controller, change
policy, or spend; only the installed root can install its successor. A root
that is lost, unresponsive or itself broken therefore ends the account's
usable life, and there is intentionally no classical recovery bypass. Treat
entry into a strict mode as irreversible and rehearse the replacement path
before using it in production.

`kind = 2` is Agent Account management only. Payload is the existing owner
message body (opcode, query_id and fields) for update_policy or rotate_controller.
The old owner address has no direct management permission in strict mode.
Controller rotation remains key rotation, not an authentication downgrade.

## Bootstrap operations

Agent Account owner message:

```
stage_auth#41475008 query_id:uint64 global_id:int32
                    expected_auth_epoch:uint64 module:MsgAddressInt
```

Wallet V5 signed extended action:

```
05 expected_auth_epoch:uint64 module:MsgAddressInt
```

The Wallet action must be the sole extended action and must not accompany a C5
OutList. Legacy extensions cannot stage a root. Once any root is staged, the
unbound legacy extension entry point is disabled, even before strict cutover.
Ordinary signed legacy messages remain usable in staged mode. Existing Wallet
V5 signed-request semantics can consume seqno for a signed request whose
subsequent action processing fails; applications must query current state after
an unsuccessful staging attempt.

## Gas, lifecycle and remaining work

Module requests are funded internal messages, so the verifier can separate its
proof cost from account execution. This does not make PQ verification free or
remove native gas, cell-depth, message-size and forwarding-fee limits. External
legacy requests still have the existing 10,000-gas admission credit in the test
configuration. The regression suite includes a bounded ordinary-cell deploy;
large StateInit deployments can exceed the credit (also observed on the
unmodified baseline) and require separate budgeting or the funded module path.
Do not increase network gas limits merely to make these tests pass.

Preventing explicit self-destruction does not make accounts immortal. Keep
accounts and verifier contracts funded for storage. Purging and redeploying an
original legacy StateInit could restore its original authority. PQ-from-genesis
StateInit avoids such a legacy authority in the original image. Client recovery,
module key backup, status discovery and safe root replacement remain operational
requirements. Existing high-level SDK transfer APIs are still classic APIs;
this change supplies the contract wire protocol, not a completed PQ wallet UI.

Validators, block signatures and network key establishment are outside this PR.
Do not advertise TOS as an entirely PQ-secure blockchain on this basis.

## Validation

`test/auth-extensions/test_auth.py` uses the native transaction emulator, not
only TVM compute execution. CHKSIG checking remains enabled. Agent Account and
Wallet FunC run at global version 6; the existing high-level Tol implementation
uses version-11+ context instructions and is tested at version 14. The existing
Rust contract sandbox suites remain a separate required compatibility gate.

The suite covers all three source implementations, real signed legacy messages,
module relay provenance, staged cutover, AND signatures, bad bindings, replay,
old authorization paths, overflow, policy limits and forbidden wallet actions.
`mutations.py` removes the nonce guard in each implementation and requires the
real execution tests to turn red. Regeneration is reproducible with:

```
python3 scripts/update-auth-contract-code.py
python3 scripts/update-auth-contract-code.py --check
python3 test/auth-extensions/test_auth.py
python3 test/auth-extensions/mutations.py
```

Set FUNC_PATH, FIFT_PATH, TOL_PATH and EMULATOR_PATH to native build outputs.
The harness uses Python cryptography solely for deterministic test signatures.
