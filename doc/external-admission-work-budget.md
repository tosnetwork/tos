# Default-on external admission work budget

Status: design proposal; no implementation is included. Review and agreement
precede implementation. Author: Bluebird. Intended reviewer: Egret.

Source references describe main at
`5bfe936ab3e144c2c055471262e14f1d604eab18`. Decision context:
[STATUS 13.103](https://github.com/tosnetwork/memo/blob/main/public-testnet/STATUS-AND-DECISIONS.md#13103-20000-credit-checks-the-admission-work-budget-is-opt-in-and-bound-to-the-whole-config-root--not-usable-as-is).
That decision record is private; this document contains the technical proposal
needed to review the design independently.

## Problem

The owner adopted basechain ConfigParam 21 `gas_credit = 20,000` from the
2026-10-06 admission plan. Masterchain CP20 remains 10,000. PR #266 updates
genesis and defaults; it changes newly created networks, not an existing
network's configuration. The epoch-5 genesis release must include working
admission protection before activation.

For an ordinary destination whose gas limit permits it, increasing credit from
10,000 to 20,000 doubles the nominal unpaid pre-ACCEPT gas available to an
invalid external message. Credit is not a CPU measurement: instruction
overshoot, decoding, cryptography and state lookup must also be bounded.

TOS already executes failed admission once, rather than repeating the VM to
collect a failure log (`validator/impl/ext-message-checker.cpp:124`, introduced
by `d27e7657e5`). It also has a non-refundable global work-bucket implementation
(`4f90000477`). Three gaps prevent treating that bucket as a deployed default:

| Gap | Current source and concrete consequence |
| --- | --- |
| F1: opt-in | `validator-engine/validator-engine.hpp:308` holds an optional profile. `validator-engine.cpp:1850` installs it only when supplied; `:6822` parses `--ext-message-work-profile`. `validator/impl/ext-message-pool.hpp:68–77` creates no work admission without it. The charge at `ext-message-pool.cpp:145–155` is conditional. A normal start without flags has no global work budget; genesis produces no profile. |
| F2: whole-root binding | `validator/impl/config.hpp:72–76` returns the ConfigParams dictionary root. `ext-message-pool.cpp:65–81` checks it on every masterchain state; `ext-message-work-profile.hpp:35–36` requires exact equality. A CP21 vote or CP32/34 validator-set change changes that root, making profile-carrying nodes refuse every external admission. The refusal is code 651, `external admission configuration is outside the work profile`; JSON-RPC currently returns `-32603` / `UPSTREAM_UNAVAILABLE`. |
| F3: fixed, uncalibrated cost | `validator/admission-work-profile.h:16–29` accepts operator-supplied `attempt_units` and numerical limits, with no hardware calibration. `ext-message-work-profile.hpp:39–41` consumes that fixed number. The gas-bound helpers in `ext-message-work-quote.hpp:19–50` have test callers, not production pricing callers. |

The internal root-only rebind at `ext-message-work-profile.hpp:22–32` preserves
tokens, but no running-engine operator command exposes it. The CLI setter at
`validator-engine.hpp:385–387` is wired at startup. Operators therefore need a
new profile and restart after each changed root; there is no automatic
configuration handoff. Leaving the flag absent avoids that refusal by leaving
the work budget off, which does not solve the protection problem.

For comparison, the upstream implementation at
`3d478cbde854be03a18ab2a59f8fc3c565cf7d14`,
`validator/impl/ext-message-checker.cpp:103–115`, repeats a failed VM run with
logging. It has no global admission work bucket and relies on the small credit
alongside byte, queue, inflight and source/address limits. The larger credit
and expensive signature paths require an explicit TOS work policy. Neither
inflight limits nor removing the repeated run establishes a CPU rate limit.

## Proposed policy

### Derive a policy from the pinned admission state

Replace the whole-root profile binding with a versioned, normalized admission
parameter descriptor. Recompute it on every installed masterchain state, using
the same decoded configuration and effective defaults as execution. Do not
hash raw ConfigParams or select a root independently from the checker state.

The descriptor includes:

* CP20 and CP21 gas fields: `gas_price`, `gas_limit`, `special_gas_limit`,
  `gas_credit`, `flat_gas_limit`, `flat_gas_price`, `block_gas_limit`,
  `freeze_due_limit` and `delete_due_limit`, with their effective constructor
  defaults. Some fields change execution funding rather than the mathematical
  initial-gas bound; including the decoded gas record avoids an implicit
  dependency on fields omitted from a fee calculation.
* CP43 effective external-message maximum serialized bytes and depth. Missing
  parameters use the execution defaults; malformed parameters are errors.
* Execution/calibration compatibility: supported VM/global versions and
  workchain execution engines. Any execution-affecting parameter used by the
  implementation must either enter the descriptor or be proven covered by
  the calibration envelope. This includes protocol-dependent opcode costs.
* Precompiled-contract configuration (CP45): reject a nonempty configuration
  that the existing quote cannot bound. Malformed configuration must not be
  mistaken for an absent precompiled list. Supporting it requires a separately
  reviewed quote and calibration, not a zero cost or ordinary-VM fallback.

CP32/34 and other unrelated parameters are excluded. A validator-set change
must not suspend admission, refill tokens or require an operator action.
Identical descriptors can reuse a cached quote, but installation still
validates compatibility against the new state.

Use `external_tvm_initial_gas_bound` from
`validator/impl/ext-message-work-quote.hpp` in production, for both CP20 and
CP21, and take a bound covering every destination accepted by this policy.
The helper already includes special-account initial gas plus credit. Do not
substitute just 20,000 for that bound, or classify every destination as
ordinary. The complete-transaction helper is not the admission bound:
`validator/impl/external-message.cpp:54` stops admission at ACCEPT.

Represent work in fixed CPU-time units, for example microseconds of aggregate
CPU time. A conservative attempt quote is the checked, rounded-up sum

```
Q = safety_factor * (parse_bound(max_bytes, max_depth)
                   + state_lookup_cpu_bound
                   + hardware_factor * initial_tvm_gas_bound
                   + instruction_overshoot_bound)
```

The hardware factor converts gas to measured CPU work on the calibrated class;
the other terms cover work that gas does not charge. Parsing, lookup, special
execution and overshoot are not free. Every term and multiplication uses
checked arithmetic and a versioned calibration record. A missing bound,
overflow, unsupported VM/engine, or quote exceeding the permitted burst
capacity refuses admission. Never clamp a required quote downward to make it
fit. An increased CP21 credit re-quotes automatically; no engine restart or
whole-root profile replacement is needed.

The initial implementation uses a single conservative quote before expensive
dispatch, taking the maximum across eligible destination classes. A cheaper
per-destination scheme would need a separately metered classification stage;
it is not justified by trusting an unauthenticated message's claimed type.
The special-account bound may make a single quote conservative; measure its
throughput before accepting that tradeoff.

### Default-on and operator controls

Create the global budget without a CLI profile. Ship a versioned conservative
calibration and CPU allowance with the node release; ordinary tos-ops install
and start commands pass nothing special. A calibration identifier, descriptor
fingerprint, effective quote, capacity and refill rate are visible in startup
logs and admission stats.

Operators may override the calibrated hardware class, lower rate/burst, or
provide a reviewed calibration for other hardware. Increasing the allowance
is an explicit override with validation and a prominent startup log. Do not
infer safe capacity by multiplying by an arbitrary host CPU count. An
uncalibrated machine cannot silently receive the fastest class's defaults.

Disabling protection requires an explicit, clearly named option and a warning
at startup plus persistent disabled status in stats. Absence of configuration
means enabled. Retire the experimental whole-root CLI format rather than
silently interpreting it as a new policy or retaining it as an opt-out.
Disabling is not an automatic response to unsupported chain parameters.

### State transitions and refusal semantics

Keep the bucket in stable CPU-work units across re-quotes. At a state change,
refill once using elapsed monotonic time and the old policy, preserve remaining
tokens and the refill clock, and install the new quote atomically with its
state descriptor. If capacity is lowered, clamp the balance to it; never
scale up available credit or reset to full. A change in quote alone changes
the number of affordable attempts, not the amount of stored work credit.

Queued requests revalidate size, descriptor and quote against a freshly pinned
masterchain state before charging and dispatching. No await may separate that
charge from checker dispatch with the same state. Already-dispatched work
remains charged under its pinned policy and is never refunded. A parameter
change is not permission to rerun admission.

Unsupported policy suspends new expensive dispatch, retaining the bucket and
bounded queues. It recovers automatically when a supported state arrives;
time spent unsupported cannot mint more than normal capped refill. A lowered
rate/capacity, unsupported-to-supported transition, or disable/re-enable must
not create a fresh burst. Use empty startup buckets and normal refill so
restarts cannot repeatedly grant full capacity. Readiness reports warming up
until one attempt is affordable. No durable bucket file is required by this
proposal; repeated starts lose credit instead of creating it.

Proposed distinct refusal reasons are `ADMISSION_POLICY_UNSUPPORTED` (quote or
calibration unavailable) and `ADMISSION_WORK_EXHAUSTED` (temporary scarcity).
Return a node-local not-ready status with a stable structured JSON-RPC reason;
reserve stable numeric codes during implementation review. Unsupported errors
state the unsupported parameter/class without exposing message contents.
Exhaustion is retryable, with a bounded retry hint where computable. Do not
misclassify either as an invalid signature, invalid block or successful send.
Rate-limit repeated diagnostics while keeping counters for every refusal.

### Existing protections remain independent

Keep the existing ordering and ownership of byte reservations, queue/inflight
caps, per-peer limits and post-check per-address limits. Bytes are occupancy:
release them on completion/cancellation. Work is spent: never return it on
VM rejection, signature failure, cancellation after dispatch, or success.
Cheap pre-dispatch refusals need not spend a full VM quote. Their own parsing
and routing overhead must still be measured under load; this budget is not a
claim that all RPC/server CPU is charged.

Broadcasts, queries, liteserver, JSON-RPC with or without a source address and
local submissions must converge on the same global charge. An absent peer
only affects per-peer accounting. Keep the single-run checker and its actual
VM-count controls. Queue caps bound waiting memory, not work already admitted.

### Consensus neutrality

This policy controls one node's willingness to accept external messages into
its local pipeline. It is never a block-validity, transaction-validity or
validator-set condition. Validators must still validate an otherwise valid
block containing a message they would locally rate-limit. Nodes with
different calibrated budgets remain consensus-compatible. No calibration
record, quote, bucket balance or operator override is written into consensus
state, signed as a block condition, or used to alter transaction execution.

## Calibration and fairness acceptance

Calibrate on the production-class testnet VPS: 6 vCPU, 12 GB RAM, virtio disk.
Record CPU model, virtualization, CPU quota, memory/disk, compiler/build flags,
node revision, crypto backend, calibration version and input hashes. Repeat
with competing block processing and cold/warm caches, not only an idle large
coordinator. Do not publish a measured factor before those runs exist.

Measure process/thread user and system CPU, wall latency, allocations/peak
memory and I/O separately for decode/parse, state fetch/lookup, and TVM
execution. Exercise maximum bytes/depth, malformed encodings, invalid
signatures, maximum-cost ordinary and special paths, instruction overshoot,
and every permitted VM/engine/config range. Verify the failure path actually
runs the VM once. Use adversarial tails and repeated measurements with safety
headroom, not only median valid-message gas. Disk stalls are bounded by
existing wait/inflight/byte controls and must not be passed off as CPU cost.

Proposed initial target for review: admission under sustained attack uses at
most **20% of aggregate six-vCPU capacity**, or 1.2 CPU-seconds per second,
leaving 80% for chain progress and other work. In microsecond work units,
refill is at most 1,200,000 units/s, reduced for measured unmetered ingress
overhead and safety margin. Proposed burst window is at most 250 ms of this
allowance; its capacity must still cover the largest supported quote. If no
safe quote fits, revise the policy/calibration before release, rather than
silently expanding the burst or weakening the bound. These are proposed
acceptance targets, not measured shipped constants.

Derive the hardware factor and fixed bounds from the measured worst envelope,
rounding upward; derive refill/burst from the CPU-share target and measured
background needs, rounding downward. Validate the resulting defaults with an
independent holdout corpus and both supported launch architectures. A single
factor is valid only over its tested scope. The calibration record must
express the allowed gas/size/depth/version range; out-of-range re-quotes fail
closed even if arithmetic succeeds.

Measure legitimate ordinary, rescue and POP submissions mixed with unique
invalid signatures, using separate unspent test identities to avoid replay
and duplicate-cache shortcuts. Record offered rates, dispatches, signature
refusals, budget refusals, CPU share, chain head age, admission latency and
actual executed transactions linked by message hash. Test below budget and
at several overload levels, across many source identities and source-less
queries. Retries reuse the same signed bytes with bounded backoff.

The previous local experiment at an explicit four-attempt/s policy admitted
all normal traffic at 2 invalid/s plus 0.5 normal/s. At 10 invalid/s plus 0.5
normal/s it shed 11 of 12 normal sends; rescue and POP each succeeded after
two retries. That proves limiting in that experiment, not fairness. A global
bucket provides no priority guarantee against arbitrary competing arrivals.

For review, propose at least 99% legitimate admission within five seconds at
the supported below-budget mixed rate, and a separately agreed success/latency
target under overload, reported per legitimate class. If overload fairness
is required but fails, release needs a reviewed scheduling/reservation design;
do not grant priority using an unverified rescue label or claim retries alone
solve starvation. Exact attack rates, repetition count and overload target
remain reviewer decisions.

## Alternatives considered

* Whole-root pins plus restart/rebind runbooks: brittle for routine validator
  rotation, suspend all ingress, and conflate unrelated consensus changes
  with work cost. An operator rebind command alone does not fix default-off
  or missing calibration.
* Mandatory manual profiles generated by tos-ops: couples every deployment
  and rotation to an external generator, leaves non-tos-ops nodes unprotected,
  and still requires automatic re-quoting. tos-ops should verify defaults.
* Fixed uncalibrated tokens/attempt: cannot relate CP21 changes or hardware
  cost to an attack CPU share. Gas-only multiplication omits parse/lookup and
  instruction overshoot.
* Lower credit, or rely solely on inflight/per-peer limits: does not meet the
  adopted rescue admission requirement and limits concurrency or one source
  rather than aggregate work. Multiple sources still share the CPU.
* Refund failed work, reset buckets on state changes, or run the failure VM
  again for logs: gives attackers free work or repeated bursts.
* Use full-transaction gas as the normal admission quote: admission stops at
  ACCEPT; it conflates paid execution and unpaid checks. Special execution
  still needs the existing helper's larger initial bound.
* Consensus enforcement of the local rate: would make machine-local policy
  affect block validity and is outside this design.

## Test plan and red controls

Every control must fail at its intended assertion when its guard is removed,
then pass after restoration. Compilation failure is not a valid red receipt.

| Boundary | Positive and negative tests | Red control |
| --- | --- | --- |
| Unrelated configuration | Real MC-state fixtures change CP32/34 and another unrelated parameter; all ingress sources keep working and credit/clock are unchanged. | Reintroduce whole-root equality; the rotation test must refuse. |
| CP21/CP20 changes | Increase/decrease credit and gas/special/flat fields; install new states and assert exact helper-derived quote, throughput and preserved tokens. Include queued requests and a decrease back. | Freeze old quote, omit one relevant field, or refill on update; each dedicated assertion fails. |
| Default-on | Launch a generated-genesis node without admission flags; all sources exhaust one shared budget, including peerless RPC. Explicit opt-out is warned and observable. | Make construction optional again; no-flag exhaustion must fail. |
| Unsupported scope | CP45 precompiled config, malformed config, unsupported VM/engine, arithmetic overflow and out-of-calibration limits refuse before expensive dispatch with the named reason. Supported state restores admission without restart. | Ignore each compatibility/overflow check; assert a checker dispatch would otherwise occur. |
| Stable work state | Re-quotes, repeated config oscillation, operator updates and disable/re-enable create no credit. Restart begins empty and cannot repeatedly grant bursts. | Reset to full on any transition/start; observed dispatch count exceeds the envelope. |
| Resource ownership | Preserve bytes, inflight/queue and per-source/address limits; failed/successful checks never refund work, and VM failure executes once. | Refund work, bypass a source, or rerun VM; counters and envelope tests fail. |
| CPU and legitimate traffic | On the VPS class, mixed traffic stays within the approved CPU-share/burst envelope while measured normal/rescue/POP success and latency meet the agreed targets. Verify execution, not only accepted RPC answers. | Disable charging or underprice expensive failures; measured dispatch/CPU envelope must fail. A no-retry control demonstrates the reported retry contribution without claiming scheduler fairness. |
| Consensus separation | A block containing locally rate-limited messages validates identically on nodes with different local budgets. | Wire policy into block validation; the differing-policy replay must fail. |

Run the relevant native option/pool/manager/checker suites, JSON-RPC reason
tests, default genesis/PQ admission corpus, source coverage and checked
arithmetic/static-analysis gates. Retain bounded calibration data and exact
red/green commands with hashes; no live-network action is part of this design
PR. Calibration and the CPU/fairness tests are implementation release gates,
not claims established by this document.

## Rollout

1. Agree this design and its open questions. Implement and independently
   review it in a separate PR; the design-only PR changes one document.
2. Calibrate/reproduce the defaults on the VPS class and supported
   architectures, run controls and a local epoch-5 rehearsal with default
   CP21=20,000 / CP20=10,000, no candidate flag and no manual profile. Exercise
   validator-set rotation and a local CP21 transition before public use.
3. Ship the protected binary with the epoch-5 genesis release. No live vote
   is needed to establish that genesis's credit. The public reset remains a
   separately authorized action; epoch 5 waits for implementation and gates.
4. In tos-ops, remove any dependency on manually generated whole-root
   profiles, start with ordinary default options, and verify effective
   enabled/calibrated status in install/start/readiness checks. Test an
   explicit disabled override as visibly unsafe; do not silently supply it.
   Update operator documentation and expose refusal/quote/CPU diagnostics.
5. Before mainnet: independent security review, wider hardware calibration,
   long attack/rotation soaks, explicit fairness acceptance, operational
   monitoring and upgrade/rollback procedures. A later live CP21 change must
   re-quote automatically within the approved calibration envelope; otherwise
   it intentionally refuses with an actionable reason, never disables itself.

## Questions for Egret and the reviewer

1. Is the normalized descriptor and compatibility envelope complete? In
   particular, which protocol/workchain/authentication changes need explicit
   version rejection beyond CP20/21, CP43 and CP45?
2. Accept the conservative maximum-across-destinations initial quote, or is a
   separately charged classification stage necessary to avoid the special
   bound making ordinary throughput unusable?
3. Are 20% aggregate CPU and a 250 ms burst appropriate for the six-vCPU VPS?
   What safety factor, sampling duration and holdout hardware are required
   before selecting actual constants?
4. What legitimate rescue/POP success rate and latency under which overload
   rates gate epoch 5? Is measured retry fairness enough for this milestone,
   or must an authenticated scheduling policy be designed first?
5. Agree empty startup buckets, stable CPU-work units, explicit warned opt-out
   and removal of the experimental profile format? What structured numeric
   error codes should accompany the proposed JSON-RPC reasons?

No implementation, hardware calibration result, activation permission or
mainnet readiness is implied by accepting this document for review.
