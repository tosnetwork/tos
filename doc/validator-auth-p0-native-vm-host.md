# Privileged native VM host boundary

This is additive native execution plumbing. It does not change frozen public
wire/API bytes or authorize network activation. A concrete configuration-account
host, deterministic registry/proof gas schedule and native action/commit binding
are still required before these instructions can accept chain operations.

## Instructions and authority source

| Encoding | Instruction | Stack effect |
| --- | --- | --- |
| `f918` | `VAUTH_STATE` | `-- checkpoint:Cell` |
| `f919` | `VAUTH_APPLY` | `update:Cell evidence:Cell -- checkpoint:Cell` |

Both require native VM version at least 16, immutable capability 1024 and a host
injected by the native execution embedding. The evidence operand is opaque at this
VM layer; its native ingress contract must carry authorization objects and bounded
header witnesses. Neither an account-provided C7 nor executing the opcode itself
establishes configuration-account, owner or committee authority.

The C++ `ValidatorAuthHost` and independent Rust trait expose `checkpoint` and
`apply`, each with an explicit gas-charge callback. The opcode layer rejects
negative charges and invokes the VM's checked gas mechanism. Cell operand type
and stack underflow checks precede host application. Intrinsic opcode/return gas
remains charged by the ordinary VM machinery.

Nested RUNVM receives no privileged host, including when the parent is authorized.
Existing immutable crypto capability inheritance remains unchanged. The concrete
host must stage candidates until the actual transaction commits, including TVM
COMMIT followed by later failure and native action-phase rollback. This interface
does not itself implement those commit semantics.

## Evidence and limits

The test host only records calls, checks operand order, charges a specified amount
and returns distinguishable cells. Twenty-five shared cases compare exact native
C++/Rust results, gas and host call counts: version/capability refusal, absent host,
forged C7, nested VM isolation, insufficient gas, exact gas, negative charge,
underflow and wrong types. Six C++ and six Rust compiled guard removals fail the
intended assertions; restored baselines pass. Full-dependency Ubuntu/ARM
ASan/UBSan/LSan exports match. The existing 168 crypto VM outcome/gas cases still
match independently. These tests do not claim actual configuration transactions,
owner authorization, network execution or P0 acceptance.
