# Read-only original-operation delivery receipts

`tosctl wallet receipt` is a read-only ledger-evidence primitive for an opaque
custody controller. It never opens a Vault, signs, broadcasts, changes an operation
journal, or authorizes a replacement operation. In particular, a timeout or a
bounded history miss is **unknown**, not evidence of non-execution.

The controller supplies a locally approved `tos.operation-delivery-intent/1`
JSON file containing:

- `operation`, a bounded public operation identifier;
- `genesis_root` and `genesis_file`, the full zerostate identity;
- `sender`, `sender_code_hash`, `recipient`, and `recipient_code_hash`;
- `external_message_hash`, the original external message's cell representation
  hash, and `body_hash`, the approved downstream internal-message body hash;
- `value_nanotos`, `credited_nanotos`, and `bounce`;
- `rpc`, exactly two distinct public RPC URLs;
- `history_limit` (1–1024 per account per endpoint), `max_age_seconds` (1–3600),
  and `timeout_seconds` (1–300 for the combined proof/history operation).

Hashes are 64 lowercase hexadecimal characters. RPC endpoints may not carry
credentials, query strings, or fragments. The intent is local policy; it must
not be assembled from an unverified RPC reply. The caller must pin its approved
intent, CLI executable, native verifier executable/configuration, operation and
controller generation before using the result. The configured verifier is a
local trust source, exactly as for the existing proven-getter APIs.

`external_message_hash` is the full message **cell representation hash**, not a
SHA-256 of HTTP/JSON-RPC bytes, a query ID or a wallet sequence number. The
controller must bind both its transport admission record and this message hash
to the same original operation before the first forward.

The command also requires `--proof-config`, `--sender-pre-state`, and
`--recipient-pre-state`. The pre-state files are public `Account` preimages for
the two actual transactions. Each is authenticated against its transaction's
old-state hash. An earlier observed snapshot is usable only if it is exactly
that preimage; concurrent messages or TickTock execution can invalidate it.
Missing actual preimages remain a refusal, never an excuse to substitute current
code for executed code. Symlinks and non-regular inputs are refused;
input bytes and BOC depth are bounded. No signed request, Vault, private carrier
or financial journal is an input. The public full original-message hash is
matched inside authenticated history; the command never prints message bytes.

The implementation reuses `ProvenGetterProvider` and `ProvenTransaction`:

1. Match the intent's full genesis to the locally provisioned zerostate anchor.
2. Authenticate the sender live, then the recipient at the exact same trusted
   masterchain checkpoint. Require the approved current code identities.
3. From each RPC separately, traverse authenticated transaction history to the
   exact original external message. Bind its retained pre-state to the
   transaction's old-state hash and the approved executed code.
4. Require the sender to emit exactly one outgoing message, matching the approved source,
   destination, complete base-currency value, body, and bounce flags, without a
   StateInit. Authenticate that exact message's recipient transaction and its
   executed code. Require complete execution, the exact delivery link, and the
   locally approved credit-phase amount.
5. Require both endpoints to yield the same authenticated receipt identities,
   and recheck both masterchain and shard observation ages before returning.

Only public operation/checkpoint/transaction/message identities are returned.
The output explicitly sets `business_acceptance: false` and
`authorizes_send: false`. Credit-phase value is not spendable final balance.

This command handles one external-wallet → internal-recipient edge between
active accounts. It deliberately refuses ambiguous repeated matching outputs,
deployment StateInit, changed executed code, incomplete executions and missing
history. It does not prove an Elector accepted a stake, an application completed
its business transition, a returned payment settled, or all liabilities are
reconciled. Those application-specific proofs and original-operation bindings
remain mandatory before a controller can release a financial fence. Multi-hop
pool/service workflows require their additional authenticated edges.

This is not a production election-runner unknown-send fix: durable admission,
sole-producer and reload fencing, application-state confirmation, and continued
validator-duty renewal still need their own integration and actual fault tests.

Upstream comparison: the TOS operator receipt/proven-getter paths are absent
from `ton-c` commit `857b8a57a178e6ae0fe7fa86e7d81c5233de8560`; this command
reuses the existing TOS native verification strategy and modifies no inherited
consensus, VM or cryptographic implementation.
