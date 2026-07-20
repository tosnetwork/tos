# Workflow Example: Planner, Worker, Service and Verifier Actors

This walks through one realistic AI-agent workflow using only actors and `tosctl` commands
that already exist in this repository, composing:

- a **planner** actor that funds and posts a Task Escrow (any Agent Account or wallet acting
  as `creator`; see [`doc/agent-wallet-mvp.md`](agent-wallet-mvp.md))
- a **worker** actor (an Agent Account) that discovers, accepts, and completes the task
- a **service** actor it pays for a paid capability mid-task (a Service Actor)
- a **verifier** actor that settles the happy path, and a **reviewer** actor that resolves a
  contested one (a Dispute contract)

Every hash field below follows [`doc/ai-workflow-schemas.md`](ai-workflow-schemas.md); every
command is documented in full elsewhere (`doc/agent-wallet-mvp.md` for Agent
Account/Wallet/Task Escrow, and the Capability Registry / Service Actor / Dispute sections of
`ROADMAP.md`'s Phase 3/4 entries for the newer contracts) -- this document only shows how
they compose into one workflow, and is a documentation example, not a new contract or a new
automated test (each contract's own lifecycle is already covered by its dedicated
`scripts/*-e2e.py` real-localnet acceptance script).

## 0. Actors in this example

| Role | Concrete actor | Wallet/profile |
|---|---|---|
| planner | funding wallet | `planner` |
| worker | Agent Account | `research-agent` (Agent Wallet profile) |
| service | Service Actor | deployed by `model-provider` |
| verifier | Task Escrow verifier | `verifier` wallet |
| reviewer | Dispute reviewer | `reviewer` wallet |

## 1. The worker discovers a service through the Capability Registry

A model provider registers what it offers and where to call it:

```bash
tosctl agent registry deploy --name model-provider-registry \
  --owner "0:<model-provider-account-id>" \
  --task-categories-hash <64-hex, TaskCategoriesBundle: ["research"]> \
  --pricing-hash <64-hex, PricingBundle: 0.05 TOS/call> \
  --metadata-hash <64-hex, AgentCapabilityMetadataBundle> \
  --verification-method-hash <64-hex, VerificationMethodBundle: "ed25519_signature"> \
  --bond 5 --from model-provider --amount 5.2 -w -1 --yes
```

The worker (or its off-chain planner) looks this up before committing to a task:

```bash
tosctl agent registry show --name model-provider-registry --format json
```

## 2. The model provider deploys the callable Service Actor

The registry entry above is a capability *advertisement*; the Service Actor is the callable
endpoint that actually takes payment per call:

```bash
tosctl agent service deploy --name model-provider-service \
  --owner "0:<model-provider-account-id>" --open-access \
  --price-per-call 0.05 --rate-limit-per-day 1000 \
  --metadata-hash <64-hex, same AgentCapabilityMetadataBundle as above> \
  --proof-scheme-hash <64-hex, same VerificationMethodBundle as above> \
  --from model-provider --amount 0.3 -w -1 --yes
```

## 3. The planner posts a Task Escrow

```bash
tosctl agent task create --name literature-review \
  --creator "0:<planner-account-id>" --agent "0:<research-agent-account-id>" \
  --verifier "0:<verifier-account-id>" \
  --budget 5 --deadline 1790000000 --review-period 86400 \
  --policy-hash <64-hex-settlement-policy-hash> \
  --from planner --amount 5.2 -w 0 --yes
```

## 4. The worker accepts, calls the paid service mid-task, and submits a result

The worker's Agent Account accepts the task through its controller-signed path (see
`doc/agent-wallet-mvp.md`'s Task Escrow section):

```bash
tosctl agent task send --operation accept --name literature-review \
  --via-agent-account research-agent --amount 0.01 --yes
```

While doing the work, the worker pays the Service Actor for a model call:

```bash
tosctl agent service send --operation call --name model-provider-service \
  --from research-agent-owner-wallet \
  --request-hash <64-hex, ServiceCallRequestBundle> --amount 0.05 --yes
```

The model provider commits its response:

```bash
tosctl agent service send --operation respond --name model-provider-service \
  --from model-provider --response-hash <64-hex, ServiceCallResponseBundle> --yes
```

If the service was deployed with `--attestor-pubkey` or `--signer-vault-key`, `respond`
additionally requires a signature over `response_hash` (`--attestation-signature` or
`--signer-vault-key` on `send`), verified inline by the Service Actor itself.

The worker then submits the task result, with `evidence_hash` referencing a
`TaskEvidenceBundle` whose `steps` array includes this `service_call` (see
`doc/ai-workflow-schemas.md`):

```bash
tosctl agent task send --operation result --name literature-review \
  --via-agent-account research-agent --amount 0.01 \
  --result-hash <64-hex, TaskResultBundle> \
  --evidence-hash <64-hex, TaskEvidenceBundle> --yes
```

## 5a. Happy path: the verifier settles

```bash
tosctl agent task send --operation settle --name literature-review \
  --from verifier --payout 5 --yes
```

If the task was deployed with `--attestor-pubkey` or `--signer-vault-key` (see
`tosctl agent task create --help`), `settle` additionally requires a valid ed25519
signature over the on-chain `result_hash`, verified inline by Task Escrow itself
(`--attestation-signature <hex>` or `--signer-vault-key <name>` on `send`) -- on top
of, never instead of, the creator/verifier authorization above.

## 5b. Contested path: the planner disputes, a reviewer resolves

If the planner rejects the submitted result instead of letting it settle, it opens a
Dispute case referencing the Task Escrow as the disputed subject:

```bash
tosctl agent task send --operation dispute --name literature-review \
  --from planner --dispute-hash <64-hex, DisputeEvidenceBundle> --yes

tosctl agent dispute deploy --name literature-review-dispute \
  --claimant "0:<planner-account-id>" --respondent "0:<research-agent-account-id>" \
  --reviewer "0:<reviewer-account-id>" --deadline 1790086400 \
  --subject-hash <64-hex-hash-of-the-task-escrow-address> \
  --claimant-evidence-hash <64-hex, DisputeEvidenceBundle, submitted_by: "claimant"> \
  --from planner --amount 0.1 -w -1 --yes
```

The worker responds with its own evidence bundle:

```bash
tosctl agent dispute send --operation submit-respondent-evidence \
  --name literature-review-dispute --from research-agent-owner-wallet \
  --respondent-evidence-hash <64-hex, DisputeEvidenceBundle, submitted_by: "respondent"> --yes
```

The reviewer rules (here, a 65/35 split in the worker's favor), publishing a
`DisputeRulingBundle` alongside the typed on-chain ruling:

```bash
tosctl agent dispute send --operation rule --name literature-review-dispute \
  --from reviewer --ruling split --split-bps 6500 \
  --ruling-hash <64-hex, DisputeRulingBundle> --yes
```

If the dispute was deployed with `--attestor-pubkey` or `--signer-vault-key`, `rule`
additionally requires a signature over `ruling_hash` (`--attestation-signature` or
`--signer-vault-key` on `send`), verified inline by the Dispute contract itself.

The Dispute contract is a pure adjudication ledger (see
[`crypto/smartcont/dispute-code.fc`](../crypto/smartcont/dispute-code.fc)): it records the
ruling but does not move funds itself. The verifier (or the Task Escrow's existing verifier
role, per `doc/agent-wallet-mvp.md`'s Task Escrow section) still has to execute the payout
that matches the ruling:

```bash
tosctl agent task send --operation resolve --name literature-review \
  --from verifier --payout 3.25 --yes
```

`3.25` here is `5 * 6500 / 10000` -- the reviewer's ruling and the actual on-chain settlement
are two separate steps by design (dispute adjudication vs. task-specific fund custody), so
the party executing the payout is responsible for translating `split_bps` into the correct
`--payout` amount for that specific task's budget.

## What this example does not cover

- Automating the `split_bps -> --payout` translation on-chain (would require Task Escrow to
  call out to a Dispute contract's ruling directly, which does not exist yet -- see
  `ROADMAP.md` Phase 4's still-open proof-adapter-interface item).
- A chain-wide way to discover Task Escrows, Capability Registry entries or Service Actors
  without already knowing their address or local `tosctl` record name (see the "not a
  chain-wide index" notes in `ROADMAP.md` Phase 2/3).
