# `tosctl shield` — the shielded pool client

`tosctl shield` holds notes in the shielded pool, receives and sends them
privately through a bonded relayer over Tor, and moves value between the pool
and ordinary accounts. It is a command group of `tosctl`, built with the
`shielded` Cargo feature or installed as the `tosctl-shielded` NixOS package.

The client is **experimental**. It has passed its end-to-end gate on an isolated
local network (global id 3) with an offline Tor stand-in; see
[Evidence and limitations](#evidence-and-limitations). On any other network a
write command prints, before it acts:

```
UNPROVEN OUTSIDE LOCAL NETWORKS: the shielded client has passed its end-to-end
gate on an isolated local network with an offline Tor stand-in; real Tor
circuits and public networks are unexercised
```

The pool contract and its profile are specified in
`artifacts/shielded-pool/PROFILE.md`; the relayer protocol in
[bonded-relayer-v1.md](bonded-relayer-v1.md) and
[br1-tor-transport.md](br1-tor-transport.md). This manual covers the client.

## What the client hides, and what it does not

A private transfer has four links an observer could follow. The client cuts
each as follows.

| Link | Who could learn it | What the client does |
| --- | --- | --- |
| The account that pays for a transfer | anyone reading the chain | a relayed `send` is funded and broadcast by the relayer's account; no wallet of yours signs anything. You pay the relayer with one private output of the same spend (output slot 2). |
| Where a request comes from | the relayer, observers | the relayer is reached only as a v3 onion service through a local Tor daemon's SOCKS port, with fresh isolation credentials per transfer and no DNS. There is no direct fallback: when Tor is unavailable the command fails. |
| Which notes you are looking for | the RPC endpoint you read from | `sync` replays the whole pool history and trial-decrypts locally, so a read never names a note. A relayed `send` additionally requires every chain read to stay on loopback (your own node) and to be authenticated by the proof verifier. |
| Patterns in amounts and shapes | anyone | the pool has fixed denominations (1, 10, 100, 1000 TOS); every spend has two inputs and three outputs, padded with dummy outputs that carry real encryptions. |

Two operations are public by construction and the client says so each time:

- `deposit` is sent from one of your configured wallets. The chain shows that
  wallet, the pool and the amount together.
- `withdraw` pays an ordinary address from the pool and is broadcast by one of
  your configured wallets. The chain shows that wallet, the pool, the recipient
  and the time together. Use a fresh funded account for it.

`send --direct` broadcasts a private transfer from your own wallet. It exists for
isolated local networks and tests only and is refused elsewhere; it is never a
fallback for a failed relayed send.

What the client does not do:

- it does not hide timing. Amounts and the moment of a transfer are visible to
  the relayer and, through the chain, to everyone; choose both deliberately;
- it does not make a lying RPC endpoint harmless. Without the proof verifier a
  read is unauthenticated; the `--unverified-rpc` mode marks such a state and
  spends refuse it;
- the offline evidence proves transport boundaries (which addresses the client
  connects to, what it refuses) and not anonymity on the real Tor network.

## Prerequisites

1. **A `tosctl` configuration** with a JSON-RPC endpoint and at least one funded
   wallet (`tosctl wallet create`, `tosctl wallet activate`). The configured
   wallet pays deposits, broadcasts withdrawals and, on a local network, direct
   sends. Instances live beside the configuration file (see
   [State and journal](#state-and-journal)), so keep that directory private
   (`0700`); the client refuses a directory with group-writable ancestors.

2. **The proof verifier**, configured in the `proof_verifier` section of the
   configuration: the `tos-proof-verify` executable, an `anchor_file` made from
   an independently obtained zerostate, and exactly one of `liteserver_config`
   (live reads) or `material_dir` (recorded material). `live_state_file` and
   `live_max_age_seconds` bound live reads; `timeout_seconds` and
   `min_interval_ms` bound the verifier's calls. A relayed `send` requires this
   section; `sync` and `deposit` use it when present and accept
   `--unverified-rpc` for isolated local testing only.

3. **A Tor client** for `send --relayer` and `status`: SOCKS on
   `127.0.0.1:9050` (or the port named by `--tor-port`) with `IsolateSOCKSAuth`,
   onion traffic only, no control port. `assembly/nix/tosctl/tor-client.nix` is
   that configuration for NixOS; an equivalent `torrc` serves elsewhere. The
   client sends its own isolation credentials on every connection and refuses
   any endpoint that is not an onion address.

4. **The proving material**: the finished phase-2 ceremony directory and the
   phase-1 slice it started from, named by `--ceremony-dir` and `--phase1-dir`
   or by the environment variables `TOSCTL_SHIELD_CEREMONY_DIR` and
   `TOSCTL_SHIELD_PHASE1_DIR`. The NixOS package ships both and defaults the
   variables to them; an explicit flag or variable always wins, and an empty
   variable names nothing.

## Profiles and pinning

The client never takes a pool or a relayer from a free endpoint. Both come from
small JSON files it checks.

**Pool profile** (`tosctl-shield-profile-v1`): `global_id`, `pool_address`,
`pool_code_hash`. `init` binds an instance to one profile for good. The global
id names the network:

| Global id | Network | Rule |
| --- | --- | --- |
| 3 | isolated local network | allowed; the network the evidence was gathered on |
| 2 | public testnet | allowed only with `--allow-testnet-pool`; the pool is reset without notice, so no real value belongs there |
| 1 | main network | refused; the pool has no live go there |

On every read the client holds the pool's code and configuration to the
profile's pins and to the pins compiled into it: the profile revision
(`KNOWN_PROFILE_HASHES`), the audited verifying key (`KNOWN_VERIFYING_KEYS`)
and, outside local networks, the known pool code hashes (`KNOWN_CODE_HASHES`).
A mismatch is a refusal, not a warning.

**Relayer profile** (`tos.shield.relayer-profile.v1`): the relayer's `release`
pins (`global_id`, genesis root and file, `bond`, `bond_code_hash`,
`policy_hash`, `worker_key_hash`, the pool and its code and configuration
hashes) and `bond_init_b64`, the Bond's StateInit. The relayer's onion endpoint
is read only from the authenticated Bond; a profile whose endpoint is not a v3
onion address, or that names a loopback or IP address, is refused before any
connection is attempted. The release's pool pins must be the instance's pool.

## Commands

Every command takes `-c/--config <path>` (or `CONFIG_PATH`) and, except
`audit-ceremony`, `-n/--name <instance>`. Write commands ask for confirmation
unless `-y/--yes` is given.

| Command | What it does | Chain write | Signer |
| --- | --- | --- | --- |
| `init --name N --profile FILE --mnemonic-fd 0` (or `--mnemonic-file`) | creates an instance for one pool from a mnemonic; the seed is kept as the Vault secret `shield-N`; nothing secret is written in clear | no | — |
| `sync --name N` | replays the pool's history from a verified head, rebuilds the commitment and nullifier trees, imports this instance's notes and reconciles spent ones | no | — |
| `balance --name N [--notes]` | the spendable balance; with `--notes`, every note with its amount, leaf index, kind (ordinary, dummy, recovery) and whether it is spent | no | — |
| `address --name N` | issues a receiving descriptor at the next unused key index; the last line of the output is the descriptor | no | — |
| `deposit --name N --amount D --from WALLET` | pays a denomination plus the pool's deposit fee from a configured wallet into a new note | yes | your wallet |
| `withdraw --name N --amount D --to ADDRESS --from WALLET` | spends notes to pay a denomination to a workchain-0 address; the pool's withdrawal fee comes from the notes on top | yes | your wallet |
| `send --name N --amount X --to DESCRIPTOR --relayer FILE` | plans, proves and submits a private transfer through the relayer over Tor | yes | the relayer |
| `send --name N --amount X --to DESCRIPTOR --direct --from WALLET` | the same transfer broadcast from your wallet; isolated local networks only | yes | your wallet |
| `status --name N --relayer FILE [--request ID]` | what the chain and the relayer say about relayed spends; never resubmits | no | — |
| `audit-ceremony` | audits the proving material without a chain or an instance | no | — |

Amounts are given in TOS (`--amount 10`) or nanotos (`--amount-nanotos`).
Deposits and withdrawals must be exactly one denomination.

Refusals you will meet, each deliberate:

- a second command on the same instance while one runs: `the ... lock is held
  by another shield command`;
- a spend before the state is verified: run `sync` first, or the client reports
  that the state was built on an RPC endpoint's word;
- `--unverified-rpc` on a relayed send, a wrong profile schema, a tampered or
  missing proving key, a relayer profile whose Bond is not active or whose
  pins do not match the instance's pool, a quote that is wrong in any term
  (scope, slot, lifetime, clock window), a quote window too close to its end
  (`RELAY_DEADLINE_MARGIN_SECS`, 60 s), a non-onion or loopback relayer
  endpoint, Tor unavailable.

## Proving material and `audit-ceremony`

Every spend proves itself with the proving key of the finished phase-2
ceremony, and before it does, audits the ceremony's whole transcript: it
rebuilds the ceremony's starting key from the phase-1 slice, replays every
contribution and derives the verifying key, which must be the one the client
pins. There is no audit cache; the audit runs in full on every spend, and the
key actually loaded is always rehashed. On two cores it takes about three
minutes and peaks near 150 MiB.

`audit-ceremony` runs the same audit alone and prints the slice, starting-key,
proving-key and pinned verifying-key digests with the time it took. Run it
after installing or changing material. It proves the artifacts; whether a pool
on a given network verifies against that key is read from a verified head at
spend time.

## A relayed send, step by step

1. The instance is opened, its network gated, the proof verifier required and
   every chain read confined to loopback. The relayer profile is validated and
   its endpoint parsed before anything is read.
2. The pool and the Bond are read from a verified head: the Bond must be
   active and backed, its pins must match the profile and the instance's pool.
3. Proving material is audited (above).
4. A quote is requested over Tor (`POST /v1/quote`) under fresh isolation
   credentials, asking for `--quote-lifetime` seconds (default 300). Every
   term is checked: scope, quote identity, status-token hash, fee output in
   slot 2, lifetime, clock window.
5. The spend is planned from up to two input notes: the recipient's note,
   your change and the relayer's fee note at the quoted index and amount, with
   checked arithmetic. The plan is shown (`Inputs:`, `Change:`, `Pool fee:`)
   and confirmed unless `--yes`.
6. The intent is signed with the per-note keys, proved and self-verified; the
   exact body, the request and the input reservations are written to the
   journal and synced to disk **before** the request leaves the machine.
7. `POST /v1/submit`. On success the command prints
   `OK request <id> submitted; the relayer claims it is <status>`.
8. The spend counts as settled only when your own `sync` shows both input
   nullifiers published and the output notes in the tree.

If the submit response never arrives, nothing is sent again. The journal
records the request as unknown and the command reports
`the submission of request <id> returned no acknowledgement`. `status` then
asks the relayer and reads the chain; it reconciles, it does not resubmit.
This is the one case where you must run `status` (and `sync`) before deciding
what happened.

`status` prints, per request: `Request <id>`, the intent, what the chain
shows, what the journal recorded, and what the relayer claims (with the
message hash when it has one). Every exchange with the relayer, for `send`
and `status` alike, is bounded by `--relay-timeout` (default 60 s).

## Direct withdrawal and direct send

`withdraw` builds the same two-input, three-output spend with a public payout
and broadcasts it from the wallet named by `--from`. The payout is bounceable:
if the recipient cannot accept it (an uninitialised address, for example) the
value bounces back to the pool, which mints a **recovery note** to the sender
for the bounced value minus the pool's recovery charge (the `recovery_charge`
getter; no note when the value does not exceed the charge). The next `sync`
imports it as a note of kind `recovery`, spendable like any other. The
withdrawal itself already consumed the index the recovery note would use;
`balance --notes` lists that as a `recovery` row of 0 TOS with no leaf (the
template the withdrawal signed), and the minted note, when it comes, appears
at the same index with its leaf and value.

`send --direct --from WALLET` is accepted only when the instance is on an
isolated local network. It never runs when a relayed send fails.

## State and journal

An instance lives beside the configuration file:

```
<config dir>/shield/<name>.json            the pointer: profile, binding, instance id
<config dir>/shield/<16 hex bytes>/state   the sealed state
<config dir>/shield/<16 hex bytes>/journal the sealed journal, append-only
<config dir>/shield/<16 hex bytes>/lock    the instance lock
```

The directory name is half the instance id and reveals nothing about the
instance. State and journal are encrypted with a key derived from the seed
under a domain-separated context that binds the instance, its network and its
pool; a state of another version or bound elsewhere is refused. The seed is the
Vault secret `shield-<name>` and is loaded per command.

Durability rules the client keeps, and which a backup must respect:

- a descriptor's key index is persisted before the descriptor is shown;
  the same for change, dummy and recovery indices;
- the status token is persisted before a quote is requested; the exact body,
  request and input reservations before a submit;
- the journal is appended and synced before each chain write or relayer
  request leaves the machine, and is never rewritten;
- two commands on one instance are refused by the lock.

Back up the whole `shield` directory together with the Vault, and restore the
two files of an instance together. Never restore an older copy of the state
over a newer journal: the journal holds requests and reservations the older
state does not know, and a descriptor or an input could be reused.

## The NixOS package

`nix build --no-update-lock-file .#tosctl-shielded` builds `tosctl` with the
feature and the material as its own store path, held to `material.sha256`. The
installed `tosctl` is wrapped to default `TOSCTL_SHIELD_CEREMONY_DIR` and
`TOSCTL_SHIELD_PHASE1_DIR` to the shipped material, so `tosctl shield
audit-ceremony` works at once and your own flag or variable still wins.
`assembly/nix/tosctl/tor-client.nix` is the Tor client the relayed commands
expect; importing it is the operator's decision. The flake's
`tosctl-shielded-vm` check boots that configuration offline and runs the
package's acceptance runner, including the Tor and SOCKS properties.
[assembly/nix/tosctl/README.md](../assembly/nix/tosctl/README.md) describes
the package, its input checks and the VM check.

## Evidence and limitations

The end-to-end gate ran on an isolated local network of global id 3 with the
pool built around the audited ceremony verifying key, a bonded relayer
operator reached through an offline Tor stand-in (a SOCKS5 peer that admits
one onion name and records every connection), and `strace`-captured
connection traces of the client as independent evidence of where it connected.
It covered deposit, sync, a relayed send with two inputs and the relayer's fee
import, a withdrawal that bounced and minted a recovery note, spending that
note, a public withdrawal, and an ambiguous submission whose response was
dropped and which `status` reconciled without resubmission, each with a red
control (tampered profile, concurrent lock, loopback Bond endpoint, wrong onion
name, direct bypass of the proxy, Tor unavailable). The run's evidence index,
`test/shielded-pool/evidence/shield-local-e2e-20261103.json`, names the
binary under test by digest, every receipt by hash and the retention root of
the raw material, which stays outside Git with its retention record; the
driver and its controls are `test/shielded-pool/localnet/`, and
`localnet/evidence.py` checks an index, recomputing the receipt digests when
the retention root is present.

What that evidence does not establish:

- anonymity on the real Tor network: the stand-in proves which addresses the
  client connects to and what it refuses, not circuit behaviour or traffic
  analysis resistance;
- the public testnet: its pool is gated behind `--allow-testnet-pool` and may
  be reset at any time; no public network has been exercised;
- the main network: there is no profile for it and the client refuses global
  id 1;
- `--unverified-rpc` is a trusted-source mode for isolated testing only. It
  authenticates nothing, and spends refuse a state built with it.

The clap description keeps the mark `(experimental)` until these are closed.
