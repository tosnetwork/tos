from dataclasses import dataclass, field
from pathlib import Path

import nacl.signing
from contract import Provider, WalletV1
from pytosiq_core import Address
from tosapi import tos_api

from .install import Install, run_fift
from .key import Key

NANOTOS_PER_TOS = 1_000_000_000


def _shard_json_repr(shard: int):
    if shard >= (1 << 63):
        return shard - (1 << 64)
    return shard


@dataclass
class SimplexConsensusConfig:
    target_block_rate_ms: int = 400
    slots_per_leader_window: int = 4
    first_block_timeout_ms: int = 1000
    max_leader_window_desync: int = 250
    protocol_version: int = 2
    use_quic: bool = True


@dataclass
class NetworkConfig:
    monitor_min_split: int = 0
    split: int = 0
    global_version: int = 14
    shard_validators: int = 1  # DEV-SPECIFIC: single-validator bootstrap rehearsal
    block_limit_mul: int = 1
    mc_valgroup_lifetime: int = 100000  # DEV: long lifetime for local testnet stability
    mc_consensus: SimplexConsensusConfig | None = field(
        default_factory=SimplexConsensusConfig
    )  # Simplex enabled
    shard_valgroup_lifetime: int = 100000  # DEV: long lifetime for local testnet stability
    shard_consensus: SimplexConsensusConfig | None = field(
        default_factory=SimplexConsensusConfig
    )  # Simplex enabled
    shard_validators_lifetime: int = 100000  # DEV: long lifetime for local testnet
    validator_economics_profile: bool = False
    validator_election_stage_a_profile: bool = False
    # TEST-ONLY: an accelerated validator-election application experiment may
    # need a larger local faucet than the canonical 100,000-TOS validator
    # bootstrap.  None preserves the canonical/default zerostate exactly.
    validator_election_experiment_faucet_balance_nanotos: int | None = None
    # ConfigParam 4: masterchain account id of the .tos DNS root resolver.
    # None (default) leaves the parameter unset so resolvers fail closed; a
    # profile may pin the counterfactual address of a root deployed at runtime.
    dns_root_addr: int | None = None
    # ConfigParam 11 (ConfigVotingSetup): the default carries mainnet-like
    # values (min_store_sec = 1e6 s, min_wins = 2), under which a proposal
    # can never be accepted on a single-validator localnet whose validator
    # set never rotates. A profile opts into a single-round-friendly
    # override (60 s minimum storage, one win) to rehearse governance
    # activation of ordinary parameters.
    enable_config_voting: bool = False


@dataclass
class WorkchainState:
    file: Path
    file_hash: bytes
    root_hash: bytes


@dataclass
class Zerostate:
    masterchain: WorkchainState
    shardchain: WorkchainState
    main_wallet_key: nacl.signing.SigningKey
    main_wallet_address: Address

    def as_block(self):
        return tos_api.TosNode_blockIdExt(
            workchain=-1,
            shard=_shard_json_repr(0x8000_0000_0000_0000),
            seqno=0,
            root_hash=self.masterchain.root_hash,
            file_hash=self.masterchain.file_hash,
        )

    def as_validator_config(self):
        return tos_api.Validator_config_global(zero_state=self.as_block())

    def main_wallet(self, provider: Provider) -> WalletV1:
        return WalletV1(provider, self.main_wallet_address, self.main_wallet_key)


_TEMPLATE = """
"TosUtil.fif" include
"Asm.fif" include
"Lists.fif" include
"FiftExt.fif" include

256 1<<1- 15 / constant AllOnes

wc_master setworkchain
3 setglobalid   // TOS dev global_id

// Initial state of Workchain 0 (Basic workchain)

0 mkemptyShardState

{{ <b x{{a7}} s, 5 roll 32 u, 4 roll 8 u, 3 roll 8 u, rot 8 u, x{{e000}} s,
  3 roll 256 u, rot 256 u, 0 32 u, x{{1}} s, -1 32 i, 0 64 u, x{{0}} s, 20 32 u, 20 32 u, 10 32 u, 1000 32 u, 0 8 u, b>
  dup isWorkchainDescr? not abort"invalid WorkchainDescr created"
  <s swap workchain-dict @ 32 idict!+ 0= abort"cannot add workchain"
  workchain-dict !
}} : add-std-workchain-v2

dup dup 31 boc+>B dup "basestate0.boc" B>file
Bhashu dup =: basestate0_fhash 256 u>B "basestate0.fhash" B>file
hashu dup =: basestate0_rhash 256 u>B "basestate0.rhash" B>file
basestate0_rhash basestate0_fhash now {monitor_min_split} {split} dup 0 add-std-workchain-v2

config.workchains!

// Genesis balances reserved for system contracts, carved out of the fixed
// 5 B TOS total supply. Defined once here and reused at both the
// main-wallet subtraction below and each contract's own register_smc call,
// so the total is correct by construction instead of relying on
// independently-maintained literals staying in sync.
{smc3_genesis_balance} constant smc3_genesis_balance
{elector_genesis_balance} constant elector_genesis_balance
{config_genesis_balance} constant config_genesis_balance

// SmartContract #1 (Simple wallet)

<{{ SETCP0 DUP IFNOTRET // return if recv_internal
   DUP 85143 INT EQUAL IFJMP:<{{ // "seqno" get-method
     DROP c4 PUSHCTR CTOS 32 PLDU  // cnt
   }}>
   INC 32 THROWIF  // fail unless recv_external
   512 INT LDSLICEX DUP 32 PLDU   // sign cs cnt
   c4 PUSHCTR CTOS 32 LDU 256 LDU ENDS  // sign cs cnt cnt' pubk
   s1 s2 XCPU            // sign cs cnt pubk cnt' cnt
   EQUAL 33 THROWIFNOT   // ( seqno mismatch? )
   s2 PUSH HASHSU        // sign cs cnt pubk hash
   s0 s4 s4 XC2PU        // pubk cs cnt hash sign pubk
   CHKSIGNU              // pubk cs cnt ?
   34 THROWIFNOT         // signature mismatch
   ACCEPT
   SWAP 32 LDU NIP 8 LDU LDREF ENDS      // pubk cnt mode msg
   SWAP SENDRAWMSG       // pubk cnt ; ( message sent )
   INC NEWC 32 STU 256 STU ENDC c4 POPCTR
}}>c
// code
<b 0 32 u,
   "main-wallet.pk" load-generate-keypair drop
   B,
b> // data
Libs{{
  x{{ABACABADABACABA}} s>c public_lib
  x{{1234}} x{{5678}} |_ s>c private_lib
}}Libs  // libraries
{main_wallet_genesis_balance}
// balance selected by NetworkConfig (development faucet or validator bootstrap)
0 // split_depth
0 // ticktock
AllOnes 0 * // address
6 // mode: create+setaddr
register_smc
dup make_special dup constant smc1_addr
Masterchain over
2dup ."wallet address = " .addr cr 2dup 6 .Addr cr
"main-wallet.addr" save-address-verbose

// SmartContract #3
PROGRAM{{
  recv_internal x{{}} PROC
  run_ticktock PROC:<{{
    c4 PUSHCTR CTOS 32 LDU 256 LDU ENDS
    NEWC ROT INC 32 STUR OVER 256 STUR ENDC
    c4 POPCTR
    // first 32 bits of persistent data have been increased
    // remaining 256 bits with an address have been fetched
    // create new empty message with 0.1 Tomis to that address
    NEWC b{{00100010011111111}} STSLICECONST TUCK 256 STU
    100000000 INT STTOMIS  // store 0.1 Tomis
    1 4 + 4 + 64 + 32 + 1+ 1+ INT STZEROES ENDC
    // send raw message from Cell
    ZERO SENDRAWMSG
    -17 INT 256 STIR 130000000 INT STTOMIS
    107 INT STZEROES ENDC
    ZERO // another message with 0.13 Tomis to account -17
    NEWC b{{11000100100000}} "test" $>s |+ STSLICECONST
    123456789 INT STTOMIS
    107 INT STZEROES "Hello, world!" $>s STSLICECONST ENDC
    ZERO SENDRAWMSG SENDRAWMSG // external message to address "test"
  }}>
}}END>c
// code
<b x{{11EF55AA}} s, smc1_addr 256 u, b> // data
// empty_cell // libraries
Libs{{
  x{{ABACABADABACABA}} s>c public_lib
  x{{1234}} x{{5678}} |_ s>c public_lib
}}Libs  // libraries
smc3_genesis_balance // balance
0 // split_depth
3 // ticktock: tick
2 // mode: create
register_smc
dup make_special dup constant smc3_addr
."address = " 64x. cr


/*
 *
 * SmartContract #4 (elector)
 *
 */
"auto/elector-code.fif" include   // code in separate source file
<b 0 1 1+ 1+ 4 + 32 + u, 0 256 u, b>  // data: dict dict dict tomis uint32 uint256
empty_cell  // libraries
elector_genesis_balance  // balance
0 // split_depth
2 // ticktock: tick
AllOnes 3 * // address: -1:333...333
6 // mode: create + setaddr
register_smc
dup make_special dup constant smc4_addr dup constant elector_addr
Masterchain swap
."elector smart contract address = " 2dup .addr cr 2dup 7 .Addr cr
"elector" +".addr" save-address-verbose

/*
 *
 * Configuration Parameters
 *
 */
// version capabilities (Native Registry SHA256C requires version 14)
{global_version} capCreateStats capBounceMsgBody or capReportVersion or capShortDequeue or capStoreOutMsgQueueSize or capMsgMetadata or capDeferMessages or config.version!
// ConfigParam 19: global_id (must match setglobalid above)
<b globalid@ 32 i, b> 19 config!
// max-validators max-main-validators min-validators
{max_validators} {max_main_validators} {min_validators} config.validator_num!
// min-stake max-stake min-total-stake max-factor
{min_stake} {max_stake} {min_total_stake} {max_stake_factor} config.validator_stake_limits!
// elected-for elect-start-before elect-end-before stakes-frozen-for
{election_params} config.election_params!
// misbehaviour punishment schedule (ConfigParam 40), matching the canonical
// genesis in crypto/smartcont/gen-zerostate.fif. Contracts that hold pooled
// stake read this parameter to size the own funds a validator must reserve,
// so a local network without it exercises a fallback rather than the real
// guard. Interval tiers scale with the profile's validation round.
{punishment_params} config.punishment_params!
// config-addr = -1:5555...5555
AllOnes 5 * constant config_addr
config_addr config.config_smc!
// elector-addr
elector_addr config.elector_smc!

// 1 sg* 100 sg* 1000 sg* 1000000 sg* config.storage_prices!  // old values (too high)
1 500 1000 500000 config.storage_prices!
config.special!

// gas_price gas_limit special_gas_limit gas_credit block_gas_limit freeze_due_limit delete_due_limit flat_gas_limit flat_gas_price
// DEV-SPECIFIC: cheaper gas for tests (production: 26214400/655360000)
10 sg* 1 *M dup   10000 1000 *M TM$0.1 TM$1.0 100 1000 config.gas_prices!
10 sg* 1 *M 20 *M 10000 1000 *M TM$0.1 TM$1.0 100 1000 config.mc_gas_prices!
// lump_price bit_price cell_price ihr_factor first_frac next_frac
// DEV-SPECIFIC: cheaper forwarding for tests (production: 400000/10000000)
100 10 sg* 10 sg* 3/2 sg*/ 1/3 sg*/ 1/3 sg*/ config.fwd_prices!
100 10 sg* 10 sg* 3/2 sg*/ 1/3 sg*/ 1/3 sg*/ config.mc_fwd_prices!
// mc-cc-lifetime sh-cc-lifetime sh-val-lifetime sh-val-num mc-shuffle
{mc_valgroup_lifetime} {shard_valgroup_lifetime} {shard_validators_lifetime} {shard_validators_per_group} true config.catchain_params!

// round-candidates next-cand-delay-ms consensus-timeout-ms fast-attempts attempt-duration cc-max-deps max-block-size max-collated-size new-cc-ids
// proto-version catchain-max-blocks-coeff
<b x{{d9}} s, 1 8 u, 3 8 u, 2000 32 u, 16000 32 u, 3 32 u, 8 32 u, 4 32 u, 4 *Mi 32 u, 4 *Mi 32 u, 5 16 u, 0 32 u, b>
29 config!
// 3 2000 16000 3 8 4 960 *Mi 960 *Mi true config.consensus_params!

{{ <b x{{5e}} s, 3 roll param_limits, rot param_limits, swap param_limits,
  x{{d3}} s, 200000 32 u, 30 32 u, b>
}} : make-block-limits-v2

// DEV-SPECIFIC: higher gas limits for tests (production: mc=2.5M, base=20M)
128 *Ki 512 *Ki {block_limit_mul} * 1 *Mi {block_limit_mul} * triple  // bytes: underload soft hard
2000000 100000000 100000000 triple  // gas: underload soft hard
1000 500000 1000000 triple        // lt: underload soft hard
triple dup
untriple make-block-limits 22 config!
untriple make-block-limits 23 config!

{masterchain_block_reward} {basechain_block_reward} config.block_create_fees!
// smc1_addr config.collector_smc!
{minter_address} config.minter_smc!

// ConfigParam 4 (dns_root_addr): empty unless the profile pins a DNS root.
// The pinned address may be the counterfactual address of a root deployed at
// runtime; clients fail closed while the account does not exist.
{dns_config_param}


// No genesis extra-currency minting. PoW/test givers are not registered in
// either profile; the validator-economics profile also has no native premine.

// ConfigParam 19 (global_id) is mandatory and critical, as in gen-zerostate.fif:
// every wallet contract fails closed without it.
( 0 1 9 10 12 14 15 16 17 18 19 20 21 22 23 24 25 28 34 ) config.mandatory_params!
( -999 -1000 -1001 0 1 3 4 9 10 12 14 15 16 17 19 32 34 36 ) config.critical_params!

// [ min_tot_rounds max_tot_rounds min_wins max_losses min_store_sec max_store_sec bit_pps cell_pps ]
// first for ordinary proposals, then for critical proposals
_( 2 3 2 2 1000000 10000000 1 500 )
_( 4 7 4 2 5000000 20000000 2 1000 )
config.param_proposals_setup!

// Governance-rehearsal override of ConfigParam 11 (must come AFTER the
// default setup above): min_store_sec drops to 60s and min_wins to 1 so a
// single-validator localnet can carry an ordinary proposal to acceptance
// in one voting round. Empty unless the profile opts in.
{voting_config_param}

// deposit bit_pps cell_pps
TM$100 1 500 config.complaint_prices!

{validators}
now dup {original_vset_valid_for} + {mc_validators} config.validators!

{new_consensus_config}
config.new_consensus_params_all!

{{
  =: data
  <b @' data B, b> <s
    // b{{00000}} // old
    b{{00000000}} // new
}} : collator-entry
{{ -rot dup sbits rot swap [[ <{{ DICTSET }}>s ]] 0 runvmx abort"dict-insert failed" }} : dict-insert

/*
 *
 * SmartContract #5 (Configuration smart contract)
 *
 */
"auto/config-code.fif" include   // code in separate source file
<b configdict ref,  // initial configuration
   0 32 u,          // seqno
   "config-master" +".pk" load-generate-keypair drop
   B,
   dictnew dict,   // vote dict
b> // data
empty_cell  // libraries
config_genesis_balance  // balance
0 1 config_addr 6 register_smc  // tock
dup set_config_smc
Masterchain swap
."config smart contract address = " 2dup .addr cr 2dup 7 .Addr cr
"config-master" +".addr" save-address-verbose
// Other data

/*
 *
 *  Create state
 *
 */

{expected_genesis_supply}
allocated-balance <> abort"unexpected native balance in generated zerostate"
create_state
dup 31 boc+>B dup "zerostate.boc" B>file
Bhashu dup =: zerostate_fhash 256 u>B "zerostate.fhash" B>file
hashu dup =: zerostate_rhash 256 u>B "zerostate.rhash" B>file
"""


def _punishment_params(election_params: str) -> str:
    """ConfigParam 40 arguments scaled to a profile's validation round.

    The base pair is the mildest tier and the multipliers, in 1/256 units,
    scale it up: severity by x2.5 flat and x4 proportional, medium by x4, long
    by x16, so the worst tier lands on TM$2500 plus a quarter of the stake.
    Those values are fixed; the interval thresholds are not, because a
    threshold at or above the round length guards a tier nothing can reach.
    Local profiles run rounds measured in minutes, so the tiers move with them.
    """
    elected_for = int(election_params.split()[0])
    unpunishable = max(1, min(elected_for // 64, 1000))
    medium = max(unpunishable + 1, elected_for // 4)
    long = max(medium + 1, (elected_for * 3) // 4)
    if long >= 1 << 16:
        raise ValueError(
            f"punishment interval {long} does not fit the uint16 field; "
            "the profile's validation round is too long to scale from"
        )
    return (
        "TM$62.5 16777216 640 1024 "
        f"{unpunishable} {long} 4096 4096 {medium} 1024 1024"
    )


def create_zerostate(
    install: Install, state_dir: Path, config: NetworkConfig, validator_keys: list[Key]
) -> Zerostate:
    if (
        config.validator_election_stage_a_profile
        and not config.validator_economics_profile
    ):
        raise ValueError(
            "validator election Stage A profile requires validator economics profile"
        )
    experiment_faucet_balance = (
        config.validator_election_experiment_faucet_balance_nanotos
    )
    if experiment_faucet_balance is not None:
        if not config.validator_election_stage_a_profile:
            raise ValueError(
                "validator election experiment faucet override requires the Stage A profile"
            )
        if (
            isinstance(experiment_faucet_balance, bool)
            or not isinstance(experiment_faucet_balance, int)
            or experiment_faucet_balance <= 0
        ):
            raise ValueError(
                "validator election experiment faucet balance must be positive integer nanotos"
            )
    if config.validator_economics_profile and len(validator_keys) != 4:
        raise ValueError(
            "validator economics profile requires exactly four genesis validators"
        )
    if config.validator_economics_profile and len(
        {key.public_key.key for key in validator_keys}
    ) != len(validator_keys):
        raise ValueError(
            "validator economics profile requires unique genesis validator keys"
        )

    keys: list[str] = []
    for key in validator_keys:
        keys.append(
            f"B{{{key.public_key.key.hex()}}} "
            f"B{{{key.id.hex()}}} 256 B>u@ 17 add-adnl-validator"
        )

    if config.validator_economics_profile:
        profile = {
            "smc3_genesis_balance": "0",
            "elector_genesis_balance": "TM$500",
            "config_genesis_balance": "TM$500",
            "main_wallet_genesis_balance": "TM$100000",
            "expected_genesis_supply": "TM$101000",
            "max_validators": 400,
            "max_main_validators": 100,
            "min_validators": 4,
            "min_stake": "TM$10000",
            "max_stake": "TM$10000000",
            "min_total_stake": "TM$40000",
            "max_stake_factor": "sg~1",
            "election_params": "65536 32768 8192 32768",
            "masterchain_block_reward": "TM$0.569879384",
            "basechain_block_reward": "TM$0.335223167",
            "minter_address": "config_addr",
            "mc_valgroup_lifetime": 250,
            "shard_valgroup_lifetime": 250,
            "shard_validators_lifetime": 1000,
            "shard_validators_per_group": 23,
            "original_vset_valid_for": 131072,
        }
        if config.validator_election_stage_a_profile:
            # TEST-ONLY: preserve all production economics, validator-count,
            # stake, reward, and contract settings while shortening only the
            # election timing and original validator-set lifetime. Never use
            # this profile to generate a production zerostate.
            profile["election_params"] = "300 180 60 180"
            profile["original_vset_valid_for"] = 600
            if experiment_faucet_balance is not None:
                profile["main_wallet_genesis_balance"] = str(
                    experiment_faucet_balance
                )
                profile["expected_genesis_supply"] = str(
                    experiment_faucet_balance + 1_000 * NANOTOS_PER_TOS
                )
    else:
        profile = {
            "smc3_genesis_balance": "TM$1",
            "elector_genesis_balance": "TM$10",
            "config_genesis_balance": "TM$10",
            "main_wallet_genesis_balance": (
                "TM$5000000000 smc3_genesis_balance - "
                "elector_genesis_balance - config_genesis_balance -"
            ),
            "expected_genesis_supply": "TM$5000000000",
            "max_validators": 40,
            "max_main_validators": 20,
            "min_validators": max(
                1, min(len(keys), config.shard_validators)
            ),
            "min_stake": "TM$10000",
            "max_stake": "TM$100000",
            "min_total_stake": "TM$10000",
            "max_stake_factor": "sg~10",
            "election_params": "86400 4000 600 1000",
            "masterchain_block_reward": "TM$1.7",
            "basechain_block_reward": "TM$1",
            "minter_address": "smc1_addr",
            "mc_valgroup_lifetime": config.mc_valgroup_lifetime,
            "shard_valgroup_lifetime": config.shard_valgroup_lifetime,
            "shard_validators_lifetime": config.shard_validators_lifetime,
            "shard_validators_per_group": config.shard_validators,
            "original_vset_valid_for": 3600,
        }

    profile["punishment_params"] = _punishment_params(profile["election_params"])

    new_consensus_config = ""
    for consensus_config in (config.mc_consensus, config.shard_consensus):
        if isinstance(consensus_config, SimplexConsensusConfig):
            new_consensus_config += (
                "dictnew\n"
                f"<b {consensus_config.target_block_rate_ms} 32 u, b> <s 0 rot 8 udict! drop\n"
                f"<b {consensus_config.first_block_timeout_ms} 32 u, b> <s 1 rot 8 udict! drop\n"
                f"<b {consensus_config.max_leader_window_desync} 32 u, b> <s 10 rot 8 udict! drop\n"
                "<b x{22} s, 0 5 u, "
                f"{consensus_config.protocol_version} 2 u, "
                f"{int(consensus_config.use_quic)} 1 u, "
                f"{consensus_config.slots_per_leader_window} 32 u, "
                "swap dict, b>\n"
            )
        else:
            new_consensus_config += "null\n"

    if config.dns_root_addr is not None:
        dns_config_param = f"<b 0x{config.dns_root_addr:064x} 256 u, b> 4 config!\n"
    else:
        dns_config_param = ""

    if config.enable_config_voting:
        # cfg_vote_setup#91 with identical normal/critical ConfigProposalSetup
        # (cfg_prop_setup#36: min_tot_rounds max_tot_rounds min_wins max_losses
        # min_store_sec max_store_sec bit_price cell_price). min_wins = 1 lets
        # a single validator's vote accept an ordinary proposal in one round.
        prop_setup = (
            "<b x{36} s, 1 8 u, 8 8 u, 1 8 u, 8 8 u,"
            " 60 32 u, 31622400 32 u, 1 32 u, 500 32 u, b>"
        )
        voting_config_param = f"<b x{{91}} s, {prop_setup} ref, {prop_setup} ref, b> 11 config!\n"
    else:
        voting_config_param = ""

    run_fift(
        install,
        _TEMPLATE.format(
            monitor_min_split=config.monitor_min_split,
            split=config.split,
            global_version=config.global_version,
            block_limit_mul=config.block_limit_mul,
            validators="\n".join(keys),
            mc_validators=len(keys),
            new_consensus_config=new_consensus_config,
            dns_config_param=dns_config_param,
            voting_config_param=voting_config_param,
            **profile,
        ),
        state_dir,
    )

    pk = (state_dir / "main-wallet.pk").read_bytes()
    addr_file = (state_dir / "main-wallet.addr").read_bytes()
    addr_hash = addr_file[:32]
    addr_wc = int.from_bytes(addr_file[32:36], "big", signed=True)

    return Zerostate(
        masterchain=WorkchainState(
            file=state_dir / "zerostate.boc",
            file_hash=(state_dir / "zerostate.fhash").read_bytes(),
            root_hash=(state_dir / "zerostate.rhash").read_bytes(),
        ),
        shardchain=WorkchainState(
            file=state_dir / "basestate0.boc",
            file_hash=(state_dir / "basestate0.fhash").read_bytes(),
            root_hash=(state_dir / "basestate0.rhash").read_bytes(),
        ),
        main_wallet_key=nacl.signing.SigningKey(pk),
        main_wallet_address=Address((addr_wc, addr_hash)),
    )
