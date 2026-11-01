//! Pure checks of the native account read that makes the engine load each monitored shard
//! state. The honest answers have the engine's shape: a header proof that visits the block
//! info and state update, a state proof that visits the accounts dictionary path of the
//! address (so a present account's cell stays pruned), and a pruned account body. Each
//! refusal case changes exactly one property of an otherwise valid answer, so the check named
//! in its message is the one that refuses.
use super::*;
use chain_block::{
    Account, AccountId as Address, BlockInfo, Cell, CurrencyCollection, MerkleUpdate,
    MsgAddressInt, ShardAccount, ShardIdent, UsageTree, write_boc, write_boc_multi,
};
use tos::lite_server::{AccountState, accountid::AccountId, accountstate};

const GLOBAL_ID: i32 = 3;
const SEQ_NO: u32 = 12;

fn held() -> Network {
    let zero = FullId {
        workchain: -1,
        shard: i64::MIN,
        seqno: 0,
        root_hash: "10".repeat(32),
        file_hash: "11".repeat(32),
    };
    Network { global_id: GLOBAL_ID, zero: zero.clone(), init: zero }
}

fn basechain() -> Result<ShardIdent> {
    ShardIdent::with_tagged_prefix(0, 0x8000_0000_0000_0000)
}

/// The address the caller reads in `shard`: the shard prefix followed by zeros.
fn queried(shard: &ShardIdent) -> [u8; 32] {
    let mut address = [0; 32];
    address[..8].copy_from_slice(&shard.shard_prefix_without_tag().to_be_bytes());
    address
}

/// Another address in `shard`, so the accounts dictionary is never empty by accident.
fn neighbour(shard: &ShardIdent, last: u8) -> [u8; 32] {
    let mut address = queried(shard);
    address[31] = last;
    address
}

fn account(workchain: i32, address: [u8; 32], coins: u64) -> Result<Account> {
    let workchain = i8::try_from(workchain)?;
    let address =
        MsgAddressInt::with_standart(None, workchain, Address::from(UInt256::from(address)))?;
    Ok(Account::with_address_and_ballance(&address, &CurrencyCollection::with_coins(coins)))
}

/// A state of `shard` at `seq_no` holding `(address, coins)` accounts.
fn state(
    global_id: i32,
    shard: &ShardIdent,
    seq_no: u32,
    accounts: &[([u8; 32], u64)],
) -> Result<Cell> {
    let mut state = ShardStateUnsplit::with_ident(shard.clone());
    state.set_global_id(global_id);
    state.set_seq_no(seq_no);
    state.set_gen_time(2000);
    for &(address, coins) in accounts {
        let entry = ShardAccount::with_params(
            &account(shard.workchain_id(), address, coins)?,
            UInt256::default(),
            0,
        )?;
        state.insert_account(&Address::from(UInt256::from(address)), &entry)?;
    }
    state.serialize()
}

/// A block of `shard` at `seq_no` (header salted by `salt`) recording `state`.
fn block(shard: &ShardIdent, seq_no: u32, salt: u32, state: &Cell) -> Result<(Cell, BlockIdExt)> {
    let mut info = BlockInfo::default();
    info.set_shard(shard.clone());
    info.set_seq_no(seq_no)?;
    info.set_gen_utime(1000 + salt);
    let update = MerkleUpdate::create(state, state)?;
    let block =
        Block::with_params(GLOBAL_ID, info, Default::default(), update, Default::default())?;
    let cell = block.serialize()?;
    let file_hash =
        UInt256::from(<[u8; 32]>::try_from(hex::decode(sha256(&write_boc(&cell)?))?.as_slice())?);
    let id = BlockIdExt::with_params(shard.clone(), seq_no, cell.repr_hash(), file_hash);
    Ok((cell, id))
}

struct Read {
    held: Network,
    shard: ShardIdent,
    address: [u8; 32],
    state: Cell,
    block: Cell,
    id: BlockIdExt,
}

/// An honest block of `shard`; with `present`, the queried address holds an account.
fn read(shard: ShardIdent, present: bool) -> Result<Read> {
    let address = queried(&shard);
    let mut accounts = vec![(neighbour(&shard, 7), 70), (neighbour(&shard, 9), 90)];
    if present {
        accounts.push((address, 1000));
    }
    let state = state(GLOBAL_ID, &shard, SEQ_NO, &accounts)?;
    let (block, id) = block(&shard, SEQ_NO, 0, &state)?;
    Ok(Read { held: held(), shard, address, state, block, id })
}

/// The engine's header proof: the block info and the state update, the rest pruned.
fn header_proof(block: &Cell) -> Result<Cell> {
    let usage = UsageTree::with_root(block.clone());
    let visited = Block::construct_from_cell(usage.root_cell())?;
    visited.read_info()?;
    visited.read_state_update()?;
    MerkleProof::create_by_usage_tree(block, &usage)?.serialize()
}

/// The engine's state proof: the header and the dictionary path of `address`.
fn state_proof(state: &Cell, address: [u8; 32]) -> Result<Cell> {
    let usage = UsageTree::with_root(state.clone());
    ShardStateUnsplit::construct_from_cell(usage.root_cell())?
        .read_accounts()?
        .account(&Address::from(UInt256::from(address)))?;
    MerkleProof::create_by_usage_tree(state, &usage)?.serialize()
}

/// The engine's pruned body of the account at `address` in `state`, empty when absent.
fn body(state: &Cell, address: [u8; 32]) -> Result<Vec<u8>> {
    let entry = ShardStateUnsplit::construct_from_cell(state.clone())?
        .read_accounts()?
        .account(&Address::from(UInt256::from(address)))?;
    let Some(entry) = entry else {
        return Ok(Vec::new());
    };
    let account = entry.account_cell();
    let usage = UsageTree::with_root(account.clone());
    Account::construct_from_cell(usage.root_cell())?;
    MerkleProof::create_by_usage_tree(&account, &usage)?.write_to_bytes()
}

fn wrap(id: &BlockIdExt, shardblk: &BlockIdExt, proof: Vec<u8>, state: Vec<u8>) -> AccountState {
    AccountState::LiteServer_AccountState(accountstate::AccountState {
        id: id.clone(),
        shardblk: shardblk.clone(),
        shard_proof: Vec::new(),
        proof,
        state,
    })
}

fn honest(r: &Read) -> Result<AccountState> {
    let proof = write_boc_multi(vec![header_proof(&r.block)?, state_proof(&r.state, r.address)?])?;
    Ok(wrap(&r.id, &r.id, proof, body(&r.state, r.address)?))
}

/// `honest`, with its `proof` and `state` fields replaced.
fn with_parts(r: &Read, proof: Vec<u8>, state: Vec<u8>) -> AccountState {
    wrap(&r.id, &r.id, proof, state)
}

fn request(r: &Read) -> AccountId {
    AccountId { workchain: r.shard.workchain_id(), id: r.address.into() }
}

fn verify(r: &Read, answer: &AccountState) -> Result<()> {
    verify_account_read(&r.held, &r.id, &request(r), answer)
}

fn refused(result: Result<()>, expected: &str) {
    match result {
        Ok(()) => panic!("accepted; expected refusal containing {expected:?}"),
        Err(error) => {
            let text = format!("{error:#}");
            assert!(text.contains(expected), "refused for another reason: {text}");
        }
    }
}

fn parts(answer: &AccountState) -> (Vec<u8>, Vec<u8>) {
    let AccountState::LiteServer_AccountState(answer) = answer;
    (answer.proof.clone(), answer.state.clone())
}

// ===== accepted =====

#[test]
fn masterchain_block_with_the_account_absent_is_accepted() -> Result<()> {
    let r = read(ShardIdent::masterchain(), false)?;
    verify(&r, &honest(&r)?)
}

#[test]
fn masterchain_block_with_the_account_present_is_accepted() -> Result<()> {
    let r = read(ShardIdent::masterchain(), true)?;
    verify(&r, &honest(&r)?)
}

#[test]
fn shard_block_with_the_account_absent_is_accepted() -> Result<()> {
    let r = read(basechain()?, false)?;
    verify(&r, &honest(&r)?)
}

/// The present account's cell is a pruned branch in the state proof, so the body is compared
/// with the hash the pruned branch records for the original cell, not with its own hash.
#[test]
fn shard_block_with_the_account_present_and_its_cell_pruned_is_accepted() -> Result<()> {
    let r = read(basechain()?, true)?;
    let answer = honest(&r)?;
    let (proof, _) = parts(&answer);
    let roots = read_boc(&proof)?.roots;
    let state: ShardStateUnsplit =
        MerkleProof::construct_from_cell(roots[1].clone())?.virtualize()?;
    let entry = state
        .read_accounts()?
        .account(&Address::from(UInt256::from(r.address)))?
        .context("present account")?;
    assert!(entry.account_cell().is_pruned(), "the engine's proof prunes the account cell");
    verify(&r, &answer)
}

/// A state proof that also visits the account cell leaves it unpruned (level 0); the body is
/// then compared with that cell's own hash, and the answer is accepted the same way.
#[test]
fn shard_block_with_the_account_present_and_its_cell_unpruned_is_accepted() -> Result<()> {
    let r = read(basechain()?, true)?;
    let usage = UsageTree::with_root(r.state.clone());
    ShardStateUnsplit::construct_from_cell(usage.root_cell())?
        .read_accounts()?
        .account(&Address::from(UInt256::from(r.address)))?
        .context("present account")?
        .read_account()?;
    let full_path = MerkleProof::create_by_usage_tree(&r.state, &usage)?.serialize()?;
    let proof = write_boc_multi(vec![header_proof(&r.block)?, full_path.clone()])?;
    let state: ShardStateUnsplit = MerkleProof::construct_from_cell(full_path)?.virtualize()?;
    let entry = state
        .read_accounts()?
        .account(&Address::from(UInt256::from(r.address)))?
        .context("present account")?;
    assert!(!entry.account_cell().is_pruned(), "this proof keeps the account cell");
    assert_eq!(entry.account_cell().level(), 0, "an unpruned account cell has level 0");
    verify(&r, &with_parts(&r, proof, body(&r.state, r.address)?))
}

#[test]
fn a_state_with_no_accounts_proves_absence() -> Result<()> {
    let shard = basechain()?;
    let state = state(GLOBAL_ID, &shard, SEQ_NO, &[])?;
    let (block, id) = block(&shard, SEQ_NO, 0, &state)?;
    let r = Read { held: held(), address: queried(&shard), shard, state, block, id };
    verify(&r, &honest(&r)?)
}

// ===== the request and the answer's block =====

#[test]
fn an_account_of_another_workchain_is_refused() -> Result<()> {
    let r = read(basechain()?, false)?;
    let account = AccountId { workchain: 1, id: r.address.into() };
    refused(
        verify_account_read(&r.held, &r.id, &account, &honest(&r)?),
        "account read names another workchain than its shard block",
    );
    Ok(())
}

#[test]
fn an_address_outside_the_shard_is_refused() -> Result<()> {
    // The left half of the basechain holds addresses whose first bit is 0.
    let shard = ShardIdent::with_tagged_prefix(0, 0x4000_0000_0000_0000)?;
    let r = read(shard, false)?;
    let mut outside = r.address;
    outside[0] |= 0x80;
    let account = AccountId { workchain: 0, id: outside.into() };
    refused(
        verify_account_read(&r.held, &r.id, &account, &honest(&r)?),
        "account read names an address outside its shard block",
    );
    Ok(())
}

#[test]
fn an_answer_for_another_block_is_refused() -> Result<()> {
    let r = read(basechain()?, false)?;
    let (_, other) = block(&r.shard, SEQ_NO, 1, &r.state)?;
    let (proof, state) = parts(&honest(&r)?);
    refused(
        verify(&r, &wrap(&other, &r.id, proof, state)),
        "account read answered for another block",
    );
    Ok(())
}

#[test]
fn an_answer_from_another_shard_state_is_refused() -> Result<()> {
    let r = read(basechain()?, false)?;
    let (_, other) = block(&r.shard, SEQ_NO, 1, &r.state)?;
    let (proof, state) = parts(&honest(&r)?);
    refused(
        verify(&r, &wrap(&r.id, &other, proof, state)),
        "native account read used a different shard state",
    );
    Ok(())
}

#[test]
fn a_shard_proof_is_refused() -> Result<()> {
    let r = read(basechain()?, false)?;
    let AccountState::LiteServer_AccountState(mut answer) = honest(&r)?;
    answer.shard_proof = write_boc(&header_proof(&r.block)?)?;
    refused(
        verify(&r, &AccountState::LiteServer_AccountState(answer)),
        "account read carries an unexpected shard proof",
    );
    Ok(())
}

// ===== the proof's shape =====

#[test]
fn an_empty_proof_is_refused() -> Result<()> {
    let r = read(basechain()?, false)?;
    refused(verify(&r, &with_parts(&r, Vec::new(), Vec::new())), "account proof is empty");
    Ok(())
}

#[test]
fn an_oversized_proof_is_refused() -> Result<()> {
    let r = read(basechain()?, false)?;
    let oversized = vec![0; usize::try_from(MANIFEST_LIMIT)? + 1];
    refused(
        verify(&r, &with_parts(&r, oversized, Vec::new())),
        "account proof exceeds the byte limit",
    );
    Ok(())
}

#[test]
fn a_proof_that_is_not_a_bag_of_cells_is_refused() -> Result<()> {
    let r = read(basechain()?, false)?;
    refused(
        verify(&r, &with_parts(&r, b"not a bag of cells".to_vec(), Vec::new())),
        "account proof is not a bag of cells",
    );
    Ok(())
}

#[test]
fn a_proof_with_one_root_is_refused() -> Result<()> {
    let r = read(basechain()?, false)?;
    let proof = write_boc(&header_proof(&r.block)?)?;
    refused(
        verify(&r, &with_parts(&r, proof, Vec::new())),
        "account proof has 1 roots, expected 2",
    );
    Ok(())
}

#[test]
fn a_proof_with_three_roots_is_refused() -> Result<()> {
    let r = read(basechain()?, false)?;
    let (other, _) = block(&r.shard, SEQ_NO, 1, &r.state)?;
    let proof = write_boc_multi(vec![
        header_proof(&r.block)?,
        state_proof(&r.state, r.address)?,
        header_proof(&other)?,
    ])?;
    refused(
        verify(&r, &with_parts(&r, proof, Vec::new())),
        "account proof has 3 roots, expected 2",
    );
    Ok(())
}

#[test]
fn a_root_that_is_not_a_merkle_proof_is_refused() -> Result<()> {
    let r = read(basechain()?, false)?;
    let proof = write_boc_multi(vec![r.block.clone(), state_proof(&r.state, r.address)?])?;
    refused(verify(&r, &with_parts(&r, proof, Vec::new())), "account proof is not a Merkle proof");
    Ok(())
}

// ===== block and state binding =====

#[test]
fn a_header_proof_of_another_block_is_refused() -> Result<()> {
    let r = read(basechain()?, false)?;
    let (other, _) = block(&r.shard, SEQ_NO, 1, &r.state)?;
    let proof = write_boc_multi(vec![header_proof(&other)?, state_proof(&r.state, r.address)?])?;
    refused(
        verify(&r, &with_parts(&r, proof, Vec::new())),
        "account header proof belongs to another block",
    );
    Ok(())
}

/// The block id claims the height of the state its header records, but the header itself is
/// one block lower; only the header's own coordinates tell them apart.
#[test]
fn a_block_id_with_other_coordinates_than_its_header_is_refused() -> Result<()> {
    let shard = basechain()?;
    let address = queried(&shard);
    let state = state(GLOBAL_ID, &shard, SEQ_NO + 1, &[(neighbour(&shard, 7), 70)])?;
    let (block, id) = block(&shard, SEQ_NO, 0, &state)?;
    let claimed = BlockIdExt::with_params(
        shard.clone(),
        SEQ_NO + 1,
        id.root_hash().clone(),
        id.file_hash().clone(),
    );
    let r = Read { held: held(), address, shard, state, block, id: claimed };
    refused(verify(&r, &honest(&r)?), "account header proof has other coordinates than its block");
    Ok(())
}

#[test]
fn a_proof_of_another_state_at_the_same_coordinates_is_refused() -> Result<()> {
    let r = read(basechain()?, false)?;
    let other = state(GLOBAL_ID, &r.shard, SEQ_NO, &[(neighbour(&r.shard, 7), 71)])?;
    let proof = write_boc_multi(vec![header_proof(&r.block)?, state_proof(&other, r.address)?])?;
    refused(
        verify(&r, &with_parts(&r, proof, Vec::new())),
        "account state proof is not a proof of the state its block records",
    );
    Ok(())
}

/// A block recording a state that differs from the honest one in one header field.
fn recorded(global_id: i32, shard: &ShardIdent, seq_no: u32) -> Result<()> {
    let block_shard = basechain()?;
    let state = state(global_id, shard, seq_no, &[(neighbour(&block_shard, 7), 70)])?;
    let (block, id) = block(&block_shard, SEQ_NO, 0, &state)?;
    let r =
        Read { held: held(), address: queried(&block_shard), shard: block_shard, state, block, id };
    refused(
        verify(&r, &honest(&r)?),
        "account state proof state has another network, shard or height",
    );
    Ok(())
}

#[test]
fn a_recorded_state_of_another_network_is_refused() -> Result<()> {
    recorded(GLOBAL_ID + 1, &basechain()?, SEQ_NO)
}

#[test]
fn a_recorded_state_of_another_shard_is_refused() -> Result<()> {
    recorded(GLOBAL_ID, &ShardIdent::with_tagged_prefix(0, 0x4000_0000_0000_0000)?, SEQ_NO)
}

#[test]
fn a_recorded_state_of_another_height_is_refused() -> Result<()> {
    recorded(GLOBAL_ID, &basechain()?, SEQ_NO - 1)
}

// ===== account position and body =====

#[test]
fn a_state_proof_without_the_accounts_is_refused() -> Result<()> {
    let r = read(basechain()?, false)?;
    let usage = UsageTree::with_root(r.state.clone());
    ShardStateUnsplit::construct_from_cell(usage.root_cell())?;
    let header_only = MerkleProof::create_by_usage_tree(&r.state, &usage)?.serialize()?;
    let proof = write_boc_multi(vec![header_proof(&r.block)?, header_only])?;
    refused(
        verify(&r, &with_parts(&r, proof, Vec::new())),
        "account state proof does not reach the account's position",
    );
    Ok(())
}

/// The proof visits the path of another address, so the queried address's branch is pruned.
/// An absent-looking lookup there would accept a substituted answer; it must be an error.
#[test]
fn a_pruned_branch_on_the_account_path_is_refused_not_read_as_absence() -> Result<()> {
    let shard = basechain()?;
    let address = queried(&shard);
    let mut far = address;
    far[0] ^= 0x40;
    let state = state(
        GLOBAL_ID,
        &shard,
        SEQ_NO,
        &[(address, 1000), (neighbour(&shard, 7), 70), (far, 30)],
    )?;
    let (block, id) = block(&shard, SEQ_NO, 0, &state)?;
    let r = Read { held: held(), address, shard, state, block, id };
    let proof = write_boc_multi(vec![header_proof(&r.block)?, state_proof(&r.state, far)?])?;
    refused(
        verify(&r, &with_parts(&r, proof, Vec::new())),
        "account state proof does not reach the account's position",
    );
    Ok(())
}

#[test]
fn a_present_account_without_a_body_is_refused() -> Result<()> {
    let r = read(basechain()?, true)?;
    let (proof, _) = parts(&honest(&r)?);
    refused(
        verify(&r, &with_parts(&r, proof, Vec::new())),
        "account read omits an account the state holds",
    );
    Ok(())
}

#[test]
fn a_body_for_an_absent_account_is_refused() -> Result<()> {
    let r = read(basechain()?, false)?;
    let (proof, _) = parts(&honest(&r)?);
    let present = state(GLOBAL_ID, &r.shard, SEQ_NO, &[(r.address, 1000)])?;
    refused(
        verify(&r, &with_parts(&r, proof, body(&present, r.address)?)),
        "account read has a body for an account the state lacks",
    );
    Ok(())
}

#[test]
fn a_body_of_another_account_state_is_refused() -> Result<()> {
    let r = read(basechain()?, true)?;
    let (proof, _) = parts(&honest(&r)?);
    let other = state(GLOBAL_ID, &r.shard, SEQ_NO, &[(r.address, 999)])?;
    refused(
        verify(&r, &with_parts(&r, proof, body(&other, r.address)?)),
        "account body differs from the account the state holds",
    );
    Ok(())
}

#[test]
fn a_body_that_is_not_a_merkle_proof_is_refused() -> Result<()> {
    let r = read(basechain()?, true)?;
    let (proof, _) = parts(&honest(&r)?);
    let plain = write_boc(&account(0, r.address, 1000)?.serialize()?)?;
    refused(verify(&r, &with_parts(&r, proof, plain)), "account body is not a Merkle proof");
    Ok(())
}

#[test]
fn a_body_with_two_roots_is_refused() -> Result<()> {
    let r = read(basechain()?, true)?;
    let (proof, body) = parts(&honest(&r)?);
    let other = state(GLOBAL_ID, &r.shard, SEQ_NO, &[(r.address, 999)])?;
    let doubled = write_boc_multi(vec![
        read_single_root_boc(&body)?,
        read_single_root_boc(self::body(&other, r.address)?)?,
    ])?;
    refused(verify(&r, &with_parts(&r, proof, doubled)), "account body has 2 roots, expected 1");
    Ok(())
}

#[test]
fn an_oversized_body_is_refused() -> Result<()> {
    let r = read(basechain()?, true)?;
    let (proof, _) = parts(&honest(&r)?);
    let oversized = vec![0; usize::try_from(MANIFEST_LIMIT)? + 1];
    refused(verify(&r, &with_parts(&r, proof, oversized)), "account body exceeds the byte limit");
    Ok(())
}

// ===== answers of a real engine =====
//
// Captured from a disposable local network (global id 3) by `examples/capture_account_reads`:
// the newest masterchain block and the basechain shard block it records, read at the address
// native validation uses, plus the masterchain configuration contract. On that chain the
// masterchain caller address holds an account, so both present and absent answers occur.

const MANIFEST: &str = include_str!("../data/account_read/manifest.json");

fn fixture_bytes(name: &str) -> &'static [u8] {
    match name {
        "masterchain-caller" => include_bytes!("../data/account_read/masterchain-caller.tl"),
        "masterchain-config" => include_bytes!("../data/account_read/masterchain-config.tl"),
        "basechain-caller" => include_bytes!("../data/account_read/basechain-caller.tl"),
        _ => &[],
    }
}

struct Captured {
    held: Network,
    block: BlockIdExt,
    account: AccountId,
    present: bool,
    bytes: Vec<u8>,
}

fn captured(name: &str) -> Result<Captured> {
    let manifest: serde_json::Value = serde_json::from_str(MANIFEST)?;
    let entry = manifest["reads"]
        .as_array()
        .context("manifest reads")?
        .iter()
        .find(|entry| entry["name"] == name)
        .context("fixture is not in the manifest")?;
    let text = |key: &str| entry[key].as_str().context("manifest text field").map(str::to_owned);
    let bytes = fixture_bytes(name).to_vec();
    ensure!(sha256(&bytes) == text("sha256")?, "fixture {name} differs from its manifest hash");
    let hash = |key: &str| -> Result<UInt256> {
        Ok(UInt256::from(<[u8; 32]>::try_from(hex::decode(text(key)?)?.as_slice())?))
    };
    let workchain = i32::try_from(entry["workchain"].as_i64().context("workchain")?)?;
    let shard = u64::from_str_radix(&text("shard")?, 16)?;
    let seqno = u32::try_from(entry["seqno"].as_u64().context("seqno")?)?;
    let block = BlockIdExt::with_params(
        ShardIdent::with_tagged_prefix(workchain, shard)?,
        seqno,
        hash("root_hash")?,
        hash("file_hash")?,
    );
    let mut held = held();
    held.global_id = i32::try_from(manifest["global_id"].as_i64().context("global id")?)?;
    let account = AccountId { workchain, id: hash("account")? };
    let present = entry["present"].as_bool().context("present")?;
    Ok(Captured { held, block, account, present, bytes })
}

fn decode(bytes: &[u8]) -> Result<AccountState> {
    tl_api::deserialize_typed::<AccountState>(bytes)
}

fn verify_captured(c: &Captured, bytes: &[u8]) -> Result<()> {
    verify_account_read(&c.held, &c.block, &c.account, &decode(bytes)?)
}

/// One copy of `bytes` per occurrence of `needle`, each with one byte of that occurrence
/// changed. At least one occurrence is required, so a value missing from the answer fails.
fn flipped(bytes: &[u8], needle: &[u8]) -> Result<Vec<Vec<u8>>> {
    let at: Vec<usize> = bytes
        .windows(needle.len())
        .enumerate()
        .filter(|(_, window)| *window == needle)
        .map(|(offset, _)| offset)
        .collect();
    ensure!(!at.is_empty(), "the tampered value does not occur in the answer");
    Ok(at
        .into_iter()
        .map(|offset| {
            let mut tampered = bytes.to_vec();
            tampered[offset + needle.len() / 2] ^= 0x01;
            tampered
        })
        .collect())
}

/// Refused by a proof check, not by the transport or the bag-of-cells framing: the changed
/// answer still decodes as TL, so the refusal comes from the verifier, and the verifier does
/// not refuse it for its framing.
fn refused_by_proof(c: &Captured, tampered: &[u8]) -> Result<()> {
    let answer = decode(tampered).context("a tampered answer must still decode as TL")?;
    let text = match verify_account_read(&c.held, &c.block, &c.account, &answer) {
        Ok(()) => panic!("a changed authenticated byte was accepted"),
        Err(error) => format!("{error:#}"),
    };
    eprintln!("tamper refused: {text}");
    assert!(!text.contains("bag of cells"), "refused by framing, not by a proof check: {text}");
    Ok(())
}

#[test]
fn every_captured_engine_answer_is_accepted() -> Result<()> {
    for name in ["masterchain-caller", "masterchain-config", "basechain-caller"] {
        let c = captured(name)?;
        verify_captured(&c, &c.bytes).with_context(|| format!("captured {name}"))?;
        assert_eq!(c.present, !parts(&decode(&c.bytes)?).1.is_empty(), "{name} presence");
    }
    let presence: Vec<bool> = ["masterchain-caller", "masterchain-config", "basechain-caller"]
        .iter()
        .map(|name| captured(name).map(|c| c.present))
        .collect::<Result<_>>()?;
    assert!(
        presence.contains(&true) && presence.contains(&false),
        "both presence cases are pinned"
    );
    Ok(())
}

/// In the engine's own answer the present account's cell is a pruned branch of the state
/// proof, and its body is a Merkle proof whose root hash is the hash that branch records.
#[test]
fn the_engine_prunes_a_present_account_and_its_body_matches_the_recorded_hash() -> Result<()> {
    let c = captured("masterchain-config")?;
    let (proof, body) = parts(&decode(&c.bytes)?);
    let roots = read_boc(&proof)?.roots;
    let state: ShardStateUnsplit =
        MerkleProof::construct_from_cell(roots[1].clone())?.virtualize()?;
    let entry = state
        .read_accounts()?
        .account(&Address::from(c.account.id.clone()))?
        .context("the configuration contract is present")?;
    let cell = entry.account_cell();
    assert!(cell.is_pruned(), "the engine prunes the account cell in its state proof");
    let body = MerkleProof::construct_from_cell(read_single_root_boc(&body)?)?;
    assert_eq!(body.hash, cell.hash(0), "the body's root is the account the branch records");
    Ok(())
}

#[test]
fn a_captured_answer_with_its_recorded_state_hash_changed_is_refused() -> Result<()> {
    for name in ["masterchain-caller", "basechain-caller"] {
        let c = captured(name)?;
        let (proof, _) = parts(&decode(&c.bytes)?);
        let header: Block =
            MerkleProof::construct_from_cell(read_boc(&proof)?.roots[0].clone())?.virtualize()?;
        let recorded = header.read_state_update()?.new_hash;
        for tampered in flipped(&c.bytes, recorded.as_slice())? {
            refused_by_proof(&c, &tampered)?;
        }
    }
    Ok(())
}

#[test]
fn a_captured_answer_with_its_pruned_account_hash_changed_is_refused() -> Result<()> {
    let c = captured("masterchain-config")?;
    let (proof, _) = parts(&decode(&c.bytes)?);
    let state: ShardStateUnsplit =
        MerkleProof::construct_from_cell(read_boc(&proof)?.roots[1].clone())?.virtualize()?;
    let entry = state
        .read_accounts()?
        .account(&Address::from(c.account.id.clone()))?
        .context("the configuration contract is present")?;
    for tampered in flipped(&c.bytes, entry.account_cell().hash(0).as_slice())? {
        refused_by_proof(&c, &tampered)?;
    }
    Ok(())
}

/// The engine's answer for a present account, checked as an answer for its neighbour: the
/// proof either does not reach the neighbour's position or proves it absent, and an absent
/// account cannot come with a body. (An absence proof alone may also prove other addresses
/// absent, which is correct, so the present answer is the one that pins this.)
#[test]
fn a_captured_present_answer_read_for_another_account_is_refused() -> Result<()> {
    let mut c = captured("masterchain-config")?;
    let mut other = *c.account.id.as_array();
    other[31] ^= 0x01;
    c.account = AccountId { workchain: c.account.workchain, id: other.into() };
    assert!(verify_captured(&c, &c.bytes).is_err(), "present answer accepted for another account");
    Ok(())
}
