//! Stateful development-only message generator for the disposable local pool.
//! Requests and responses contain note secrets and must stay in private files.
use std::io::{BufRead, Read, Write};
use std::str::FromStr;

use ark_ff::AdditiveGroup;
use chain_block::write_boc;
use fips204::{
    ml_dsa_44,
    traits::{SerDes, Signer},
};
use serde_json::{json, Value};
use shielded_pool_circuit::{
    circuit::{HeldNote, OutputNote, ShieldedTransactionCircuit, TransactionBuilder},
    field::Fr,
    groth16, imt, notes, scenario, tree, wire,
};
use shielded_pool_circuit_crosscheck::{
    pool::{be, dec, Pool, DEPLOYED_DENOMINATIONS, WITHDRAWAL_FEE},
    transact::{Anchor, Recipient, Transact, SIGNATURE_CONTEXT},
    wire::byte_chain,
};

#[path = "../runtime_resources.rs"]
mod runtime_resources;
use runtime_resources::{DEVELOPMENT_FIXTURE, POOL_SOURCE};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
fn contract_gas_ceiling(name: &str) -> Result<i64> {
    runtime_resources::gas_ceiling(name).map_err(Into::into)
}
fn development_vk_bytes() -> Result<Vec<u8>> {
    let fixture: Value = serde_json::from_str(DEVELOPMENT_FIXTURE)?;
    let value = fixture["verifying_key"]["hex"].as_str().ok_or("missing development verifying key")?;
    need(value.len() == 2 * 1248, "development verifying key length")?;
    unhex(value)
}
fn need(ok: bool, message: &str) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(message.into())
    }
}
fn num(v: &Value, name: &str) -> Result<u64> {
    Ok(v[name].as_u64().ok_or(format!("missing integer {name}"))?)
}
fn field(v: &Value, name: &str) -> Result<Fr> {
    Ok(Fr::from_str(v[name].as_str().ok_or(format!("missing field {name}"))?)
        .map_err(|_| "invalid field")?)
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn unhex(s: &str) -> Result<Vec<u8>> {
    need(s.len() % 2 == 0 && s.is_ascii(), "invalid hex")?;
    (0..s.len()).step_by(2).map(|i| Ok(u8::from_str_radix(&s[i..i + 2], 16)?)).collect()
}
fn entropy<const N: usize>() -> Result<[u8; N]> {
    let mut out = [0; N];
    std::fs::File::open("/dev/urandom")?.read_exact(&mut out)?;
    Ok(out)
}
fn fresh() -> Result<Fr> {
    Ok(Fr::from(u128::from_le_bytes(entropy()?)))
}
fn key(note: &Value) -> Result<ml_dsa_44::PrivateKey> {
    let b = unhex(note["secret_key"].as_str().ok_or("no secret key")?)?;
    Ok(ml_dsa_44::PrivateKey::try_from_bytes(b.try_into().map_err(|_| "secret length")?)
        .map_err(|_| "secret encoding")?)
}
fn public(note: &Value) -> Result<[u8; 1312]> {
    Ok(unhex(note["public_key"].as_str().ok_or("no public key")?)?
        .try_into()
        .map_err(|_| "public length")?)
}
fn note(amount: u64, owner: u64, index: u64) -> Result<Value> {
    let (pk, sk) = ml_dsa_44::try_keygen().map_err(|_| "keygen failed")?;
    let payload = entropy::<{ wire::OUTPUT_DATA_BYTES }>()?;
    Ok(
        json!({"amount":amount,"owner":owner,"index":index,"nf_key":dec(fresh()?),"note_secret":dec(fresh()?),"public_key":hex(&pk.into_bytes()),"secret_key":hex(&sk.into_bytes()),"payload":hex(&payload),"data_hash":dec(wire::output_data_hash(&payload))}),
    )
}
fn owner(n: &Value) -> Result<Fr> {
    Ok(notes::owner_commitment(
        notes::owner_nf_key_hash(field(n, "nf_key")?),
        wire::pq_auth_key_hash(&public(n)?),
        field(n, "note_secret")?,
    ))
}
fn held(n: &Value) -> Result<HeldNote> {
    Ok(HeldNote {
        is_phantom: false,
        owner_nf_key: field(n, "nf_key")?,
        note_secret: field(n, "note_secret")?,
        amount: Fr::from(num(n, "amount")?),
        output_data_hash: field(n, "data_hash")?,
        leaf_index: num(n, "index")?,
    })
}
fn output(n: &Value) -> Result<OutputNote> {
    Ok(OutputNote {
        is_dummy: false,
        owner_nf_key_hash: notes::owner_nf_key_hash(field(n, "nf_key")?),
        pq_auth_key_hash: wire::pq_auth_key_hash(&public(n)?),
        note_secret: field(n, "note_secret")?,
        amount: Fr::from(num(n, "amount")?),
    })
}
fn trees(s: &Value) -> Result<(tree::Frontier, imt::State)> {
    let leaves = s["leaves"].as_array().ok_or("missing leaves")?;
    need(leaves.len() < 4096, "development model reached its 4096-leaf bound")?;
    let mut f = tree::Frontier::new();
    for l in leaves {
        f.append(Fr::from_str(l.as_str().ok_or("bad leaf")?).map_err(|_| "bad field")?)?;
    }
    let mut i = imt::State::genesis();
    for n in s["nullifiers"].as_array().ok_or("missing nullifiers")? {
        let nf = Fr::from_str(n.as_str().ok_or("bad nullifier")?).map_err(|_| "bad field")?;
        let (_, t) = i.witness_for(&nf)?;
        i.apply(t);
    }
    Ok((f, i))
}
fn expected(s: &Value, f: &tree::Frontier, i: &imt::State) -> Result<Value> {
    Ok(
        json!({"commitment_root":dec(f.recomputed_root()),"nullifier_root":dec(i.root()),"commitment_next_index":f.next_index(),"nullifier_next_index":i.next_index,"native_liability":num(s,"liability")?,"backed":-1}),
    )
}
fn fee(name: &str) -> Result<u64> {
    let gas = u64::try_from(contract_gas_ceiling(name)?)?;
    Ok(667u64
        .checked_add(
            gas.saturating_sub(100)
                .checked_mul(436907)
                .ok_or("fee overflow")?
                .checked_add(65535)
                .ok_or("fee rounding overflow")?
                .checked_div(65536)
                .ok_or("fee division")?,
        )
        .ok_or("fee overflow")?)
}
fn plan(req: Value, keys: &mut Option<groth16::DevelopmentKeys>) -> Result<Value> {
    let op = req["operation"].as_str().ok_or("no operation")?;
    if op == "resources" {
        // Public build inputs only, never notes or private signing material.
        // The installer compares these exact bytes before publishing a snapshot.
        let verifying_key = development_vk_bytes()?;
        return Ok(json!({
            "schema": "tos.local-pq-runtime-resources.v1",
            "withdrawal_fee": WITHDRAWAL_FEE,
            "pool_source": POOL_SOURCE,
            "development_fixture": DEVELOPMENT_FIXTURE,
            "verifying_key_hex": hex(&verifying_key),
            "deposit_gas_ceiling": contract_gas_ceiling("deposit_gas_ceiling")?,
            "transact_gas_ceiling": contract_gas_ceiling("transact_gas_ceiling")?
        }));
    }
    let mut s = req["state"].clone();
    if op == "init" {
        s = json!({"leaves":[],"nullifiers":[],"notes":[],"liability":0});
    }
    let (mut frontier, mut imt) = trees(&s)?;
    let before = expected(&s, &frontier, &imt)?;
    if op == "init" {
        return Ok(json!({"state":s,"expected":before}));
    }
    let mut active = s["notes"].as_array().ok_or("no notes")?.clone();
    let amount = num(&req, "amount")?;
    let index = frontier.next_index();
    let body;
    let value;
    if op == "deposit" {
        need(DEPLOYED_DENOMINATIONS.contains(&amount), "deposit is not an allowed denomination")?;
        let n = note(amount, num(&req, "owner")?, index)?;
        let owner = owner(&n)?;
        let payload = unhex(n["payload"].as_str().ok_or("payload")?)?;
        body = Pool::deposit_body(amount, owner, byte_chain(&payload)?)?;
        let leaf = notes::note_commitment(
            notes::note_body_commitment(owner, Fr::from(amount), field(&n, "data_hash")?),
            Fr::from(index),
        );
        frontier.append(leaf)?;
        s["leaves"].as_array_mut().ok_or("leaves")?.push(json!(dec(leaf)));
        active.push(n);
        s["liability"] =
            json!(num(&s, "liability")?.checked_add(amount).ok_or("liability overflow")?);
        value = amount.checked_add(fee("deposit_gas_ceiling")?).ok_or("deposit fee overflow")?;
    } else {
        need(op == "transfer" || op == "withdraw", "unknown operation")?;
        let selected = req["inputs"].as_array().ok_or("no selected inputs")?;
        need(selected.len() == 2 && selected[0] != selected[1], "two distinct inputs required")?;
        let find = |id: &Value| -> Result<Value> {
            Ok(active.iter().find(|n| n["index"] == *id).ok_or("input not spendable")?.clone())
        };
        let input = [find(&selected[0])?, find(&selected[1])?];
        let total = num(&input[0], "amount")?
            .checked_add(num(&input[1], "amount")?)
            .ok_or("input overflow")?;
        let withdrawal = op == "withdraw";
        need(
            !withdrawal || DEPLOYED_DENOMINATIONS.contains(&amount),
            "withdrawal is not an allowed denomination",
        )?;
        let payout = if withdrawal { amount } else { 0 };
        let wf = if withdrawal { WITHDRAWAL_FEE } else { 0 };
        let change = total
            .checked_sub(payout)
            .and_then(|v| v.checked_sub(wf))
            .ok_or("insufficient private value")?;
        let out0 =
            if withdrawal { change.checked_div(2).ok_or("change division")? } else { amount };
        let out1 = change.checked_sub(out0).ok_or("transfer exceeds input")?;
        need(out0 > 0 && out1 > 0, "two positive output notes required")?;
        let newnotes = [
            note(out0, num(&req, "owner")?, index)?,
            note(out1, num(&input[0], "owner")?, index.checked_add(1).ok_or("index overflow")?)?,
        ];
        let mut dummy = scenario::Pool::new();
        let outputs = [output(&newnotes[0])?, output(&newnotes[1])?, dummy.dummy_output()];
        let payloads = [
            unhex(newnotes[0]["payload"].as_str().ok_or("payload")?)?,
            unhex(newnotes[1]["payload"].as_str().ok_or("payload")?)?,
            entropy::<{ wire::OUTPUT_DATA_BYTES }>()?.to_vec(),
        ];
        let recovery_payload = entropy::<{ wire::OUTPUT_DATA_BYTES }>()?.to_vec();
        let recovery_owner = if withdrawal { fresh()? } else { Fr::ZERO };
        let recipient: [u8; 32] = unhex(req["recipient"].as_str().ok_or("recipient")?)?
            .try_into()
            .map_err(|_| "recipient length")?;
        let pool: [u8; 32] =
            unhex(req["pool"].as_str().ok_or("pool")?)?.try_into().map_err(|_| "pool length")?;
        let until = u32::try_from(num(&req, "valid_until")?)?;
        let anchor = frontier.recomputed_root();
        let builder = TransactionBuilder {
            execution_domain: wire::execution_domain(
                i32::try_from(req["global_id"].as_i64().ok_or("global_id")?)?,
                &pool,
            ),
            valid_until: until,
            intent_nonce: fresh()?,
            public_amount_out: Fr::from(payout),
            withdrawal_fee: Fr::from(wf),
            public_recipient_hash: if withdrawal {
                wire::public_recipient_hash(&recipient)
            } else {
                Fr::ZERO
            },
            recovery_template_hash: if withdrawal {
                wire::recovery_template_hash(
                    recovery_owner,
                    wire::output_data_hash(&recovery_payload),
                )
            } else {
                Fr::ZERO
            },
            is_withdrawal: None,
            input_pq_auth_key_hash: [
                wire::pq_auth_key_hash(&public(&input[0])?),
                wire::pq_auth_key_hash(&public(&input[1])?),
            ],
            outputs,
            output_data_hash: payloads.each_ref().map(|p| wire::output_data_hash(p)),
        };
        let (pubin, witness) =
            builder.build(&frontier, anchor, [held(&input[0])?, held(&input[1])?])?;
        if keys.is_none() {
            let k = groth16::development_keys(ShieldedTransactionCircuit::blank(pubin))?;
            need(
                groth16::canonical_verifying_key(&k.verifying)?.bytes == development_vk_bytes()?,
                "development key mismatch",
            )?;
            *keys = Some(k);
        }
        let k = keys.as_ref().ok_or("keys not initialized")?;
        let proof =
            groth16::prove(k, ShieldedTransactionCircuit::new(pubin, witness), entropy::<1>()?[0])?;
        need(groth16::verify(&k.verifying, &pubin, &proof)?, "generated proof does not verify")?;
        let canonical = groth16::CanonicalProof::from_proof(&proof)?;
        let sigs = [
            key(&input[0])?
                .try_sign(&be(pubin.transaction_intent_digest), SIGNATURE_CONTEXT)
                .map_err(|_| "sign failed")?,
            key(&input[1])?
                .try_sign(&be(pubin.transaction_intent_digest), SIGNATURE_CONTEXT)
                .map_err(|_| "sign failed")?,
        ];
        let pubs = [public(&input[0])?, public(&input[1])?];
        let (w0, t0) = imt.witness_for(&pubin.nullifier_0)?;
        imt.apply(t0);
        let (w1, t1) = imt.witness_for(&pubin.nullifier_1)?;
        imt.apply(t1);
        body = Transact {
            public: &pubin,
            proof: &canonical,
            anchor_root: anchor,
            anchor: Anchor::Current,
            valid_until: until,
            output_payloads: &payloads,
            keys: [&pubs[0], &pubs[1]],
            signatures: &sigs,
            witnesses: &[w0, w1],
            public_amount_out: payout,
            withdrawal_fee: wf,
            recipient: if withdrawal { Some(Recipient(recipient)) } else { None },
            recovery_owner_commitment: recovery_owner,
            recovery_payload: if withdrawal { Some(recovery_payload) } else { None },
        }
        .body()?;
        for nf in [pubin.nullifier_0, pubin.nullifier_1] {
            s["nullifiers"].as_array_mut().ok_or("nullifiers")?.push(json!(dec(nf)));
        }
        for nb in [pubin.note_body_0, pubin.note_body_1, pubin.note_body_2] {
            let leaf = notes::note_commitment(nb, Fr::from(frontier.next_index()));
            frontier.append(leaf)?;
            s["leaves"].as_array_mut().ok_or("leaves")?.push(json!(dec(leaf)));
        }
        active.retain(|n| !selected.contains(&n["index"]));
        active.extend(newnotes);
        s["liability"] = json!(num(&s, "liability")?
            .checked_sub(payout)
            .and_then(|v| v.checked_sub(wf))
            .ok_or("liability underflow")?);
        value = fee("transact_gas_ceiling")?;
    }
    s["notes"] = json!(active);
    Ok(
        json!({"body_hex":hex(&write_boc(&body)?),"value":value,"before":before,"expected":expected(&s,&frontier,&imt)?,"state":s}),
    )
}
fn main() -> Result<()> {
    let stdin = std::io::stdin();
    let mut input = stdin.lock();
    let mut keys = None;
    loop {
        let mut bytes = Vec::new();
        let n = (&mut input).take(32 * 1024 * 1024 + 1).read_until(b'\n', &mut bytes)?;
        if n == 0 {
            break;
        }
        need(n <= 32 * 1024 * 1024 && bytes.last() == Some(&b'\n'), "request exceeds bound")?;
        let result =
            serde_json::from_slice(&bytes).map_err(Into::into).and_then(|r| plan(r, &mut keys));
        let response = match result {
            Ok(v) => json!({"ok":true,"result":v}),
            Err(e) => json!({"ok":false,"error":e.to_string()}),
        };
        println!("{}", response);
        std::io::stdout().flush()?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn initial() -> Value {
        json!({"leaves":[],"nullifiers":[],"notes":[],"liability":0})
    }
    #[test]
    fn deposit_matches_reconstructed_model() -> Result<()> {
        let p = plan(
            json!({"state":initial(),"operation":"deposit","amount":1_000_000_000u64,"owner":1}),
            &mut None,
        )?;
        let (f, i) = trees(&p["state"])?;
        need(p["expected"] == expected(&p["state"], &f, &i)?, "model differs")?;
        need(num(&p["state"]["notes"][0], "owner")? == 1, "owner differs")?;
        need(num(&p["state"], "liability")? == 1_000_000_000, "deposit liability differs")
    }
    #[test]
    fn denomination_is_required() {
        let p = plan(
            json!({"state":initial(),"operation":"deposit","amount":123,"owner":0}),
            &mut None,
        );
        assert!(matches!(p,Err(e) if e.to_string().contains("denomination")));
    }
    #[test]
    fn repeated_inputs_are_refused() {
        let p = plan(
            json!({"state":initial(),"operation":"transfer","amount":1,"inputs":[0,0]}),
            &mut None,
        );
        assert!(matches!(p,Err(e) if e.to_string().contains("distinct")));
    }
    #[test]
    fn liability_overflow_is_refused() {
        let mut s = initial();
        s["liability"] = json!(u64::MAX);
        let p = plan(
            json!({"state":s,"operation":"deposit","amount":1_000_000_000u64,"owner":0}),
            &mut None,
        );
        assert!(matches!(p,Err(e) if e.to_string().contains("overflow")));
    }
}
