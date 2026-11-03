// Copyright 2026 TOS Network. SPDX-License-Identifier: GPL-3.0-only
//! Owned replay session. Initial hashes and head metadata must come from one
//! verified observation; this adapter does not authenticate caller expectations.
use crate::{
    decimal,
    history::hash,
    pool::read_cell,
    recover_notes,
    replay::{Head, Replay},
    response, Error, Result, ScanResult, TosShieldedResponse, MAX_OUTPUTS, MAX_REQUEST_BYTES,
    MAX_RESPONSE_BYTES,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use chain_block::ConfigParamEnum;
use serde::{Deserialize, Serialize};
use shielded_pool_circuit::{field::Fr, wire};
use shielded_pool_codec::{compute_fee, PoolState, BOUNCE_GAS_CEILING};
use shielded_pool_wallet::plan::PoolTerms;
use shielded_pool_wallet::{
    descriptor::{Descriptor, DESCRIPTOR_BYTES},
    keys::PoolInstance,
    ledger::Ledger,
};
use std::{
    panic::{catch_unwind, AssertUnwindSafe},
    ptr, slice,
};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    version: u8,
    global_id: i32,
    account_id: String,
    last_hash: String,
    last_lt: String,
    account_root: String,
    shard_time: String,
    pool_state_boc: String,
    pool_data_hash: String,
    gas_boc: String,
    gas_hash: String,
    receive_binding: Option<String>,
}

enum State {
    Building(Box<Replay>),
    Ready(Box<Ledger>),
    Failed,
}
/// Opaque and single-owner. All calls, including free, must be serialized by the caller.
pub struct TosShieldedReplay {
    state: State,
    domain: Fr,
    receive_binding: Option<[u8; 228]>,
    terms: PoolTerms,
}

#[cfg(all(unix, feature = "proving"))]
pub struct PaymentPreparation<'a> {
    pub request: &'a shielded_pool_wallet::plan::Request,
    pub terms: &'a shielded_pool_wallet::spend::Terms,
    pub proven_time: u32,
}

#[cfg(all(unix, feature = "proving"))]
pub struct RecoveredRelaySubmission {
    request: Zeroizing<Vec<u8>>,
    quote: br1_client::client::Quote,
    client: br1_client::client::Client,
    inputs_consumed: bool,
}

#[cfg(all(unix, feature = "proving"))]
impl RecoveredRelaySubmission {
    pub async fn status(
        &self,
    ) -> std::result::Result<br1_client::client::Status, br1_client::client::ClientError> {
        self.client.status_wire(&self.request, &self.quote).await
    }

    /// Explicit retry of the saved request through its original isolation context.
    pub async fn retry(
        &self,
    ) -> std::result::Result<br1_client::client::Status, br1_client::client::ClientError> {
        match self.status().await {
            Ok(status) => Ok(status),
            Err(br1_client::client::ClientError::Refused { status: 404 })
                if !self.inputs_consumed =>
            {
                self.client.submit_wire(&self.request, &self.quote).await
            }
            Err(error) => Err(error),
        }
    }
}

fn bound_cell(encoded: &str, expected: &str) -> Result<chain_block::Cell> {
    let bytes = STANDARD.decode(encoded).map_err(|_| Error::InvalidInput)?;
    if STANDARD.encode(&bytes) != encoded {
        return Err(Error::InvalidInput);
    }
    let root = read_cell(&bytes)?;
    if root.cell_type() != chain_block::CellType::Ordinary || root.level() != 0 {
        return Err(Error::InvalidInput);
    }
    if root.repr_hash().as_array() != &hash(expected)? {
        return Err(Error::InvalidInput);
    }
    Ok(root)
}

/// Authenticated BR1 offer and the isolated transport that obtained it.
#[cfg(all(unix, feature = "proving"))]
pub struct RelayOffer {
    client: br1_client::client::Client,
    quote: br1_client::client::Quote,
}

#[cfg(all(unix, feature = "proving"))]
impl RelayOffer {
    /// Obtain a fee offer through the approved client's isolated Tor route.
    async fn request(client: br1_client::client::Client, lifetime: u64) -> Result<Self> {
        use rand::RngCore;
        let mut token = Zeroizing::new([0u8; 32]);
        rand::rngs::OsRng.try_fill_bytes(token.as_mut()).map_err(|_| Error::Crypto)?;
        let token = Zeroizing::new(hex::encode(token.as_slice()));
        let quote = client.quote(2, lifetime, &token).await.map_err(|_| Error::InvalidInput)?;
        Ok(Self { client, quote })
    }

    pub fn identity(&self) -> &str {
        &self.quote.identity
    }

    pub fn fee(&self) -> u64 {
        self.quote.terms.amount
    }

    pub fn valid_until(&self) -> u64 {
        self.quote.terms.valid_until
    }
}

/// Payment details displayed and accepted by the wallet user.
#[cfg(all(unix, feature = "proving"))]
pub struct ConfirmedTransfer<'a> {
    pub recipient: &'a Descriptor,
    pub amount: u128,
    pub fee: u64,
    pub quote_identity: &'a str,
}

/// Audited proving material tied to an authenticated pool selection.
#[cfg(all(unix, feature = "proving"))]
pub struct PaymentProver {
    client: shielded_pool_prover::PublicClient,
    binding: [u8; 228],
}

impl TosShieldedReplay {
    fn create(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_REQUEST_BYTES {
            return Err(Error::Limit);
        }
        let r: Request = serde_json::from_slice(bytes).map_err(|_| Error::InvalidInput)?;
        if r.version != 1 {
            return Err(Error::InvalidInput);
        }
        let head = Head {
            account_id: hash(&r.account_id)?,
            last_hash: hash(&r.last_hash)?,
            last_lt: decimal(&r.last_lt)?,
            account_root: hash(&r.account_root)?,
            shard_time: decimal(&r.shard_time)?,
        };
        let state = PoolState::parse(&bound_cell(&r.pool_state_boc, &r.pool_data_hash)?)
            .map_err(|_| Error::InvalidInput)?;
        let gas = bound_cell(&r.gas_boc, &r.gas_hash)?;
        let ConfigParamEnum::ConfigParam21(prices) =
            ConfigParamEnum::construct_from_cell_and_number(gas, 21)
                .map_err(|_| Error::InvalidInput)?
        else {
            return Err(Error::InvalidInput);
        };
        let charge = compute_fee(&prices, BOUNCE_GAS_CEILING).map_err(|_| Error::InvalidInput)?;
        let domain = wire::execution_domain(r.global_id, &head.account_id);
        let receive_binding = r
            .receive_binding
            .map(|encoded| {
                let mut bytes = [0; 228];
                hex::decode_to_slice(encoded, &mut bytes).map_err(|_| Error::InvalidInput)?;
                if bytes[..4] != r.global_id.to_be_bytes()
                    || bytes[4..36] != head.account_id
                    || bytes[132..164] != state.config.profile_hash
                    || bytes[164..196] != state.config.poseidon_manifest_hash
                    || bytes[196..228] != state.config.groth16_vk_hash
                {
                    return Err(Error::InvalidInput);
                }
                Ok(bytes)
            })
            .transpose()?;
        Ok(Self {
            state: State::Building(Box::new(Replay::new(head, &state, charge)?)),
            domain,
            receive_binding,
            terms: PoolTerms {
                denominations: state.config.denominations,
                withdrawal_fee: state.config.withdrawal_fee,
            },
        })
    }

    #[cfg(unix)]
    fn wallet_binding(&self, bytes: &[u8]) -> Result<crate::sealed::Binding> {
        if self.receive_binding.as_ref().map(|value| value.as_slice()) != Some(bytes) {
            return Err(Error::InvalidInput);
        }
        let field = |offset| -> Result<[u8; 32]> {
            bytes[offset..offset + 32].try_into().map_err(|_| Error::InvalidInput)
        };
        let binding = crate::sealed::Binding {
            global_id: i32::from_be_bytes(bytes[..4].try_into().map_err(|_| Error::InvalidInput)?),
            pool_account: field(4)?,
            genesis_root: field(36)?,
            genesis_file: field(68)?,
            code_hash: field(100)?,
            profile_hash: field(132)?,
            manifest_hash: field(164)?,
            verifying_key_hash: field(196)?,
        };
        if wire::execution_domain(binding.global_id, &binding.pool_account) != self.domain {
            return Err(Error::InvalidInput);
        }
        Ok(binding)
    }

    /// Audit the installed material for the exact pool this replay authenticated.
    #[cfg(all(unix, feature = "proving"))]
    pub fn load_payment_prover(
        &self,
        phase1: &std::path::Path,
        ceremony: &std::path::Path,
        binding: &[u8; 228],
    ) -> Result<PaymentProver> {
        if !matches!(self.state, State::Ready(_)) {
            return Err(Error::InvalidInput);
        }
        let pool = self.wallet_binding(binding)?;
        let client = shielded_pool_prover::PublicClient::audit_and_load(
            phase1,
            ceremony,
            &hex::encode(pool.verifying_key_hash),
            pool.global_id,
            &pool.pool_account,
        )
        .map_err(|_| Error::Crypto)?;
        Ok(PaymentProver { client, binding: *binding })
    }

    /// Prepare a spend against this completed ledger. The caller verifies the
    /// quote and freshness before invoking this operation and before signing.
    #[cfg(all(unix, feature = "proving"))]
    pub fn prepare_payment(
        &self,
        seed: &[u8; 32],
        root: &std::path::Path,
        binding: &[u8; 228],
        payment: PaymentPreparation<'_>,
        fresh: &mut dyn FnMut() -> shielded_pool_wallet::error::Result<Fr>,
    ) -> Result<shielded_pool_wallet::spend::Prepared> {
        let PaymentPreparation { request, terms, proven_time } = payment;
        let State::Ready(ledger) = &self.state else { return Err(Error::InvalidInput) };
        if terms.anchor_root != ledger.checkpoint().commitment_root
            || terms.intent_nonce == Fr::from(0u64)
            || !terms.valid_until.checked_sub(proven_time).is_some_and(|remaining| {
                (1..=shielded_pool_prover::INTENT_VALIDITY_WINDOW_SECS).contains(&remaining)
            })
        {
            return Err(Error::InvalidInput);
        }
        let pool = self.wallet_binding(binding)?;
        let recovered = crate::wallet::recover_complete(
            ledger.outputs(),
            ledger.published_nullifiers(),
            seed,
            self.domain,
        )?;
        let mut store = crate::store::StateStore::open_wallet(
            root,
            crate::sealed::RecordCipher::derive(seed, pool),
        )
        .map_err(|_| Error::InvalidInput)?;
        if let Some(pending) = store.pending_payment().map_err(|_| Error::InvalidInput)? {
            if !ledger.accepted_intents().contains(&pending.intent) {
                return Err(Error::InvalidInput);
            }
            // Only authenticated chain replay can settle a journaled payment.
            store.commit(&[]).map_err(|_| Error::InvalidInput)?;
        }
        let plan = store
            .reserve_payment_plan(&self.terms, &recovered.0, &Default::default(), request)
            .map_err(|_| Error::InvalidInput)?;
        let instance = PoolInstance::new(seed, self.domain);
        shielded_pool_wallet::spend::prepare(&instance, &plan, ledger.frontier(), terms, fresh)
            .map_err(|_| Error::Crypto)
    }

    /// Get an authenticated quote for the pool proven by this replay. The app
    /// supplies an approved release and verifies current on-chain bond eligibility.
    #[cfg(all(unix, feature = "proving"))]
    pub async fn request_relay_offer(
        &self,
        release: &br1_client::release::Release,
        bond_init: &str,
        tor_port: u16,
        timeout_secs: u64,
        lifetime: u64,
    ) -> Result<RelayOffer> {
        use br1_client::socks::{Isolation, TorProxy};
        if !matches!(self.state, State::Ready(_)) {
            return Err(Error::InvalidInput);
        }
        let pool =
            self.wallet_binding(self.receive_binding.as_ref().ok_or(Error::InvalidInput)?)?;
        if release.global_id != pool.global_id
            || release.genesis_root != hex::encode(pool.genesis_root)
            || release.genesis_file != hex::encode(pool.genesis_file)
            || release.pool != format!("0:{}", hex::encode(pool.pool_account))
            || release.pool_code_hash != hex::encode(pool.code_hash)
        {
            return Err(Error::InvalidInput);
        }
        let proxy =
            TorProxy::new(tor_port, Isolation::random()).map_err(|_| Error::InvalidInput)?;
        let client = br1_client::client::Client::from_bond(release, bond_init, proxy, timeout_secs)
            .map_err(|_| Error::InvalidInput)?;
        RelayOffer::request(client, lifetime).await
    }

    /// Build the spend from the exact confirmed recipient, amount and BR1 quote.
    /// The caller supplies fresh proven time and an approved bonded relay client.
    #[cfg(all(unix, feature = "proving"))]
    #[allow(clippy::too_many_arguments)]
    pub fn stage_confirmed_transfer(
        &self,
        seed: &[u8; 32],
        root: &std::path::Path,
        prover: &PaymentProver,
        transfer: ConfirmedTransfer<'_>,
        proven_time: u32,
        relay: RelayOffer,
        fresh: &mut dyn FnMut() -> shielded_pool_wallet::error::Result<Fr>,
    ) -> Result<RecoveredRelaySubmission> {
        let RelayOffer { client, quote } = relay;
        let quote = client
            .restore_quote(&quote.envelope, &quote.status_token)
            .map_err(|_| Error::InvalidInput)?;
        let terms = &quote.terms;
        if quote.identity != transfer.quote_identity
            || terms.amount != transfer.fee
            || terms.slot != 2
            || !(terms.issued_at..terms.valid_until).contains(&u64::from(proven_time))
        {
            return Err(Error::InvalidInput);
        }
        let fee_bytes = STANDARD.decode(&terms.descriptor_b64).map_err(|_| Error::InvalidInput)?;
        let fee = Descriptor::from_bytes(&fee_bytes).map_err(|_| Error::InvalidInput)?;
        let request = shielded_pool_wallet::plan::Request::relayed_transfer(
            self.domain,
            transfer.recipient,
            transfer.amount,
            &fee,
            u128::from(terms.amount),
        )
        .map_err(|_| Error::InvalidInput)?;
        let State::Ready(ledger) = &self.state else { return Err(Error::InvalidInput) };
        let terms = shielded_pool_wallet::spend::Terms {
            anchor_root: ledger.checkpoint().commitment_root,
            valid_until: u32::try_from(terms.valid_until).map_err(|_| Error::InvalidInput)?,
            intent_nonce: fresh().map_err(|_| Error::Crypto)?,
        };
        let prepared = self.prepare_payment(
            seed,
            root,
            &prover.binding,
            PaymentPreparation { request: &request, terms: &terms, proven_time },
            fresh,
        )?;
        self.stage_private_transfer(seed, root, prover, prepared, proven_time, (client, quote))
    }

    /// Prove, sign and journal a confirmed payment before handing it to the
    /// relay transport. The caller must check the quote's fee and bond policy
    /// against the payment the user confirmed.
    #[cfg(all(unix, feature = "proving"))]
    pub fn stage_private_transfer(
        &self,
        seed: &[u8; 32],
        root: &std::path::Path,
        prover: &PaymentProver,
        payment: shielded_pool_wallet::spend::Prepared,
        proven_time: u32,
        relay: (br1_client::client::Client, br1_client::client::Quote),
    ) -> Result<RecoveredRelaySubmission> {
        let (client, quote) = relay;
        let quote = client
            .restore_quote(&quote.envelope, &quote.status_token)
            .map_err(|_| Error::InvalidInput)?;
        let terms = &quote.terms;
        let descriptor = STANDARD.decode(&terms.descriptor_b64).map_err(|_| Error::InvalidInput)?;
        let descriptor = shielded_pool_wallet::descriptor::Descriptor::from_bytes(&descriptor)
            .map_err(|_| Error::InvalidInput)?;
        let recipient = shielded_pool_wallet::plan::RecipientKeys::of(&descriptor);
        let fee = &payment.witness.outputs[2];
        if terms.slot != 2
            || !(terms.issued_at..terms.valid_until).contains(&u64::from(proven_time))
            || shielded_pool_circuit::field::fr_to_be(&payment.public.valid_until)
                > shielded_pool_circuit::field::fr_to_be(&Fr::from(terms.valid_until))
            || descriptor.execution_domain != self.domain
            || fee.is_dummy
            || fee.amount != Fr::from(terms.amount)
            || fee.owner_nf_key_hash != recipient.owner_nf_key_hash
            || fee.pq_auth_key_hash != recipient.pq_auth_key_hash
        {
            return Err(Error::InvalidInput);
        }

        let body =
            Zeroizing::new(self.encode_private_transfer(seed, prover, payment, proven_time)?);
        let request =
            self.persist_relay_submission(seed, root, &prover.binding, &body, &client, &quote)?;
        Ok(RecoveredRelaySubmission { request, quote, client, inputs_consumed: false })
    }

    /// Prove and sign a private transfer against the current replay checkpoint.
    /// The BR1 envelope must be persisted before it is submitted.
    #[cfg(all(unix, feature = "proving"))]
    fn encode_private_transfer(
        &self,
        seed: &[u8; 32],
        prover: &PaymentProver,
        payment: shielded_pool_wallet::spend::Prepared,
        proven_time: u32,
    ) -> Result<Vec<u8>> {
        use shielded_pool_circuit::field::fr_to_be;
        use shielded_pool_codec::{
            auth_bundle, groth16_proof_cell, witness_bundle, NullifierWitness, TransactBody,
            ANCHOR_CURRENT,
        };
        let State::Ready(ledger) = &self.state else { return Err(Error::InvalidInput) };
        if self.receive_binding.as_ref() != Some(&prover.binding)
            || prover.client.execution_domain() != self.domain
            || payment.public.anchor_root != ledger.checkpoint().commitment_root
            || payment.recovery_payload.is_some()
            || payment.public.public_amount_out != Fr::from(0u64)
        {
            return Err(Error::InvalidInput);
        }
        let expires = fr_to_be(&payment.public.valid_until);
        if expires[..28] != [0; 28] {
            return Err(Error::InvalidInput);
        }
        let valid_until =
            u32::from_be_bytes(expires[28..].try_into().map_err(|_| Error::InvalidInput)?);
        let proof = crate::prove_prepared_payment(&prover.client, &payment, proven_time)?;
        let witnesses = shielded_pool_wallet::spend::nullifier_witnesses(
            ledger.nullifier_state(),
            payment.nullifiers(),
        )
        .map_err(|_| Error::Crypto)?
        .map(|witness| NullifierWitness {
            low_index: witness.low_index,
            low_value: fr_to_be(&witness.low_value),
            low_next_index: witness.low_next_index,
            low_next_value: fr_to_be(&witness.low_next_value),
            low_path: witness.low_path.iter().map(fr_to_be).collect(),
            append_path: witness.append_path.iter().map(fr_to_be).collect(),
        });
        let signed =
            payment.sign(&PoolInstance::new(seed, self.domain)).map_err(|_| Error::Crypto)?;
        let public = signed.public;
        let intent_digest = fr_to_be(&public.transaction_intent_digest);
        let body = TransactBody {
            query_id: u64::from_be_bytes(
                intent_digest[24..].try_into().map_err(|_| Error::InvalidInput)?,
            ),
            anchor_kind: ANCHOR_CURRENT,
            anchor_id: 0,
            valid_until,
            public_amount_out: 0,
            withdrawal_fee: 0,
            recipient: None,
            intent_digest,
            anchor_root: fr_to_be(&public.anchor_root),
            nullifiers: [fr_to_be(&public.nullifier_0), fr_to_be(&public.nullifier_1)],
            note_bodies: [
                fr_to_be(&public.note_body_0),
                fr_to_be(&public.note_body_1),
                fr_to_be(&public.note_body_2),
            ],
            payloads: signed.payloads,
            groth16_proof: groth16_proof_cell(&proof.a, &proof.b, &proof.c)
                .map_err(|_| Error::Crypto)?,
            recovery_owner_commitment: fr_to_be(&signed.recovery_owner_commitment),
            recovery_payload: None,
            recovery_cell: chain_block::Cell::default(),
            auth_bundle: auth_bundle(
                [&signed.input_keys[0], &signed.input_keys[1]],
                [&signed.signatures[0], &signed.signatures[1]],
            )
            .map_err(|_| Error::Crypto)?,
            witness_bundle: witness_bundle(&witnesses).map_err(|_| Error::Crypto)?,
        }
        .build()
        .map_err(|_| Error::InvalidInput)?;
        chain_block::write_boc(&body).map_err(|_| Error::InvalidInput)
    }

    /// Build and persist the exact BR1 request before exposing it to a transport.
    /// The quote terms must already have passed authentication and fee review.
    #[cfg(all(unix, feature = "proving"))]
    fn persist_relay_submission(
        &self,
        seed: &[u8; 32],
        root: &std::path::Path,
        binding: &[u8; 228],
        body_bytes: &[u8],
        client: &br1_client::client::Client,
        authenticated: &br1_client::client::Quote,
    ) -> Result<Zeroizing<Vec<u8>>> {
        use br1_client::{request, wire};
        use shielded_pool_codec::TransactBody;
        let State::Ready(ledger) = &self.state else { return Err(Error::InvalidInput) };
        let pool = self.wallet_binding(binding)?;
        if body_bytes.len() > request::MAX_BODY_BYTES {
            return Err(Error::Limit);
        }
        let quote = client
            .restore_quote(&authenticated.envelope, &authenticated.status_token)
            .map_err(|_| Error::InvalidInput)?;
        if quote.identity != authenticated.identity || quote.terms != authenticated.terms {
            return Err(Error::InvalidInput);
        }
        let quote_terms = &quote.terms_value;
        let terms = &quote.terms;
        let scope = terms.release.as_str();
        if terms.slot != 2 {
            return Err(Error::InvalidInput);
        }
        let mut slice = chain_block::SliceData::load_cell(read_cell(body_bytes)?)
            .map_err(|_| Error::InvalidInput)?;
        if slice.get_next_u32().map_err(|_| Error::InvalidInput)?
            != shielded_pool_codec::OP_TRANSACT
        {
            return Err(Error::InvalidInput);
        }
        let body = TransactBody::parse(&mut slice).map_err(|_| Error::InvalidInput)?;
        let intent = shielded_pool_circuit::field::fr_from_be(&body.intent_digest)
            .map_err(|_| Error::InvalidInput)?;
        if body.anchor_kind != shielded_pool_codec::ANCHOR_CURRENT
            || body.anchor_root
                != shielded_pool_circuit::field::fr_to_be(&ledger.checkpoint().commitment_root)
            || ledger.accepted_intents().contains(&intent)
        {
            return Err(Error::InvalidInput);
        }
        for encoded in &body.nullifiers {
            let nullifier = shielded_pool_circuit::field::fr_from_be(encoded)
                .map_err(|_| Error::InvalidInput)?;
            if ledger.published_nullifiers().contains(&nullifier) {
                return Err(Error::InvalidInput);
            }
        }
        let request = request::Request {
            release: scope.to_owned(),
            intent: hex::encode(body.intent_digest),
            body_b64: STANDARD.encode(body_bytes),
            body_sha256: wire::hash(body_bytes),
            nullifiers: body.nullifiers.map(hex::encode),
            quote_hash: quote.identity.clone(),
            fee_note_body: hex::encode(body.note_bodies[2]),
            fee_slot: terms.slot,
            fee_note_index: terms.note_index,
            valid_until: body.valid_until,
            funding_cap: terms.funding_cap,
        };
        let value = serde_json::to_value(&request).map_err(|_| Error::InvalidInput)?;
        request::Candidate::check(&value, scope, quote_terms).map_err(|_| Error::InvalidInput)?;
        let bytes = Zeroizing::new(request.wire().map_err(|_| Error::InvalidInput)?);
        let mut store = crate::store::StateStore::open_wallet(
            root,
            crate::sealed::RecordCipher::derive(seed, pool),
        )
        .map_err(|_| Error::InvalidInput)?;
        let stored = Zeroizing::new(
            serde_json::to_vec(&(
                STANDARD.encode(&bytes),
                STANDARD.encode(&authenticated.envelope),
                &authenticated.status_token,
                client.isolation(),
            ))
            .map_err(|_| Error::InvalidInput)?,
        );
        store.persist_pending_payment(intent, &stored).map_err(|_| Error::InvalidInput)?;
        Ok(bytes)
    }

    /// Recover the original submission and reauthenticate its quote before a retry.
    /// The caller must use the approved relayer client and fresh verified replay.
    #[cfg(all(unix, feature = "proving"))]
    pub fn recover_relay_submission(
        &self,
        seed: &[u8; 32],
        root: &std::path::Path,
        binding: &[u8; 228],
        open_client: impl FnOnce(br1_client::socks::Isolation) -> Result<br1_client::client::Client>,
    ) -> Result<Option<RecoveredRelaySubmission>> {
        let State::Ready(ledger) = &self.state else { return Err(Error::InvalidInput) };
        let pool = self.wallet_binding(binding)?;
        let mut store = crate::store::StateStore::open_wallet(
            root,
            crate::sealed::RecordCipher::derive(seed, pool),
        )
        .map_err(|_| Error::InvalidInput)?;
        let Some(record) = store.pending_payment().map_err(|_| Error::InvalidInput)? else {
            return Ok(None);
        };
        if ledger.accepted_intents().contains(&record.intent) {
            return Ok(None);
        }
        let (request, envelope, token, isolation): (
            &str,
            &str,
            &str,
            br1_client::socks::Isolation,
        ) = serde_json::from_slice(&record.request).map_err(|_| Error::InvalidInput)?;
        let client = open_client(isolation.clone())?;
        if &isolation != client.isolation() {
            return Err(Error::InvalidInput);
        }
        let bytes = Zeroizing::new(STANDARD.decode(request).map_err(|_| Error::InvalidInput)?);
        let envelope = STANDARD.decode(envelope).map_err(|_| Error::InvalidInput)?;
        let quote = client.restore_quote(&envelope, token).map_err(|_| Error::InvalidInput)?;
        let parsed: br1_client::request::Request =
            serde_json::from_slice(&bytes).map_err(|_| Error::InvalidInput)?;
        if parsed.intent != hex::encode(shielded_pool_circuit::field::fr_to_be(&record.intent))
            || parsed.quote_hash != quote.identity
            || parsed.wire().map_err(|_| Error::InvalidInput)?.as_slice() != bytes.as_slice()
        {
            return Err(Error::InvalidInput);
        }
        let inputs_consumed = parsed.nullifiers.iter().try_fold(false, |consumed, encoded| {
            let word = hash(encoded)?;
            let nullifier =
                shielded_pool_circuit::field::fr_from_be(&word).map_err(|_| Error::InvalidInput)?;
            Ok(consumed || ledger.published_nullifiers().contains(&nullifier))
        })?;
        Ok(Some(RecoveredRelaySubmission { request: bytes, quote, client, inputs_consumed }))
    }

    fn scan(&self, seed: &[u8; 32], offset: usize, count: usize) -> Result<Zeroizing<Vec<u8>>> {
        let State::Ready(ledger) = &self.state else {
            return Err(Error::InvalidInput);
        };
        let end = offset.checked_add(count).ok_or(Error::Limit)?;
        if count == 0
            || count > MAX_OUTPUTS
            || offset > ledger.outputs().len()
            || end > ledger.outputs().len()
        {
            return Err(Error::InvalidInput);
        }
        let instance = PoolInstance::new(seed, self.domain);
        let outputs = ledger.outputs()[offset..end]
            .iter()
            .map(|o| (o.observed.clone(), o.leaf))
            .collect::<Vec<_>>();
        let page = Page {
            version: 1,
            output_offset: offset.to_string(),
            output_count: count.to_string(),
            total_outputs: ledger.outputs().len().to_string(),
            scan: recover_notes(&instance, &outputs, ledger.published_nullifiers())?,
        };
        let bytes = Zeroizing::new(serde_json::to_vec(&page).map_err(|_| Error::InvalidInput)?);
        if bytes.len() > MAX_RESPONSE_BYTES {
            return Err(Error::Limit);
        }
        Ok(bytes)
    }
}

#[derive(Serialize, Zeroize, ZeroizeOnDrop)]
struct Page {
    version: u8,
    output_offset: String,
    output_count: String,
    total_outputs: String,
    scan: ScanResult,
}

/// # Safety
/// Non-null pointers identify live allocations of the stated length.
#[no_mangle]
pub unsafe extern "C" fn tos_shielded_replay_create(
    request: *const u8,
    length: usize,
) -> *mut TosShieldedReplay {
    if request.is_null() || length > MAX_REQUEST_BYTES {
        return ptr::null_mut();
    }
    match catch_unwind(AssertUnwindSafe(|| {
        TosShieldedReplay::create(unsafe { slice::from_raw_parts(request, length) })
    })) {
        Ok(Ok(session)) => Box::into_raw(Box::new(session)),
        _ => ptr::null_mut(),
    }
}

/// Report whether this library includes local proving and BR1 submission.
#[no_mangle]
pub extern "C" fn tos_shielded_payment_supported() -> u8 {
    u8::from(cfg!(all(unix, feature = "proving")))
}

/// Audit installed proving material against the live replay's pool binding.
#[cfg(all(unix, feature = "proving"))]
///
/// # Safety
/// The session must be live and serialized. Both path pointers must be valid
/// for their stated lengths. The caller supplies trusted local paths.
#[no_mangle]
pub unsafe extern "C" fn tos_shielded_payment_prover_load(
    session: *const TosShieldedReplay,
    phase1: *const u8,
    phase1_len: usize,
    ceremony: *const u8,
    ceremony_len: usize,
) -> *mut PaymentProver {
    if session.is_null()
        || phase1.is_null()
        || ceremony.is_null()
        || !(1..=4096).contains(&phase1_len)
        || !(1..=4096).contains(&ceremony_len)
    {
        return ptr::null_mut();
    }
    let load = || {
        let path = |bytes| {
            let text = std::str::from_utf8(bytes).map_err(|_| Error::InvalidInput)?;
            let path = std::path::Path::new(text);
            if !path.is_absolute() || text.as_bytes().contains(&0) {
                return Err(Error::InvalidInput);
            }
            Ok(path)
        };
        let owner = unsafe { &*session };
        let phase1 = path(unsafe { slice::from_raw_parts(phase1, phase1_len) })?;
        let ceremony = path(unsafe { slice::from_raw_parts(ceremony, ceremony_len) })?;
        owner.load_payment_prover(
            phase1,
            ceremony,
            owner.receive_binding.as_ref().ok_or(Error::InvalidInput)?,
        )
    };
    match catch_unwind(AssertUnwindSafe(load)) {
        Ok(Ok(prover)) => Box::into_raw(Box::new(prover)),
        _ => ptr::null_mut(),
    }
}

/// Release a loaded proving handle.
///
/// # Safety
/// A non-null pointer must be a live handle returned by the load function.
/// Release each handle once, after all uses have ended.
#[cfg(all(unix, feature = "proving"))]
#[no_mangle]
pub unsafe extern "C" fn tos_shielded_payment_prover_free(prover: *mut PaymentProver) {
    if !prover.is_null() {
        drop(unsafe { Box::from_raw(prover) });
    }
}

/// Read-only builds cannot load a payment prover.
#[cfg(not(all(unix, feature = "proving")))]
#[no_mangle]
pub extern "C" fn tos_shielded_payment_prover_load(
    _session: *const TosShieldedReplay,
    _phase1: *const u8,
    _phase1_len: usize,
    _ceremony: *const u8,
    _ceremony_len: usize,
) -> *mut std::ffi::c_void {
    ptr::null_mut()
}

/// Read-only builds never allocate a payment prover.
#[cfg(not(all(unix, feature = "proving")))]
#[no_mangle]
pub extern "C" fn tos_shielded_payment_prover_free(_prover: *mut std::ffi::c_void) {}

/// Request a signed BR1 quote over loopback Tor. Call from a worker thread.
#[cfg(all(unix, feature = "proving"))]
///
/// # Safety
/// The session must be live and serialized. The request buffer must be valid
/// for its stated length and contain locally approved release and Bond pins.
#[no_mangle]
pub unsafe extern "C" fn tos_shielded_relay_offer_request(
    session: *const TosShieldedReplay,
    request: *const u8,
    length: usize,
) -> *mut RelayOffer {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct OfferRequest {
        release: br1_client::release::Release,
        bond_init: String,
        tor_port: u16,
        timeout_secs: u64,
        lifetime: u64,
    }
    if session.is_null() || request.is_null() || !(1..=MAX_REQUEST_BYTES).contains(&length) {
        return ptr::null_mut();
    }
    let call = || {
        let request: OfferRequest =
            serde_json::from_slice(unsafe { slice::from_raw_parts(request, length) })
                .map_err(|_| Error::InvalidInput)?;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .enable_time()
            .build()
            .map_err(|_| Error::InvalidInput)?;
        runtime.block_on(unsafe { &*session }.request_relay_offer(
            &request.release,
            &request.bond_init,
            request.tor_port,
            request.timeout_secs,
            request.lifetime,
        ))
    };
    match catch_unwind(AssertUnwindSafe(call)) {
        Ok(Ok(offer)) => Box::into_raw(Box::new(offer)),
        _ => ptr::null_mut(),
    }
}

/// Return only displayable offer details, with integer values as decimal strings.
///
/// # Safety
/// The offer must be live and must not be freed during this call.
#[cfg(all(unix, feature = "proving"))]
#[no_mangle]
pub unsafe extern "C" fn tos_shielded_relay_offer_info(
    offer: *const RelayOffer,
) -> *mut TosShieldedResponse {
    response(|| {
        let offer = unsafe { offer.as_ref() }.ok_or(Error::InvalidInput)?;
        serde_json::to_vec(&serde_json::json!({
            "identity": offer.identity(),
            "fee": offer.fee().to_string(),
            "valid_until": offer.valid_until().to_string(),
        }))
        .map(Zeroizing::new)
        .map_err(|_| Error::InvalidInput)
    })
}

/// Release an offer after confirmation, cancellation or expiry.
///
/// # Safety
/// A non-null offer must be live and no longer in use. Free each offer once.
#[cfg(all(unix, feature = "proving"))]
#[no_mangle]
pub unsafe extern "C" fn tos_shielded_relay_offer_free(offer: *mut RelayOffer) {
    if !offer.is_null() {
        drop(unsafe { Box::from_raw(offer) });
    }
}

/// Issue a descriptor only after committing its index in the canonical store.
///
/// # Safety
/// The session must be live and serialized. All input pointers must be valid
/// for their lengths. The caller authenticates freshness, the original master,
/// and the binding against the same observation used to create the replay.
#[cfg(unix)]
#[no_mangle]
pub unsafe extern "C" fn tos_shielded_replay_receive(
    session: *const TosShieldedReplay,
    seed: *const u8,
    seed_length: usize,
    root: *const u8,
    root_length: usize,
    binding: *const u8,
    binding_length: usize,
) -> *mut TosShieldedResponse {
    response(|| {
        if session.is_null()
            || seed.is_null()
            || root.is_null()
            || binding.is_null()
            || seed_length != 32
            || !(1..=4096).contains(&root_length)
            || binding_length != 228
        {
            return Err(Error::InvalidInput);
        }
        let owner = unsafe { &*session };
        let State::Ready(ledger) = &owner.state else {
            return Err(Error::InvalidInput);
        };
        let root = std::str::from_utf8(unsafe { slice::from_raw_parts(root, root_length) })
            .map_err(|_| Error::InvalidInput)?;
        if root.as_bytes().contains(&0) || !std::path::Path::new(root).is_absolute() {
            return Err(Error::InvalidInput);
        }
        let bytes = unsafe { slice::from_raw_parts(binding, binding_length) };
        let binding = owner.wallet_binding(bytes)?;
        let mut key = Zeroizing::new([0; 32]);
        key.copy_from_slice(unsafe { slice::from_raw_parts(seed, 32) });
        let recovered = crate::wallet::recover_complete(
            ledger.outputs(),
            ledger.published_nullifiers(),
            &key,
            owner.domain,
        )?;
        if !recovered.0.diagnostics.is_empty() {
            return Err(Error::InvalidInput);
        }
        let next = match recovered.0.notes.iter().map(|note| note.note_key_index).max() {
            Some(index) => index.checked_add(1).ok_or(Error::Limit)?,
            None => 0,
        };
        let mut store = crate::store::StateStore::open_wallet(
            std::path::Path::new(root),
            crate::sealed::RecordCipher::derive(&key, binding),
        )
        .map_err(|_| Error::InvalidInput)?;
        let indices = store.reserve_indices(Some(next), 1).map_err(|_| Error::InvalidInput)?;
        let index = indices.first().copied().ok_or(Error::InvalidInput)?;
        crate::issue_descriptor(&key, &shielded_pool_circuit::field::fr_to_be(&owner.domain), index)
            .map(Zeroizing::new)
    })
}

#[cfg(unix)]
#[no_mangle]
/// # Safety
/// Pointers must refer to live allocations of the stated lengths and the session must be serialized.
pub unsafe extern "C" fn tos_shielded_replay_pending_status(
    session: *const TosShieldedReplay,
    seed: *const u8,
    seed_length: usize,
    root: *const u8,
    root_length: usize,
    binding: *const u8,
    binding_length: usize,
) -> *mut TosShieldedResponse {
    response(|| {
        if session.is_null()
            || seed.is_null()
            || root.is_null()
            || binding.is_null()
            || seed_length != 32
            || !(1..=4096).contains(&root_length)
            || binding_length != 228
        {
            return Err(Error::InvalidInput);
        }
        let owner = unsafe { &*session };
        let State::Ready(ledger) = &owner.state else {
            return Err(Error::InvalidInput);
        };
        let root = std::str::from_utf8(unsafe { slice::from_raw_parts(root, root_length) })
            .map_err(|_| Error::InvalidInput)?;
        if root.as_bytes().contains(&0) || !std::path::Path::new(root).is_absolute() {
            return Err(Error::InvalidInput);
        }
        let bytes = unsafe { slice::from_raw_parts(binding, binding_length) };
        let binding = owner.wallet_binding(bytes)?;
        let mut key = Zeroizing::new([0; 32]);
        key.copy_from_slice(unsafe { slice::from_raw_parts(seed, 32) });
        let mut store = crate::store::StateStore::open_wallet(
            std::path::Path::new(root),
            crate::sealed::RecordCipher::derive(&key, binding),
        )
        .map_err(|_| Error::InvalidInput)?;
        let status = match store.pending_payment().map_err(|_| Error::InvalidInput)? {
            None => 0,
            Some(payment) if ledger.accepted_intents().contains(&payment.intent) => 2,
            Some(_) => 1,
        };
        Ok(Zeroizing::new(vec![status]))
    })
}

/// # Safety
/// The session and descriptor pointers must identify live allocations of the stated types and lengths.
#[no_mangle]
pub unsafe extern "C" fn tos_shielded_replay_validate_recipient(
    session: *const TosShieldedReplay,
    descriptor: *const u8,
    descriptor_len: usize,
) -> *mut TosShieldedResponse {
    response(|| {
        if session.is_null() || descriptor.is_null() || descriptor_len != DESCRIPTOR_BYTES {
            return Err(Error::InvalidInput);
        }
        let owner = unsafe { &*session };
        if !matches!(owner.state, State::Ready(_)) {
            return Err(Error::InvalidInput);
        }
        Descriptor::from_bytes(unsafe { slice::from_raw_parts(descriptor, descriptor_len) })
            .and_then(|recipient| recipient.validate_recipient(owner.domain))
            .map_err(|_| Error::InvalidInput)?;
        Ok(Zeroizing::new(Vec::new()))
    })
}

/// # Safety
/// Pointers must identify live allocations of the stated types and lengths.
#[no_mangle]
pub unsafe extern "C" fn tos_shielded_replay_intent_accepted(
    session: *const TosShieldedReplay,
    digest: *const u8,
    digest_len: usize,
) -> *mut TosShieldedResponse {
    response(|| {
        if session.is_null() || digest.is_null() || digest_len != 32 {
            return Err(Error::InvalidInput);
        }
        let State::Ready(ledger) = &unsafe { &*session }.state else {
            return Err(Error::InvalidInput);
        };
        let mut encoded = [0; 32];
        encoded.copy_from_slice(unsafe { slice::from_raw_parts(digest, digest_len) });
        let intent =
            shielded_pool_circuit::field::fr_from_be(&encoded).map_err(|_| Error::InvalidInput)?;
        Ok(Zeroizing::new(vec![u8::from(ledger.accepted_intents().contains(&intent))]))
    })
}

unsafe fn mutate(
    session: *mut TosShieldedReplay,
    operation: impl FnOnce(State) -> Result<State>,
) -> i32 {
    if session.is_null() {
        return 1;
    }
    let owner = unsafe { &mut *session };
    // Poison before entering any operation that can reject, mutate or unwind.
    let previous = std::mem::replace(&mut owner.state, State::Failed);
    match catch_unwind(AssertUnwindSafe(|| operation(previous))) {
        Ok(Ok(next)) => {
            owner.state = next;
            0
        }
        Ok(Err(_)) => 1,
        Err(_) => 2,
    }
}

/// # Safety
/// Session is live, exclusively owned and not concurrently used. BOC pointer is live for length.
#[no_mangle]
pub unsafe extern "C" fn tos_shielded_replay_push(
    session: *mut TosShieldedReplay,
    boc: *const u8,
    length: usize,
) -> i32 {
    unsafe {
        mutate(session, |old| {
            if boc.is_null() || length > MAX_REQUEST_BYTES {
                return Err(Error::InvalidInput);
            }
            let State::Building(mut replay) = old else {
                return Err(Error::InvalidInput);
            };
            replay.push(slice::from_raw_parts(boc, length))?;
            Ok(State::Building(replay))
        })
    }
}

/// # Safety
/// Session is live, exclusively owned and not concurrently used.
#[no_mangle]
pub unsafe extern "C" fn tos_shielded_replay_finish(session: *mut TosShieldedReplay) -> i32 {
    unsafe {
        mutate(session, |old| {
            let State::Building(replay) = old else {
                return Err(Error::InvalidInput);
            };
            Ok(State::Ready(Box::new(replay.finish()?)))
        })
    }
}

/// # Safety
/// Session is live and not concurrently mutated/freed.
#[no_mangle]
pub unsafe extern "C" fn tos_shielded_replay_info(
    session: *const TosShieldedReplay,
) -> *mut TosShieldedResponse {
    response(|| {
        if session.is_null() {
            return Err(Error::InvalidInput);
        }
        let State::Ready(ledger) = &unsafe { &*session }.state else {
            return Err(Error::InvalidInput);
        };
        let checkpoint = ledger.checkpoint();
        serde_json::to_vec(&serde_json::json!({"version":1,"total_outputs":ledger.outputs().len().to_string(),
            "commitment_root":hex::encode(shielded_pool_circuit::field::fr_to_be(&checkpoint.commitment_root)),
            "commitment_next_index":checkpoint.commitment_next_index.to_string(),
            "nullifier_root":hex::encode(shielded_pool_circuit::field::fr_to_be(&checkpoint.nullifier_root)),
            "nullifier_next_index":checkpoint.nullifier_next_index.to_string(),
            "reserved_recovery_leaves":checkpoint.reserved_recovery_leaves.to_string(),
            "native_liability":checkpoint.native_liability.to_string(),
            "withdrawal_fee": unsafe { &*session }.terms.withdrawal_fee.to_string(),
            "denominations": unsafe { &*session }.terms.denominations.iter().map(ToString::to_string).collect::<Vec<_>>()}))
            .map(Zeroizing::new).map_err(|_|Error::InvalidInput)
    })
}

/// # Safety
/// Session is live and not concurrently mutated/freed. Seed pointer is live for seed_length.
#[no_mangle]
pub unsafe extern "C" fn tos_shielded_replay_scan(
    session: *const TosShieldedReplay,
    seed: *const u8,
    seed_length: usize,
    offset: usize,
    count: usize,
) -> *mut TosShieldedResponse {
    response(|| {
        if session.is_null() || seed.is_null() || seed_length != 32 {
            return Err(Error::InvalidInput);
        }
        let mut key = Zeroizing::new([0; 32]);
        key.copy_from_slice(unsafe { slice::from_raw_parts(seed, 32) });
        unsafe { &*session }.scan(&key, offset, count)
    })
}

/// Complete global scan, not a sum of independent page balances.
/// # Safety
/// Session is live and serialized; seed points to seed_length readable bytes.
#[no_mangle]
pub unsafe extern "C" fn tos_shielded_replay_summary(
    session: *const TosShieldedReplay,
    seed: *const u8,
    seed_length: usize,
) -> *mut TosShieldedResponse {
    response(|| {
        if session.is_null() || seed.is_null() || seed_length != 32 {
            return Err(Error::InvalidInput);
        }
        let State::Ready(ledger) = &unsafe { &*session }.state else {
            return Err(Error::InvalidInput);
        };
        let mut key = Zeroizing::new([0; 32]);
        key.copy_from_slice(unsafe { slice::from_raw_parts(seed, 32) });
        crate::wallet::summary(ledger, &key, unsafe { &*session }.domain)
    })
}

/// # Safety
/// Non-null session is a live allocation from this library, freed exactly once without concurrent calls.
#[no_mangle]
pub unsafe extern "C" fn tos_shielded_replay_free(session: *mut TosShieldedReplay) {
    if !session.is_null() {
        drop(unsafe { Box::from_raw(session) });
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use shielded_pool_circuit::{notes, wire};
    use shielded_pool_wallet::{
        delivery::{self, Kind, Plaintext},
        ledger::{Event, Transact},
    };

    #[test]
    fn completed_scan_uses_the_full_published_nullifier_set() {
        // Synthetic ledger unit test, not transaction/proof execution evidence.
        let domain = Fr::from(7u64);
        let seed = [0x42; 32];
        let keys = PoolInstance::new(&seed, domain);
        let plain = Plaintext {
            slot: 0,
            kind: Kind::Ordinary,
            amount: 1000,
            note_secret: Fr::from(123u64),
            note_key_index: 7,
            owner_nf_key_hash: keys.owner_nf_key_hash(7).unwrap(),
            pq_auth_key_hash: keys.pq_auth_key_hash(7).unwrap(),
        };
        let payload =
            delivery::seal(&keys.mlkem_encapsulation_key().unwrap(), domain, &plain).unwrap();
        let owner = notes::owner_commitment(
            plain.owner_nf_key_hash,
            plain.pq_auth_key_hash,
            plain.note_secret,
        );
        let body = notes::note_body_commitment(
            owner,
            Fr::from(plain.amount),
            wire::output_data_hash(&payload),
        );
        let nullifier = notes::nullifier(body, keys.owner_nf_key(7).unwrap());
        let mut ledger = Ledger::genesis();
        ledger
            .apply(
                &Event::Deposit { amount: 1000, owner_commitment: owner, output_data: payload },
                0,
            )
            .unwrap();
        let before = TosShieldedReplay {
            state: State::Ready(Box::new(ledger.clone())),
            domain,
            receive_binding: None,
            terms: PoolTerms { denominations: vec![], withdrawal_fee: 1 },
        };
        let page: serde_json::Value =
            serde_json::from_slice(&before.scan(&seed, 0, 1).unwrap()).unwrap();
        assert_eq!(page["scan"]["batch_unspent_balance"], "1000");
        ledger
            .apply(
                &Event::Transact(Box::new(Transact {
                    intent_digest: Fr::from(77u64),
                    nullifiers: [nullifier, Fr::from(999u64)],
                    note_bodies: [Fr::from(11u64), Fr::from(12u64), Fr::from(13u64)],
                    payloads: std::array::from_fn(|_| vec![0; delivery::OUTPUT_DATA_BYTES]),
                    public_amount_out: 0,
                    withdrawal_fee: 0,
                    recovery_owner_commitment: Fr::from(0u64),
                    recovery_payload: None,
                    payout: None,
                })),
                0,
            )
            .unwrap();
        let after = TosShieldedReplay {
            state: State::Ready(Box::new(ledger)),
            domain,
            receive_binding: None,
            terms: PoolTerms { denominations: vec![], withdrawal_fee: 1 },
        };
        let page: serde_json::Value =
            serde_json::from_slice(&after.scan(&seed, 0, 1).unwrap()).unwrap();
        assert_eq!(page["scan"]["batch_unspent_balance"], "0");
        assert_eq!(page["scan"]["notes"][0]["spent"], true);
        let accepted = |session: &TosShieldedReplay, digest: &[u8; 32]| unsafe {
            Box::from_raw(tos_shielded_replay_intent_accepted(
                session,
                digest.as_ptr(),
                digest.len(),
            ))
        };
        let digest = shielded_pool_circuit::field::fr_to_be(&Fr::from(77u64));
        assert_eq!(&*accepted(&before, &digest).bytes, &[0]);
        assert_eq!(&*accepted(&after, &digest).bytes, &[1]);
        assert_eq!(accepted(&after, &[255; 32]).status, 1);
    }

    #[test]
    fn contained_mutator_panic_leaves_the_owner_failed() {
        // Deliberate test-only unwind through the same FFI ownership boundary.
        let mut owner = TosShieldedReplay {
            state: State::Ready(Box::new(Ledger::genesis())),
            domain: Fr::from(7u64),
            receive_binding: None,
            terms: PoolTerms { denominations: vec![], withdrawal_fee: 1 },
        };
        let result = unsafe {
            mutate(&mut owner, |_old| std::panic::resume_unwind(Box::new("injected test unwind")))
        };
        assert_eq!(result, 2);
        assert!(matches!(owner.state, State::Failed));
        assert_eq!(unsafe { tos_shielded_replay_finish(&mut owner) }, 1);
    }
    fn summary_json(owner: &TosShieldedReplay, seed: &[u8; 32]) -> serde_json::Value {
        let raw = unsafe { tos_shielded_replay_summary(owner, seed.as_ptr(), seed.len()) };
        assert!(!raw.is_null());
        let response = unsafe { Box::from_raw(raw) };
        assert_eq!(response.status, 0);
        serde_json::from_slice(&response.bytes).unwrap()
    }
    #[test]
    fn complete_summary_deduplicates_across_pages_and_keeps_same_index_distinct_notes() {
        // Real ML-KEM payloads on a synthetic ledger: no VM/proof execution claim.
        let seed = [42; 32];
        let domain = Fr::from(7u64);
        let keys = PoolInstance::new(&seed, domain);
        let make = |secret| {
            let plain = Plaintext {
                slot: 0,
                kind: Kind::Ordinary,
                amount: 1000,
                note_secret: Fr::from(secret),
                note_key_index: 7,
                owner_nf_key_hash: keys.owner_nf_key_hash(7).unwrap(),
                pq_auth_key_hash: keys.pq_auth_key_hash(7).unwrap(),
            };
            let payload =
                delivery::seal(&keys.mlkem_encapsulation_key().unwrap(), domain, &plain).unwrap();
            let owner = notes::owner_commitment(
                plain.owner_nf_key_hash,
                plain.pq_auth_key_hash,
                plain.note_secret,
            );
            let body = notes::note_body_commitment(
                owner,
                Fr::from(1000u64),
                wire::output_data_hash(&payload),
            );
            (Event::Deposit { amount: 1000, owner_commitment: owner, output_data: payload }, body)
        };
        let (event, body) = make(123u64);
        let mut ledger = Ledger::genesis();
        for _ in 0..513 {
            ledger.apply(&event, 0).unwrap();
        }
        let (second, _) = make(124u64);
        ledger.apply(&second, 0).unwrap();
        let before = TosShieldedReplay {
            state: State::Ready(Box::new(ledger.clone())),
            domain,
            receive_binding: None,
            terms: PoolTerms { denominations: vec![], withdrawal_fee: 1 },
        };
        let page_a: serde_json::Value =
            serde_json::from_slice(&before.scan(&seed, 0, 512).unwrap()).unwrap();
        let page_b: serde_json::Value =
            serde_json::from_slice(&before.scan(&seed, 512, 2).unwrap()).unwrap();
        assert_eq!(page_a["scan"]["batch_unspent_balance"], "1000");
        assert_eq!(page_b["scan"]["batch_unspent_balance"], "2000");
        let summary = summary_json(&before, &seed);
        assert_eq!(summary["unspent_balance"], "2000");
        assert_eq!(summary["owned_outputs"], "514");
        assert_eq!(summary["unique_unspent_notes"], "2");
        assert_eq!(summary["duplicate_outputs"], "512");
        assert_eq!(summary["reused_indices_count"], "1");
        assert_eq!(summary["scan_next_index"], "8");
        let summary_keys: std::collections::BTreeSet<_> =
            summary.as_object().unwrap().keys().map(String::as_str).collect();
        assert_eq!(
            summary_keys,
            [
                "version",
                "total_outputs",
                "owned_outputs",
                "unique_unspent_notes",
                "duplicate_outputs",
                "reused_indices_count",
                "diagnostics_count",
                "unspent_balance",
                "scan_next_index"
            ]
            .into_iter()
            .collect()
        );
        let nullifier = notes::nullifier(body, keys.owner_nf_key(7).unwrap());
        ledger
            .apply(
                &Event::Transact(Box::new(Transact {
                    intent_digest: Fr::from(77u64),
                    nullifiers: [nullifier, Fr::from(999u64)],
                    note_bodies: [Fr::from(11u64), Fr::from(12u64), Fr::from(13u64)],
                    payloads: std::array::from_fn(|_| vec![0; delivery::OUTPUT_DATA_BYTES]),
                    public_amount_out: 0,
                    withdrawal_fee: 0,
                    recovery_owner_commitment: Fr::from(0u64),
                    recovery_payload: None,
                    payout: None,
                })),
                0,
            )
            .unwrap();
        let after = TosShieldedReplay {
            state: State::Ready(Box::new(ledger)),
            domain,
            receive_binding: None,
            terms: PoolTerms { denominations: vec![], withdrawal_fee: 1 },
        };
        let summary = summary_json(&after, &seed);
        assert_eq!(summary["unspent_balance"], "1000");
        assert_eq!(summary["unique_unspent_notes"], "1");
        assert_eq!(summary["scan_next_index"], "8");
    }
    #[test]
    fn recipient_validation_requires_ready_pool_and_canonical_key() {
        let domain = wire::execution_domain(3, &[1; 32]);
        let mut owner = TosShieldedReplay {
            state: State::Ready(Box::new(Ledger::genesis())),
            domain,
            receive_binding: None,
            terms: PoolTerms { denominations: vec![], withdrawal_fee: 1 },
        };
        let issue = |domain| {
            crate::issue_descriptor(&[42; 32], &shielded_pool_circuit::field::fr_to_be(&domain), 0)
                .unwrap()
        };
        let validate = |owner: &TosShieldedReplay, bytes: &[u8]| unsafe {
            Box::from_raw(tos_shielded_replay_validate_recipient(
                owner,
                bytes.as_ptr(),
                bytes.len(),
            ))
        };
        let good = issue(domain);
        let recipient = Descriptor::from_bytes(&good).unwrap();
        let other_pool =
            Descriptor::from_bytes(&issue(wire::execution_domain(3, &[2; 32]))).unwrap();
        let fee_recipient = Descriptor::issue(&PoolInstance::new(&[43; 32], domain), 0).unwrap();
        use shielded_pool_wallet::plan::Request;
        let request = Request::relayed_transfer(domain, &recipient, 10, &fee_recipient, 1).unwrap();
        let mut index_requested = false;
        assert!(shielded_pool_wallet::plan::plan_recovered(
            &owner.terms,
            &Default::default(),
            &Default::default(),
            &request,
            &mut || {
                index_requested = true;
                Ok(0)
            },
        )
        .is_err());
        assert!(!index_requested);
        assert!(Request::relayed_transfer(domain, &recipient, 10, &other_pool, 1).is_err());
        assert!(Request::relayed_transfer(domain, &other_pool, 10, &fee_recipient, 1).is_err());

        let result = validate(&owner, &good);
        assert_eq!(result.status, 0);
        assert!(result.bytes.is_empty());
        assert_eq!(validate(&owner, &good[..good.len() - 1]).status, 1);
        assert_eq!(validate(&owner, &issue(wire::execution_domain(3, &[2; 32]))).status, 1);

        let mut malformed = good.clone();
        let kem_offset = DESCRIPTOR_BYTES - 1184;
        malformed[kem_offset..kem_offset + 3].fill(0xff);
        assert_eq!(validate(&owner, &malformed).status, 1);

        owner.state = State::Failed;
        assert_eq!(validate(&owner, &good).status, 1);
    }

    #[test]
    fn summary_requires_ready_and_exact_seed_and_allows_authentic_empty_ledger() {
        let seed = [42; 32];
        let domain = Fr::from(7u64);
        let mut owner = TosShieldedReplay {
            state: State::Failed,
            domain,
            receive_binding: None,
            terms: PoolTerms { denominations: vec![], withdrawal_fee: 1 },
        };
        for (session, key, length) in [
            (&owner as *const _, seed.as_ptr(), 32),
            (ptr::null(), seed.as_ptr(), 32),
            (&owner as *const _, ptr::null(), 32),
            (&owner as *const _, seed.as_ptr(), 31),
        ] {
            let raw = unsafe { tos_shielded_replay_summary(session, key, length) };
            let response = unsafe { Box::from_raw(raw) };
            assert_eq!(response.status, 1);
            assert!(response.bytes.is_empty());
        }
        owner.state = State::Ready(Box::new(Ledger::genesis()));
        let summary = summary_json(&owner, &seed);
        assert_eq!(summary["unspent_balance"], "0");
        assert_eq!(summary["total_outputs"], "0");
    }
    #[cfg(all(unix, feature = "proving"))]
    #[test]
    fn payment_prover_abi_rejects_invalid_inputs() {
        let owner = TosShieldedReplay {
            state: State::Ready(Box::new(Ledger::genesis())),
            domain: Fr::from(7u64),
            receive_binding: None,
            terms: PoolTerms { denominations: vec![], withdrawal_fee: 1 },
        };
        let absolute = b"/missing";
        for (session, path) in [
            (ptr::null(), absolute.as_slice()),
            (&owner as *const _, b"relative".as_slice()),
            (&owner as *const _, b"/bad\0path".as_slice()),
            (&owner as *const _, absolute.as_slice()),
        ] {
            let prover = unsafe {
                tos_shielded_payment_prover_load(
                    session,
                    path.as_ptr(),
                    path.len(),
                    absolute.as_ptr(),
                    absolute.len(),
                )
            };
            assert!(prover.is_null());
        }
        unsafe { tos_shielded_payment_prover_free(ptr::null_mut()) };
    }

    #[cfg(all(unix, feature = "proving"))]
    #[test]
    fn prover_rejects_wrong_binding_before_loading_material() {
        let mut binding = [1; 228];
        binding[..4].copy_from_slice(&3i32.to_be_bytes());
        let owner = TosShieldedReplay {
            state: State::Ready(Box::new(Ledger::genesis())),
            domain: wire::execution_domain(3, &[1; 32]),
            receive_binding: Some(binding),
            terms: PoolTerms { denominations: vec![], withdrawal_fee: 1 },
        };
        binding[164] ^= 1;
        let missing = std::path::Path::new("/nonexistent-proving-material");
        assert!(matches!(
            owner.load_payment_prover(missing, missing, &binding),
            Err(Error::InvalidInput)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn receive_reserves_before_return_and_survives_replay_restart() {
        use std::os::unix::fs::DirBuilderExt;
        let root = std::env::temp_dir().join(format!("tos-receive-{}", rand::random::<u64>()));
        std::fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
        struct Cleanup(std::path::PathBuf);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        let _cleanup = Cleanup(root.clone());
        let path = root.to_str().unwrap().as_bytes();
        let key = [42; 32];
        let mut binding = [1; 228];
        binding[..4].copy_from_slice(&3i32.to_be_bytes());
        let receive = |owner: &TosShieldedReplay, binding: &[u8]| unsafe {
            Box::from_raw(tos_shielded_replay_receive(
                owner,
                key.as_ptr(),
                key.len(),
                path.as_ptr(),
                path.len(),
                binding.as_ptr(),
                binding.len(),
            ))
        };
        let domain = wire::execution_domain(3, &[1; 32]);
        let failed = TosShieldedReplay {
            state: State::Failed,
            domain,
            receive_binding: Some(binding),
            terms: PoolTerms { denominations: vec![], withdrawal_fee: 1 },
        };
        assert_eq!(receive(&failed, &binding).status, 1);
        let make_ready = || TosShieldedReplay {
            state: State::Ready(Box::new(Ledger::genesis())),
            domain,
            receive_binding: Some(binding),
            terms: PoolTerms { denominations: vec![], withdrawal_fee: 1 },
        };
        let mut other_pool = binding;
        other_pool[4] = 2;
        assert_eq!(receive(&make_ready(), &other_pool).status, 1);
        assert_eq!(std::fs::read_dir(&root).unwrap().count(), 0);
        for index in [0, 1] {
            let result = receive(&make_ready(), &binding);
            assert_eq!(result.status, 0);
            let descriptor =
                shielded_pool_wallet::descriptor::Descriptor::from_bytes(&result.bytes).unwrap();
            assert_eq!(descriptor.note_key_index, index);
        }
        let keys = PoolInstance::new(&key, domain);
        let plain = Plaintext {
            slot: 0,
            kind: Kind::Ordinary,
            amount: 1000,
            note_secret: Fr::from(123u64),
            note_key_index: 7,
            owner_nf_key_hash: keys.owner_nf_key_hash(7).unwrap(),
            pq_auth_key_hash: keys.pq_auth_key_hash(7).unwrap(),
        };
        let payload =
            delivery::seal(&keys.mlkem_encapsulation_key().unwrap(), domain, &plain).unwrap();
        let commitment = notes::owner_commitment(
            plain.owner_nf_key_hash,
            plain.pq_auth_key_hash,
            plain.note_secret,
        );
        let mut ledger = Ledger::genesis();
        ledger
            .apply(
                &Event::Deposit {
                    amount: plain.amount,
                    owner_commitment: commitment,
                    output_data: payload,
                },
                0,
            )
            .unwrap();
        let mut observed = TosShieldedReplay {
            state: State::Ready(Box::new(ledger)),
            domain,
            receive_binding: Some(binding),
            terms: PoolTerms { denominations: vec![], withdrawal_fee: 1 },
        };
        for (owner, expected) in [(&observed, 8), (&make_ready(), 9)] {
            let result = receive(owner, &binding);
            assert_eq!(result.status, 0);
            let descriptor =
                shielded_pool_wallet::descriptor::Descriptor::from_bytes(&result.bytes).unwrap();
            assert_eq!(descriptor.note_key_index, expected);
        }
        let mut wrong_genesis = binding;
        wrong_genesis[36] ^= 1;
        let refused = receive(&make_ready(), &wrong_genesis);
        assert_eq!(refused.status, 1);
        assert!(refused.bytes.is_empty());
        let mut upgraded = binding;
        upgraded[100] = 2;
        let refused = receive(&make_ready(), &upgraded);
        assert_eq!(refused.status, 1);
        assert!(refused.bytes.is_empty());
        assert_eq!(std::fs::read_dir(&root).unwrap().count(), 1);
        let pending = |owner: &TosShieldedReplay, pins: &[u8]| unsafe {
            Box::from_raw(tos_shielded_replay_pending_status(
                owner,
                key.as_ptr(),
                key.len(),
                path.as_ptr(),
                path.len(),
                pins.as_ptr(),
                pins.len(),
            ))
        };
        assert_eq!(&*pending(&observed, &binding).bytes, &[0]);
        let open = || {
            crate::store::StateStore::open_wallet(
                &root,
                crate::sealed::RecordCipher::derive(
                    &key,
                    observed.wallet_binding(&binding).unwrap(),
                ),
            )
            .unwrap()
        };
        let intent = Fr::from(77u64);
        open().persist_pending_payment(intent, b"original submission").unwrap();
        assert_eq!(&*pending(&observed, &binding).bytes, &[1]);
        assert_eq!(pending(&observed, &wrong_genesis).status, 1);
        let recovered = open().pending_payment().unwrap().unwrap();
        assert_eq!(recovered.intent, intent);
        assert_eq!(recovered.request.as_slice(), b"original submission");
        let State::Ready(ledger) = &mut observed.state else { unreachable!() };
        ledger
            .apply(
                &Event::Transact(Box::new(Transact {
                    intent_digest: intent,
                    nullifiers: [Fr::from(998u64), Fr::from(999u64)],
                    note_bodies: [Fr::from(11u64), Fr::from(12u64), Fr::from(13u64)],
                    payloads: std::array::from_fn(|_| vec![0; delivery::OUTPUT_DATA_BYTES]),
                    public_amount_out: 0,
                    withdrawal_fee: 0,
                    recovery_owner_commitment: Fr::from(0u64),
                    recovery_payload: None,
                    payout: None,
                })),
                0,
            )
            .unwrap();
        assert_eq!(&*pending(&observed, &binding).bytes, &[2]);
    }
}
