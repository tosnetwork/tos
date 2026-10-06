// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-only
//! Wallet/module observations at one authenticated checkpoint. This is not a
//! transaction receipt or global primary-retirement policy proof.
use crate::proven_getters::ProvenAccountState;
use crate::wallet_v5r2::{AuthAction, AuthBinding, AuthRequest, AuthRole};
use crate::wallet_v5r2_genesis::{SuccessorDeployment, WalletGenesis};
use crate::wallet_v5r2_prepare::{PreparationAmounts, PreparationBinding, PreparationRequest};
use chain_block::{Cell, CellType, SliceData};

/// Both locally generated requests and their exact funded executions. Fetch
/// receipts and the current successor vault at the wallet's checkpoint.
pub struct MigrationEvidence<'a> {
    pub primary_request: &'a crate::wallet_v5r2_pop::PopRequest,
    pub primary_receipts: &'a crate::wallet_v5r2_pop::FundedPopReceipts<'a>,
    pub primary_external: &'a Cell,
    pub rescue_request: &'a crate::wallet_v5r2_pop::PopRequest,
    pub rescue_receipts: &'a crate::wallet_v5r2_pop::FundedPopReceipts<'a>,
    pub rescue_external: &'a Cell,
    pub vault: &'a ProvenAccountState,
    /// Supplied by the trusted local custody session, never inferred from chain state.
    pub fee_continuity: crate::lms_fee_schedule::Continuity,
    pub policy: Option<&'a ProvenAccountState>,
}

pub struct ProvenWalletState {
    checkpoint: crate::MasterchainCheckpoint,
    anchor_id: [u8; 32],
    global_id: i32,
    network: [u8; 32],
    wallet: [u8; 32],
    module: [u8; 32],
    seqno: u32,
    wallet_id: u32,
    retired: u16,
    epoch: u64,
    primary_nonce: u64,
    rescue_nonce: u64,
    policy: u8,
    primary_key: Vec<u8>,
    rescue_key: [u8; 32],
    module_code: [u8; 32],
    vault_code: [u8; 32],
    fee_metadata: Cell,
    master_time: u32,
    wallet_time: u32,
    module_time: u32,
    max_age: u32,
}

impl ProvenWalletState {
    /// The wallet must be a live read. Fetch the module at precisely that
    /// authenticated checkpoint (a historical read at that target is valid).
    pub fn bind_initial(
        wallet: &ProvenAccountState,
        module: &ProvenAccountState,
        birth: &WalletGenesis,
        now: u32,
        max_age: u32,
    ) -> anyhow::Result<Self> {
        Self::bind(
            wallet,
            module,
            birth,
            birth.module_init(),
            birth.module_data(),
            birth.metadata(),
            now,
            max_age,
        )
    }

    /// `birth` retains the wallet's original address/code identity. Recovery
    /// enrollment must name that same wallet and the actually installed tuple.
    pub fn bind_successor(
        wallet: &ProvenAccountState,
        module: &ProvenAccountState,
        birth: &WalletGenesis,
        successor: &SuccessorDeployment,
        now: u32,
        max_age: u32,
    ) -> anyhow::Result<Self> {
        anyhow::ensure!(
            successor.wallet() == birth.wallet_init().repr_hash().as_array(),
            "recovery enrollment belongs to another wallet"
        );
        Self::bind(
            wallet,
            module,
            birth,
            successor.module_init(),
            successor.module_data(),
            successor.metadata(),
            now,
            max_age,
        )
    }

    fn bind(
        wallet: &ProvenAccountState,
        module: &ProvenAccountState,
        birth: &WalletGenesis,
        module_init: &Cell,
        module_data: &Cell,
        metadata: &Cell,
        now: u32,
        max_age: u32,
    ) -> anyhow::Result<Self> {
        let w = wallet.evidence();
        let m = module.evidence();
        anyhow::ensure!(w.live, "wallet authorization needs a live proof");
        anyhow::ensure!(
            w.checkpoint == m.checkpoint && w.block_gen_utime == m.block_gen_utime,
            "wallet/module proof checkpoints differ"
        );
        let wallet_hash = *birth.wallet_init().repr_hash().as_array();
        let module_hash = *module_init.repr_hash().as_array();
        anyhow::ensure!(
            w.account.address == format!("0:{}", hex::encode(wallet_hash)),
            "wallet address differs from enrollment"
        );
        anyhow::ensure!(
            m.account.address == format!("0:{}", hex::encode(module_hash)),
            "module address differs from enrollment"
        );
        let wallet_code =
            SliceData::load_cell(birth.wallet_init().clone())?.checked_drain_reference()?;
        let old_module_code =
            SliceData::load_cell(birth.module_init().clone())?.checked_drain_reference()?;
        let module_code = SliceData::load_cell(module_init.clone())?.checked_drain_reference()?;
        anyhow::ensure!(
            w.account.code_hash == wallet_code.repr_hash().to_hex_string()
                && m.account.code_hash == module_code.repr_hash().to_hex_string()
                && module_code.repr_hash() == old_module_code.repr_hash(),
            "wallet/module code mismatch"
        );
        anyhow::ensure!(
            m.account.data_hash == module_data.repr_hash().to_hex_string(),
            "deployed module data mismatch"
        );
        let data =
            wallet.account().get_data().ok_or_else(|| anyhow::anyhow!("wallet has no data"))?;
        let mut s = ordinary(&data)?;
        anyhow::ensure!(
            s.remaining_bits() == 322 && s.remaining_references() == 1,
            "wallet data shape"
        );
        anyhow::ensure!(!s.get_next_bit()?, "classic authorization flag enabled");
        let seqno = s.get_next_u32()?;
        let wallet_id = s.get_next_u32()?;
        anyhow::ensure!(*s.get_next_hash()?.as_array() == [0; 32], "classic key must be inert");
        anyhow::ensure!(!s.get_next_bit()?, "legacy extensions are unsupported");
        let mut original = SliceData::load_cell(birth.wallet_data().clone())?;
        original.move_by(33)?;
        anyhow::ensure!(wallet_id == original.get_next_u32()?, "wallet id changed");
        let auth = s.checked_drain_reference()?;
        let mut auth = ordinary(&auth)?;
        anyhow::ensure!(
            auth.remaining_bits() == 218 && auth.remaining_references() == 2,
            "wallet AUTH shape"
        );
        anyhow::ensure!(
            auth.get_next_byte()? == 4 && auth.get_next_int(2)? == 2,
            "wallet requires PQ mode 2"
        );
        let retired = auth.get_next_u16()?;
        let epoch = auth.get_next_u64()?;
        let primary_nonce = auth.get_next_u64()?;
        let rescue_nonce = auth.get_next_u64()?;
        anyhow::ensure!(
            auth.checked_drain_reference()?.repr_hash() == module_init.repr_hash()
                && auth.checked_drain_reference()?.repr_hash() == metadata.repr_hash(),
            "wallet installed module/fee tuple mismatch"
        );
        let mut md = SliceData::load_cell(module_data.clone())?;
        md.move_by(8)?;
        let global_id = i32::from_be_bytes(md.get_next_u32()?.to_be_bytes());
        let network = *md.get_next_hash()?.as_array();
        let mut original = SliceData::load_cell(birth.module_data().clone())?;
        original.move_by(8)?;
        anyhow::ensure!(
            original.get_next_u32()?.to_be_bytes() == global_id.to_be_bytes()
                && original.get_next_hash()?.as_array() == &network,
            "recovery namespace mismatch"
        );
        md.move_by(8)?;
        let rescue_key = *md.get_next_hash()?.as_array();
        let policy = md.get_next_byte()?;
        let primary_key = primary_key_bytes(md.checked_drain_reference()?)?;
        let result = Self {
            checkpoint: w.checkpoint.clone(),
            anchor_id: *wallet.anchor_id(),
            global_id,
            network,
            wallet: wallet_hash,
            module: module_hash,
            seqno,
            wallet_id,
            retired,
            epoch,
            primary_nonce,
            rescue_nonce,
            policy,
            primary_key,
            rescue_key,
            module_code: *module_code.repr_hash().as_array(),
            vault_code: *SliceData::load_cell(birth.vault_init().clone())?
                .checked_drain_reference()?
                .repr_hash()
                .as_array(),
            fee_metadata: metadata.clone(),
            master_time: w.block_gen_utime,
            wallet_time: w.account.gen_utime,
            module_time: m.account.gen_utime,
            max_age,
        };
        result.fresh(now)?;
        Ok(result)
    }

    fn fresh(&self, now: u32) -> anyhow::Result<()> {
        anyhow::ensure!((1..3600).contains(&self.max_age), "wallet proof age policy out of range");
        for time in [self.master_time, self.wallet_time, self.module_time] {
            let age = now
                .checked_sub(time)
                .ok_or_else(|| anyhow::anyhow!("wallet proof time is in the future"))?;
            anyhow::ensure!(age <= self.max_age, "stale wallet/module proof");
        }
        Ok(())
    }
    pub fn seqno(&self) -> u32 {
        self.seqno
    }
    pub fn wallet_id(&self) -> u32 {
        self.wallet_id
    }
    pub fn epoch(&self) -> u64 {
        self.epoch
    }
    pub fn primary_nonce(&self) -> u64 {
        self.primary_nonce
    }
    pub fn rescue_nonce(&self) -> u64 {
        self.rescue_nonce
    }
    pub fn retired(&self) -> u16 {
        self.retired
    }
    pub fn primary_public_key(&self) -> &[u8] {
        &self.primary_key
    }
    pub fn rescue_public_key(&self) -> &[u8; 32] {
        &self.rescue_key
    }

    /// Sign only after caller approval of the actions. All request identity,
    /// counters, policy and expected key come from this authenticated snapshot.
    /// This neither reserves a nonce nor submits a transaction.
    #[cfg(feature = "native-wallet-signer")]
    pub fn sign_primary_submission(
        &self,
        policy_source: &ProvenAccountState,
        now: u32,
        valid_until: u32,
        actions: Cell,
        signer: &mut wallet_pq_signer::Signer,
    ) -> anyhow::Result<Cell> {
        let request = self.primary_request(policy_source, now, valid_until, actions)?;
        self.sign_submission(request, signer)
    }

    /// Policy-independent rescue signing. Migration uses the separate funded
    /// dual-POP gate below. Caller approval is still required; no transport is implied.
    #[cfg(feature = "native-wallet-signer")]
    pub fn sign_rescue_submission(
        &self,
        now: u32,
        valid_until: u32,
        action: AuthAction,
        signer: &mut wallet_pq_signer::Signer,
    ) -> anyhow::Result<Cell> {
        anyhow::ensure!(
            !matches!(action, AuthAction::Migrate { .. }),
            "migration signing requires both funded POPs"
        );
        // Fee-only rollover uses the same-root migration API and its funded
        // successor/custody checks; a raw Configure must not bypass them.
        anyhow::ensure!(
            !matches!(action, AuthAction::Configure { fee_replacement: Some(_) }),
            "fee replacement signing requires funded successor POPs"
        );
        let request = self.rescue_request(now, valid_until, action)?;
        self.sign_submission(request, signer)
    }

    #[cfg(feature = "native-wallet-signer")]
    fn sign_submission(
        &self,
        request: AuthRequest,
        signer: &mut wallet_pq_signer::Signer,
    ) -> anyhow::Result<Cell> {
        let (role, key): (_, &[u8]) = match request.role() {
            AuthRole::Primary => (wallet_pq_signer::Role::Primary, &self.primary_key),
            AuthRole::Rescue => (wallet_pq_signer::Role::Rescue, &self.rescue_key),
        };
        let signature =
            signer.sign_bound(role, key, wallet_pq_signer::Purpose::Auth, request.digest())?;
        request.encode_submission(&signature)
    }
    /// Local state only. Global ConfigParam 48 must ALSO authorize PRIMARY;
    /// this boolean is never sufficient permission to sign a primary request.
    pub fn primary_locally_enabled(&self) -> bool {
        self.policy == 1 && self.retired & 2 == 0
    }

    /// Build a preparation for the exact typed successor tuple. The caller
    /// approves amounts and verifies current fee floors/caps separately. This
    /// does not deploy anything or establish successor key possession.
    pub fn preparation_request(
        &self,
        now: u32,
        valid_until: u32,
        successor: &SuccessorDeployment,
        amounts: PreparationAmounts,
        policy_source: Option<&ProvenAccountState>,
    ) -> anyhow::Result<PreparationRequest> {
        self.fresh(now)?;
        anyhow::ensure!(valid_until > now, "preparation deadline expired by local clock");
        self.validate_successor(successor, policy_source, now)?;
        PreparationRequest::new(
            PreparationBinding {
                global_id: self.global_id,
                network: self.network,
                wallet: self.wallet,
                source_module: self.module,
                valid_until,
            },
            successor.preparation_plan(amounts.module, amounts.vault),
            self.module_time,
        )
    }

    fn validate_successor(
        &self,
        successor: &SuccessorDeployment,
        policy_source: Option<&ProvenAccountState>,
        now: u32,
    ) -> anyhow::Result<()> {
        anyhow::ensure!(successor.wallet() == &self.wallet, "preparation targets another wallet");
        let module_code =
            SliceData::load_cell(successor.module_init().clone())?.checked_drain_reference()?;
        let vault_code =
            SliceData::load_cell(successor.vault_init().clone())?.checked_drain_reference()?;
        anyhow::ensure!(
            module_code.repr_hash().as_array() == &self.module_code,
            "successor module code mismatch"
        );
        anyhow::ensure!(
            vault_code.repr_hash().as_array() == &self.vault_code,
            "successor vault code mismatch"
        );
        let mut data = SliceData::load_cell(successor.module_data().clone())?;
        data.move_by(8)?;
        let global_id = i32::from_be_bytes(data.get_next_u32()?.to_be_bytes());
        let network = *data.get_next_hash()?.as_array();
        anyhow::ensure!(
            global_id == self.global_id && network == self.network,
            "successor namespace mismatch"
        );
        data.move_by(8 + 256)?;
        match data.get_next_byte()? {
            1 => self.require_global_primary(
                policy_source
                    .ok_or_else(|| anyhow::anyhow!("successor READY requires proven policy"))?,
                now,
            )?,
            2 => (),
            _ => anyhow::bail!("unsupported successor policy"),
        }
        successor.require_fresh_fee_key(&self.fee_metadata)?;
        Ok(())
    }

    /// Build migration only after both keys proved funded possession through
    /// this exact successor route. Historical POPs must be recent under the
    /// wallet's age policy and authenticated at this same checkpoint.
    pub fn migration_request(
        &self,
        now: u32,
        valid_until: u32,
        successor: &SuccessorDeployment,
        evidence: &MigrationEvidence<'_>,
    ) -> anyhow::Result<AuthRequest> {
        self.fresh(now)?;
        self.validate_successor(successor, evidence.policy, now)?;
        anyhow::ensure!(
            evidence.primary_request.role() == AuthRole::Primary
                && evidence.rescue_request.role() == AuthRole::Rescue,
            "migration requires one POP for each key"
        );
        for receipt in [
            evidence.primary_receipts.fee,
            evidence.primary_receipts.module,
            evidence.rescue_receipts.fee,
            evidence.rescue_receipts.module,
        ] {
            receipt.require_checkpoint(&self.checkpoint, &self.anchor_id)?;
            let age = now
                .checked_sub(receipt.transaction().now())
                .ok_or_else(|| anyhow::anyhow!("migration POP time is in the future"))?;
            anyhow::ensure!(age <= self.max_age, "stale migration POP");
        }
        anyhow::ensure!(
            evidence.vault.evidence().checkpoint == self.checkpoint
                && evidence.vault.evidence().block_gen_utime == self.master_time
                && evidence.vault.anchor_id() == &self.anchor_id,
            "migration vault checkpoint mismatch"
        );
        let fee = crate::wallet_v5r2_state::ProvenFeeVault::bind_successor(
            evidence.vault,
            successor,
            now,
            self.max_age,
        )?;
        fee.plan(now, evidence.fee_continuity)?;
        evidence.primary_request.require_successor_funded_receipt(
            evidence.primary_receipts,
            evidence.primary_external,
            successor,
        )?;
        evidence.rescue_request.require_successor_funded_receipt(
            evidence.rescue_receipts,
            evidence.rescue_external,
            successor,
        )?;
        self.rescue_request(
            now,
            valid_until,
            AuthAction::Migrate {
                module_init: successor.module_init().clone(),
                metadata: successor.metadata().clone(),
                vault_init: successor.vault_init().clone(),
            },
        )
    }

    /// Sign the gated migration with the currently installed SLH key. This
    /// does not submit, reserve a fee leaf, or prove completed migration.
    #[cfg(feature = "native-wallet-signer")]
    pub fn sign_migration_submission(
        &self,
        now: u32,
        valid_until: u32,
        successor: &SuccessorDeployment,
        evidence: &MigrationEvidence<'_>,
        signer: &mut wallet_pq_signer::Signer,
    ) -> anyhow::Result<Cell> {
        self.sign_submission(self.migration_request(now, valid_until, successor, evidence)?, signer)
    }

    /// SLH-only preparation signing from the current installed module. It
    /// remains available after primary retirement and counter exhaustion.
    #[cfg(feature = "native-wallet-signer")]
    pub fn sign_preparation_submission(
        &self,
        now: u32,
        valid_until: u32,
        successor: &SuccessorDeployment,
        amounts: PreparationAmounts,
        policy_source: Option<&ProvenAccountState>,
        signer: &mut wallet_pq_signer::Signer,
    ) -> anyhow::Result<Cell> {
        let request =
            self.preparation_request(now, valid_until, successor, amounts, policy_source)?;
        let signature = signer.sign_bound(
            wallet_pq_signer::Role::Rescue,
            &self.rescue_key,
            wallet_pq_signer::Purpose::Preparation,
            request.digest(),
        )?;
        request.encode_submission(&signature)
    }

    fn require_global_primary(
        &self,
        policy_source: &ProvenAccountState,
        now: u32,
    ) -> anyhow::Result<()> {
        anyhow::ensure!(
            policy_source.evidence().checkpoint == self.checkpoint
                && policy_source.evidence().block_gen_utime == self.master_time,
            "retirement policy checkpoint mismatch"
        );
        let policy = policy_source
            .config_param(48)
            .ok_or_else(|| anyhow::anyhow!("proven ConfigParam 48 is missing"))?;
        crate::wallet_v5r2_policy::require_primary(policy, &self.network, now)
    }

    /// Construct a PRIMARY execute request only with ConfigParam 48 proven at
    /// this exact wallet checkpoint. An old or absent policy never authorizes it.
    /// This still does not approve actions or invoke a signer.
    pub fn primary_request(
        &self,
        policy_source: &ProvenAccountState,
        now: u32,
        valid_until: u32,
        actions: Cell,
    ) -> anyhow::Result<AuthRequest> {
        self.fresh(now)?;
        anyhow::ensure!(valid_until > now, "primary deadline expired by local clock");
        anyhow::ensure!(self.primary_locally_enabled(), "wallet locally requires rescue");
        self.require_global_primary(policy_source, now)?;
        anyhow::ensure!(
            self.primary_nonce < u64::MAX && self.seqno < u32::MAX,
            "primary execute counter exhausted"
        );
        AuthRequest::new(
            AuthBinding {
                global_id: self.global_id,
                network: self.network,
                account: self.wallet,
                module: self.module,
                epoch: self.epoch,
                nonce: self.primary_nonce,
                valid_until,
            },
            AuthRole::Primary,
            AuthAction::Execute { actions },
            self.wallet_time,
        )
    }

    /// Build the SLH request from current counters. This does not approve the
    /// requested action, validate migration delivery/POP, or invoke a signer.
    /// This rescue path does not depend on the global primary-retirement policy.
    pub fn rescue_request(
        &self,
        now: u32,
        valid_until: u32,
        action: AuthAction,
    ) -> anyhow::Result<AuthRequest> {
        self.fresh(now)?;
        anyhow::ensure!(valid_until > now, "rescue deadline expired by local clock");
        match &action {
            AuthAction::Execute { .. } => {
                anyhow::ensure!(self.rescue_nonce < u64::MAX, "rescue nonce exhausted");
                anyhow::ensure!(self.seqno < u32::MAX, "wallet seqno exhausted");
            }
            AuthAction::Configure { .. } => {
                anyhow::ensure!(self.seqno < u32::MAX, "wallet seqno exhausted");
                anyhow::ensure!(self.epoch < u64::MAX, "wallet epoch exhausted");
            }
            AuthAction::LockPrimary | AuthAction::Migrate { .. } => {
                anyhow::ensure!(self.epoch < u64::MAX, "wallet epoch exhausted");
            }
        }
        AuthRequest::new(
            AuthBinding {
                global_id: self.global_id,
                network: self.network,
                account: self.wallet,
                module: self.module,
                epoch: self.epoch,
                nonce: self.rescue_nonce,
                valid_until,
            },
            AuthRole::Rescue,
            action,
            self.wallet_time,
        )
    }
}

pub(crate) fn primary_key_bytes(mut key_cell: Cell) -> anyhow::Result<Vec<u8>> {
    let mut bytes = Vec::with_capacity(1312);
    while bytes.len() < 1312 {
        let remaining = 1312usize
            .checked_sub(bytes.len())
            .ok_or_else(|| anyhow::anyhow!("primary key length overflow"))?;
        let chunk = remaining.min(127);
        let mut key = ordinary(&key_cell)?;
        anyhow::ensure!(
            key.remaining_bits()
                == chunk.checked_mul(8).ok_or_else(|| anyhow::anyhow!("key bits overflow"))?
                && key.remaining_references() == usize::from(remaining > 127),
            "noncanonical enrolled primary key"
        );
        bytes.extend(key.get_next_bytes(chunk)?);
        if remaining > 127 {
            key_cell = key.checked_drain_reference()?;
        }
    }
    Ok(bytes)
}

fn ordinary(cell: &Cell) -> anyhow::Result<SliceData> {
    anyhow::ensure!(
        cell.cell_type() == CellType::Ordinary && cell.level() == 0,
        "ordinary wallet state required"
    );
    SliceData::load_cell(cell.clone())
}
