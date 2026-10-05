// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-only
//! End-to-end payment route evidence, relative to locally pinned enrollment.
use crate::proven_transactions::{PaymentExpectation, ProvenTransaction};
use crate::wallet_v5r2_genesis::{SuccessorDeployment, WalletGenesis};
use chain_block::{Cell, Deserializable, MsgAddressInt, StateInit};

pub struct PaymentReceipts<'a> {
    pub fee: &'a ProvenTransaction,
    pub module: &'a ProvenTransaction,
    pub wallet: &'a ProvenTransaction,
    pub recipient: &'a ProvenTransaction,
    pub fee_before: Cell,
    pub module_before: Cell,
    pub wallet_before: Cell,
}

/// Immutable route/code pins derived from trusted local enrollment. This proves
/// historical delivery, not current wallet state, custody or replay safety.
pub struct PaymentRoute {
    addresses: [MsgAddressInt; 3],
    codes: [Cell; 3],
    fee_data: Cell,
    module_data: Cell,
}

impl PaymentRoute {
    pub fn initial(birth: &WalletGenesis) -> anyhow::Result<Self> {
        Self::from_inits(birth.vault_init(), birth.module_init(), birth.wallet_init())
    }
    pub fn successor(
        birth: &WalletGenesis,
        successor: &SuccessorDeployment,
    ) -> anyhow::Result<Self> {
        anyhow::ensure!(
            successor.wallet() == birth.wallet_init().repr_hash().as_array(),
            "payment route successor belongs to another wallet"
        );
        Self::from_inits(successor.vault_init(), successor.module_init(), birth.wallet_init())
    }
    pub(crate) fn from_inits(fee: &Cell, module: &Cell, wallet: &Cell) -> anyhow::Result<Self> {
        let addresses = [fee, module, wallet]
            .map(|cell| format!("0:{}", cell.repr_hash().to_hex_string()).parse::<MsgAddressInt>());
        let [fee_address, module_address, wallet_address] = addresses;
        let init = [fee, module, wallet].map(|cell| StateInit::construct_from_cell(cell.clone()));
        let [fee, module, wallet] = init;
        let (fee, module, wallet) = (fee?, module?, wallet?);
        Ok(Self {
            addresses: [fee_address?, module_address?, wallet_address?],
            codes: [
                fee.code.ok_or_else(|| anyhow::anyhow!("payment route fee code missing"))?,
                module.code.ok_or_else(|| anyhow::anyhow!("payment route module code missing"))?,
                wallet.code.ok_or_else(|| anyhow::anyhow!("payment route wallet code missing"))?,
            ],
            fee_data: fee.data.ok_or_else(|| anyhow::anyhow!("payment route fee data missing"))?,
            module_data: module
                .data
                .ok_or_else(|| anyhow::anyhow!("payment route module data missing"))?,
        })
    }
    pub fn require_payment(
        &self,
        receipts: &PaymentReceipts<'_>,
        submitted_external: &Cell,
        expected: &PaymentExpectation,
    ) -> anyhow::Result<()> {
        let hops = [receipts.fee, receipts.module, receipts.wallet];
        let before = [&receipts.fee_before, &receipts.module_before, &receipts.wallet_before];
        for (index, (receipt, state)) in hops.iter().zip(before).enumerate() {
            let account = receipt.pre_account(state.clone())?;
            anyhow::ensure!(
                account.get_addr() == Some(&self.addresses[index]),
                "payment route address mismatch"
            );
            anyhow::ensure!(
                account.get_code().as_ref() == Some(&self.codes[index]),
                "payment route executed code mismatch"
            );
            if index == 0 {
                let data = account
                    .get_data()
                    .ok_or_else(|| anyhow::anyhow!("payment vault data missing"))?;
                crate::wallet_v5r2_state::checked_counter(&data, &self.fee_data)?;
            } else if index == 1 {
                anyhow::ensure!(
                    account.get_data().as_ref() == Some(&self.module_data),
                    "payment route module keys mismatch"
                );
            }
        }
        receipts.fee.require_inbound(submitted_external)?;
        let input = receipts
            .fee
            .transaction()
            .read_in_msg()?
            .ok_or_else(|| anyhow::anyhow!("payment fee input missing"))?;
        anyhow::ensure!(
            input.is_inbound_external(),
            "payment route must begin with external input"
        );
        for (sender, receiver) in
            [(receipts.fee, receipts.module), (receipts.module, receipts.wallet)]
        {
            let message = receiver
                .transaction()
                .in_msg_cell()
                .ok_or_else(|| anyhow::anyhow!("payment route inbound missing"))?;
            sender.require_internal_delivery(receiver, message.repr_hash().as_array())?;
        }
        let wallet_input = receipts
            .wallet
            .transaction()
            .in_msg_cell()
            .ok_or_else(|| anyhow::anyhow!("payment wallet input missing"))?;
        let delivered = receipts
            .recipient
            .transaction()
            .in_msg_cell()
            .ok_or_else(|| anyhow::anyhow!("payment recipient input missing"))?;
        receipts.wallet.require_payment(
            receipts.recipient,
            &wallet_input,
            delivered.repr_hash().as_array(),
            expected,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proven_getters::transaction_receipt_tests::fixture;
    use chain_block::{Serializable, Transaction, TransactionDescr};

    #[test]
    fn payment_route_is_one_authenticated_request_chain() {
        let get = |name| {
            let (proof, root) = fixture(name);
            ProvenTransaction::latest(&proof, root).unwrap()
        };
        let fee = get("payment-fee");
        let module = get("payment-module");
        let wallet = get("payment-wallet");
        let recipient = get("recipient");
        let receipts = PaymentReceipts {
            fee: &fee,
            module: &module,
            wallet: &wallet,
            recipient: &recipient,
            fee_before: fixture("successor-pop-fee").0.root().clone(),
            module_before: fixture("successor-pop-module").0.root().clone(),
            wallet_before: fixture("migrate-wallet").0.root().clone(),
        };
        let deployed_init = |name| {
            Transaction::construct_from_cell(fixture(name).1)
                .unwrap()
                .read_in_msg()
                .unwrap()
                .unwrap()
                .state_init()
                .unwrap()
                .serialize()
                .unwrap()
        };
        let all: serde_json::Value =
            serde_json::from_str(include_str!("../tests/fixtures/v5r2/receipt-transactions.json"))
                .unwrap();
        let wallet_init = chain_block::read_single_root_boc(
            hex::decode(all["wallet_init_hex"].as_str().unwrap()).unwrap(),
        )
        .unwrap();
        let new_route = || {
            PaymentRoute::from_inits(
                &deployed_init("deploy-vault"),
                &deployed_init("deploy-module"),
                &wallet_init,
            )
            .unwrap()
        };
        let route = new_route();
        let message = recipient.transaction().read_in_msg().unwrap().unwrap();
        let header = message.int_header().unwrap();
        let TransactionDescr::Ordinary(description) =
            recipient.transaction().read_description().unwrap()
        else {
            panic!()
        };
        let intent = PaymentExpectation {
            recipient: header.dst.clone(),
            value: header.value.clone(),
            credited: description.credit_ph.unwrap().credit,
            bounce: header.bounce,
            body: message.body().cloned().map(|s| s.into_cell().unwrap()),
            state_init: message.state_init().cloned(),
        };
        let submitted = fee.transaction().in_msg_cell().unwrap();
        route.require_payment(&receipts, &submitted, &intent).unwrap();
        for case in ["address", "code", "keys", "fee_data"] {
            let mut wrong = new_route();
            match case {
                "address" => wrong.addresses[0] = format!("0:{}", "ab".repeat(32)).parse().unwrap(),
                "code" => wrong.codes[0] = Cell::default(),
                "keys" => wrong.module_data = Cell::default(),
                "fee_data" => wrong.fee_data = Cell::default(),
                _ => unreachable!(),
            }
            wrong
                .require_payment(&receipts, &submitted, &intent)
                .err()
                .unwrap_or_else(|| panic!("accepted payment route mismatch {case}"));
        }
        route
            .require_payment(&receipts, &Cell::default(), &intent)
            .err()
            .expect("accepted payment route unrelated submission");
        let unrelated = get("successor-pop-module");
        let mixed = PaymentReceipts {
            module: &unrelated,
            module_before: fixture("deploy-module").0.root().clone(),
            ..receipts
        };
        route
            .require_payment(&mixed, &submitted, &intent)
            .err()
            .expect("accepted spliced payment route");
    }
}
