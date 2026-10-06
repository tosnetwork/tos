//! Every flag that takes an account address accepts a raw masterchain address,
//! `-1:<hex>`, as its own token. Without `allow_hyphen_values` clap reads the
//! value as a short flag and the command a tool printed for an operator to paste
//! fails to parse.
use clap::{Args, Command};

const MASTERCHAIN: &str = "-1:5555555555555555555555555555555555555555555555555555555555555555";

/// `None` when `--<flag> -1:<hex>` gives the flag exactly that value; otherwise
/// what went wrong. Other required arguments are not supplied, so errors about
/// them are ignored.
fn check<T: Args>(name: &str, id: &str) -> Option<String> {
    let command = T::augment_args(Command::new("t")).ignore_errors(true);
    let Some(long) = command
        .get_arguments()
        .find(|arg| arg.get_id().as_str() == id)
        .and_then(|arg| arg.get_long())
        .map(str::to_owned)
    else {
        return Some(format!("{name}: no long flag for {id}"));
    };
    let flag = format!("--{long}");
    match command.try_get_matches_from(["t", flag.as_str(), MASTERCHAIN]) {
        Ok(matches) => {
            let raw: Option<Vec<String>> = matches
                .get_raw(id)
                .map(|values| values.map(|v| v.to_string_lossy().into_owned()).collect());
            if raw.as_deref() == Some(&[MASTERCHAIN.to_owned()][..]) {
                None
            } else {
                Some(format!("{name} {flag}: parsed as {raw:?}"))
            }
        }
        Err(error) => Some(format!("{name} {flag}: {}", error.kind())),
    }
}

#[test]
fn every_address_flag_accepts_a_raw_masterchain_address() {
    let failures: Vec<String> = [
        check::<super::account_cmd::AccountStatusCmd>("account_cmd::AccountStatusCmd", "address"),
        check::<super::account_cmd::AccountCapabilityCmd>(
            "account_cmd::AccountCapabilityCmd",
            "address",
        ),
        check::<super::account_cmd::AccountDelegationsCmd>(
            "account_cmd::AccountDelegationsCmd",
            "address",
        ),
        check::<super::account_cmd::AccountSessionsCmd>(
            "account_cmd::AccountSessionsCmd",
            "address",
        ),
        check::<super::account_cmd::AccountAgentsCmd>("account_cmd::AccountAgentsCmd", "address"),
        check::<super::account_cmd::AccountTxsCmd>("account_cmd::AccountTxsCmd", "address"),
        check::<super::account_cmd::AccountBookmarkAddCmd>(
            "account_cmd::AccountBookmarkAddCmd",
            "address",
        ),
        check::<super::account_cmd::AccountRunMethodCmd>(
            "account_cmd::AccountRunMethodCmd",
            "address",
        ),
        check::<super::account_cmd::AccountDelegationGrantCmd>(
            "account_cmd::AccountDelegationGrantCmd",
            "address",
        ),
        check::<super::account_cmd::AccountDelegationRevokeCmd>(
            "account_cmd::AccountDelegationRevokeCmd",
            "address",
        ),
        check::<super::account_cmd::AccountSessionGrantCmd>(
            "account_cmd::AccountSessionGrantCmd",
            "address",
        ),
        check::<super::account_cmd::AccountSessionRevokeCmd>(
            "account_cmd::AccountSessionRevokeCmd",
            "address",
        ),
        check::<super::account_cmd::AccountAgentGrantCmd>(
            "account_cmd::AccountAgentGrantCmd",
            "address",
        ),
        check::<super::account_cmd::AccountAgentRevokeCmd>(
            "account_cmd::AccountAgentRevokeCmd",
            "address",
        ),
        check::<super::agent_cmd::AgentTaskSendCmd>("agent_cmd::AgentTaskSendCmd", "address"),
        check::<super::agent_cmd::AgentTaskShowCmd>("agent_cmd::AgentTaskShowCmd", "address"),
        check::<super::agent_cmd::AgentAccountTaskSendCmd>(
            "agent_cmd::AgentAccountTaskSendCmd",
            "target",
        ),
        check::<super::agent_cmd::AgentAccountNativePrepareCmd>(
            "agent_cmd::AgentAccountNativePrepareCmd",
            "target",
        ),
        check::<super::agent_cmd::AgentAccountEconomicPaymentPrepareCmd>(
            "agent_cmd::AgentAccountEconomicPaymentPrepareCmd",
            "target",
        ),
        check::<super::agent_cmd::AgentAccountEconomicEffectPrepareCmd>(
            "agent_cmd::AgentAccountEconomicEffectPrepareCmd",
            "target",
        ),
        check::<super::agent_cmd::AgentWalletSendCmd>("agent_cmd::AgentWalletSendCmd", "to"),
        check::<super::capability_registry_cmd::CapabilityRegistryDeployCmd>(
            "capability_registry_cmd::CapabilityRegistryDeployCmd",
            "owner",
        ),
        check::<super::capability_registry_cmd::CapabilityRegistryLsCmd>(
            "capability_registry_cmd::CapabilityRegistryLsCmd",
            "owner",
        ),
        check::<super::capability_registry_cmd::CapabilityRegistryShowCmd>(
            "capability_registry_cmd::CapabilityRegistryShowCmd",
            "address",
        ),
        check::<super::capability_registry_cmd::CapabilityRegistrySendCmd>(
            "capability_registry_cmd::CapabilityRegistrySendCmd",
            "address",
        ),
        check::<super::capability_registry_cmd::CapabilityRegistryBuildStateCmd>(
            "capability_registry_cmd::CapabilityRegistryBuildStateCmd",
            "owner",
        ),
        check::<super::config_pool_cmd::PoolAddCmd>("config_pool_cmd::PoolAddCmd", "address"),
        check::<super::config_pool_cmd::PoolAddCmd>("config_pool_cmd::PoolAddCmd", "owner"),
        check::<super::config_pool_cmd::PoolAddCmd>("config_pool_cmd::PoolAddCmd", "controller"),
        check::<super::config_wallet_cmd::WalletSendCmd>("config_wallet_cmd::WalletSendCmd", "to"),
        check::<super::deploy_cmd::DeployPoolCmd>("deploy_cmd::DeployPoolCmd", "owner"),
        check::<super::deploy_cmd::DeployPoolCmd>("deploy_cmd::DeployPoolCmd", "controller"),
        check::<super::deploy_cmd::DeployContractCmd>("deploy_cmd::DeployContractCmd", "address"),
        check::<super::dispute_cmd::DisputeDeployCmd>("dispute_cmd::DisputeDeployCmd", "claimant"),
        check::<super::dispute_cmd::DisputeDeployCmd>(
            "dispute_cmd::DisputeDeployCmd",
            "respondent",
        ),
        check::<super::dispute_cmd::DisputeShowCmd>("dispute_cmd::DisputeShowCmd", "address"),
        check::<super::dispute_cmd::DisputeSendCmd>("dispute_cmd::DisputeSendCmd", "address"),
        check::<super::pool_cmd::PoolImportCmd>("pool_cmd::PoolImportCmd", "address"),
        check::<super::pool_cmd::PoolImportCmd>("pool_cmd::PoolImportCmd", "controller"),
        check::<super::pool_cmd::PoolNominatorCreateCmd>(
            "pool_cmd::PoolNominatorCreateCmd",
            "owner",
        ),
        check::<super::pool_cmd::PoolNominatorCreateCmd>(
            "pool_cmd::PoolNominatorCreateCmd",
            "validator",
        ),
        check::<super::pool_cmd::PoolNominatorCreateCmd>(
            "pool_cmd::PoolNominatorCreateCmd",
            "controller",
        ),
        check::<super::pool_cmd::PoolSingleCreateCmd>("pool_cmd::PoolSingleCreateCmd", "owner"),
        check::<super::pool_cmd::PoolSingleCreateCmd>("pool_cmd::PoolSingleCreateCmd", "validator"),
        check::<super::pool_cmd::PoolSingleCreateCmd>(
            "pool_cmd::PoolSingleCreateCmd",
            "controller",
        ),
        check::<super::pool_cmd::PoolLiquidControllerCreateCmd>(
            "pool_cmd::PoolLiquidControllerCreateCmd",
            "pool_address",
        ),
        check::<super::pool_cmd::PoolLiquidControllerCreateCmd>(
            "pool_cmd::PoolLiquidControllerCreateCmd",
            "controller_0_address",
        ),
        check::<super::pool_cmd::PoolLiquidControllerCreateCmd>(
            "pool_cmd::PoolLiquidControllerCreateCmd",
            "controller_1_address",
        ),
        check::<super::pool_cmd::PoolLiquidControllerCreateCmd>(
            "pool_cmd::PoolLiquidControllerCreateCmd",
            "validator_controller",
        ),
        check::<super::pool_cmd::PoolLiquidControllerAddCmd>(
            "pool_cmd::PoolLiquidControllerAddCmd",
            "address",
        ),
        check::<super::pool_cmd::PoolLiquidControllerAddCmd>(
            "pool_cmd::PoolLiquidControllerAddCmd",
            "controller",
        ),
        check::<super::proof_attestation_cmd::ProofAttestationDeployCmd>(
            "proof_attestation_cmd::ProofAttestationDeployCmd",
            "owner",
        ),
        check::<super::proof_attestation_cmd::ProofAttestationShowCmd>(
            "proof_attestation_cmd::ProofAttestationShowCmd",
            "address",
        ),
        check::<super::proof_attestation_cmd::ProofAttestationSendCmd>(
            "proof_attestation_cmd::ProofAttestationSendCmd",
            "address",
        ),
        check::<super::service_actor_cmd::ServiceActorDeployCmd>(
            "service_actor_cmd::ServiceActorDeployCmd",
            "owner",
        ),
        check::<super::service_actor_cmd::ServiceActorLsCmd>(
            "service_actor_cmd::ServiceActorLsCmd",
            "owner",
        ),
        check::<super::service_actor_cmd::ServiceActorShowCmd>(
            "service_actor_cmd::ServiceActorShowCmd",
            "address",
        ),
        check::<super::service_actor_cmd::ServiceActorRequestShowCmd>(
            "service_actor_cmd::ServiceActorRequestShowCmd",
            "address",
        ),
        check::<super::service_actor_cmd::ServiceActorRefundShowCmd>(
            "service_actor_cmd::ServiceActorRefundShowCmd",
            "address",
        ),
        check::<super::service_actor_cmd::ServiceActorSendCmd>(
            "service_actor_cmd::ServiceActorSendCmd",
            "address",
        ),
        check::<super::service_actor_cmd::ServiceActorSendCmd>(
            "service_actor_cmd::ServiceActorSendCmd",
            "destination",
        ),
        check::<super::service_actor_cmd::ServiceActorBuildStateCmd>(
            "service_actor_cmd::ServiceActorBuildStateCmd",
            "owner",
        ),
        check::<super::tx_cmd::TxBuildIntentCmd>("tx_cmd::TxBuildIntentCmd", "address"),
        check::<super::tx_cmd::TxSigningPayloadCmd>("tx_cmd::TxSigningPayloadCmd", "address"),
        check::<super::wallet_cmd::WalletSendCmd>("wallet_cmd::WalletSendCmd", "to"),
    ]
    .into_iter()
    .flatten()
    .collect();
    assert!(
        failures.is_empty(),
        "{} flags refuse -1:<hex>:\n{}",
        failures.len(),
        failures.join("\n")
    );
}
