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

/// `None` when `--<flag>` followed directly by another option, or by a word that is
/// not an address, is refused at parse time with an invalid-value error.
fn refuses_non_address<T: Args>(name: &str, id: &str) -> Option<String> {
    let command = T::augment_args(
        Command::new("t")
            .arg(clap::Arg::new("other").long("other").action(clap::ArgAction::SetTrue)),
    );
    let long = command
        .get_arguments()
        .find(|arg| arg.get_id().as_str() == id)
        .and_then(|arg| arg.get_long())
        .map(str::to_owned)?;
    let flag = format!("--{long}");
    for value in ["--other", "not-an-address"] {
        match command.clone().try_get_matches_from(["t", flag.as_str(), value]) {
            Err(error) if error.kind() == clap::error::ErrorKind::ValueValidation => {}
            Err(error) => {
                return Some(format!(
                    "{name} {flag} {value}: refused as {}, not as an invalid address",
                    error.kind()
                ));
            }
            Ok(_) => return Some(format!("{name} {flag} {value}: accepted")),
        }
    }
    None
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
            "controller",
        ),
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
        check::<super::controller_cmd::ControllerOperationsStatusCmd>(
            "controller_cmd::ControllerOperationsStatusCmd",
            "controller",
        ),
        check::<super::controller_cmd::ControllerOperationsPlanCmd>(
            "controller_cmd::ControllerOperationsPlanCmd",
            "controller",
        ),
        check::<super::controller_cmd::ControllerOperationsPlanCmd>(
            "controller_cmd::ControllerOperationsPlanCmd",
            "payer",
        ),
        check::<super::agent_cmd::AgentAccountShowCmd>("agent_cmd::AgentAccountShowCmd", "address"),
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

/// `--to --bounce` must not set the address to `--bounce` and silently drop the
/// option: every address flag refuses an option, or any non-address, as its value.
#[test]
fn every_address_flag_refuses_an_option_or_a_non_address_as_its_value() {
    let failures: Vec<String> = [
        refuses_non_address::<super::account_cmd::AccountStatusCmd>(
            "account_cmd::AccountStatusCmd",
            "address",
        ),
        refuses_non_address::<super::account_cmd::AccountCapabilityCmd>(
            "account_cmd::AccountCapabilityCmd",
            "address",
        ),
        refuses_non_address::<super::account_cmd::AccountDelegationsCmd>(
            "account_cmd::AccountDelegationsCmd",
            "address",
        ),
        refuses_non_address::<super::account_cmd::AccountSessionsCmd>(
            "account_cmd::AccountSessionsCmd",
            "address",
        ),
        refuses_non_address::<super::account_cmd::AccountAgentsCmd>(
            "account_cmd::AccountAgentsCmd",
            "address",
        ),
        refuses_non_address::<super::account_cmd::AccountTxsCmd>(
            "account_cmd::AccountTxsCmd",
            "address",
        ),
        refuses_non_address::<super::account_cmd::AccountBookmarkAddCmd>(
            "account_cmd::AccountBookmarkAddCmd",
            "address",
        ),
        refuses_non_address::<super::account_cmd::AccountRunMethodCmd>(
            "account_cmd::AccountRunMethodCmd",
            "address",
        ),
        refuses_non_address::<super::account_cmd::AccountDelegationGrantCmd>(
            "account_cmd::AccountDelegationGrantCmd",
            "address",
        ),
        refuses_non_address::<super::account_cmd::AccountDelegationRevokeCmd>(
            "account_cmd::AccountDelegationRevokeCmd",
            "address",
        ),
        refuses_non_address::<super::account_cmd::AccountSessionGrantCmd>(
            "account_cmd::AccountSessionGrantCmd",
            "address",
        ),
        refuses_non_address::<super::account_cmd::AccountSessionRevokeCmd>(
            "account_cmd::AccountSessionRevokeCmd",
            "address",
        ),
        refuses_non_address::<super::account_cmd::AccountAgentGrantCmd>(
            "account_cmd::AccountAgentGrantCmd",
            "address",
        ),
        refuses_non_address::<super::account_cmd::AccountAgentRevokeCmd>(
            "account_cmd::AccountAgentRevokeCmd",
            "address",
        ),
        refuses_non_address::<super::agent_cmd::AgentTaskSendCmd>(
            "agent_cmd::AgentTaskSendCmd",
            "address",
        ),
        refuses_non_address::<super::agent_cmd::AgentTaskShowCmd>(
            "agent_cmd::AgentTaskShowCmd",
            "address",
        ),
        refuses_non_address::<super::agent_cmd::AgentAccountTaskSendCmd>(
            "agent_cmd::AgentAccountTaskSendCmd",
            "target",
        ),
        refuses_non_address::<super::agent_cmd::AgentAccountNativePrepareCmd>(
            "agent_cmd::AgentAccountNativePrepareCmd",
            "target",
        ),
        refuses_non_address::<super::agent_cmd::AgentAccountEconomicPaymentPrepareCmd>(
            "agent_cmd::AgentAccountEconomicPaymentPrepareCmd",
            "target",
        ),
        refuses_non_address::<super::agent_cmd::AgentAccountEconomicEffectPrepareCmd>(
            "agent_cmd::AgentAccountEconomicEffectPrepareCmd",
            "target",
        ),
        refuses_non_address::<super::agent_cmd::AgentWalletSendCmd>(
            "agent_cmd::AgentWalletSendCmd",
            "to",
        ),
        refuses_non_address::<super::capability_registry_cmd::CapabilityRegistryDeployCmd>(
            "capability_registry_cmd::CapabilityRegistryDeployCmd",
            "owner",
        ),
        refuses_non_address::<super::capability_registry_cmd::CapabilityRegistryLsCmd>(
            "capability_registry_cmd::CapabilityRegistryLsCmd",
            "owner",
        ),
        refuses_non_address::<super::capability_registry_cmd::CapabilityRegistryShowCmd>(
            "capability_registry_cmd::CapabilityRegistryShowCmd",
            "address",
        ),
        refuses_non_address::<super::capability_registry_cmd::CapabilityRegistrySendCmd>(
            "capability_registry_cmd::CapabilityRegistrySendCmd",
            "address",
        ),
        refuses_non_address::<super::capability_registry_cmd::CapabilityRegistryBuildStateCmd>(
            "capability_registry_cmd::CapabilityRegistryBuildStateCmd",
            "owner",
        ),
        refuses_non_address::<super::config_pool_cmd::PoolAddCmd>(
            "config_pool_cmd::PoolAddCmd",
            "address",
        ),
        refuses_non_address::<super::config_pool_cmd::PoolAddCmd>(
            "config_pool_cmd::PoolAddCmd",
            "owner",
        ),
        refuses_non_address::<super::config_pool_cmd::PoolAddCmd>(
            "config_pool_cmd::PoolAddCmd",
            "controller",
        ),
        refuses_non_address::<super::config_wallet_cmd::WalletSendCmd>(
            "config_wallet_cmd::WalletSendCmd",
            "to",
        ),
        refuses_non_address::<super::deploy_cmd::DeployPoolCmd>(
            "deploy_cmd::DeployPoolCmd",
            "owner",
        ),
        refuses_non_address::<super::deploy_cmd::DeployPoolCmd>(
            "deploy_cmd::DeployPoolCmd",
            "controller",
        ),
        refuses_non_address::<super::deploy_cmd::DeployContractCmd>(
            "deploy_cmd::DeployContractCmd",
            "address",
        ),
        refuses_non_address::<super::dispute_cmd::DisputeDeployCmd>(
            "dispute_cmd::DisputeDeployCmd",
            "claimant",
        ),
        refuses_non_address::<super::dispute_cmd::DisputeDeployCmd>(
            "dispute_cmd::DisputeDeployCmd",
            "respondent",
        ),
        refuses_non_address::<super::dispute_cmd::DisputeShowCmd>(
            "dispute_cmd::DisputeShowCmd",
            "address",
        ),
        refuses_non_address::<super::dispute_cmd::DisputeSendCmd>(
            "dispute_cmd::DisputeSendCmd",
            "address",
        ),
        refuses_non_address::<super::pool_cmd::PoolImportCmd>("pool_cmd::PoolImportCmd", "address"),
        refuses_non_address::<super::pool_cmd::PoolImportCmd>(
            "pool_cmd::PoolImportCmd",
            "controller",
        ),
        refuses_non_address::<super::pool_cmd::PoolNominatorCreateCmd>(
            "pool_cmd::PoolNominatorCreateCmd",
            "controller",
        ),
        refuses_non_address::<super::pool_cmd::PoolSingleCreateCmd>(
            "pool_cmd::PoolSingleCreateCmd",
            "controller",
        ),
        refuses_non_address::<super::pool_cmd::PoolLiquidControllerCreateCmd>(
            "pool_cmd::PoolLiquidControllerCreateCmd",
            "pool_address",
        ),
        refuses_non_address::<super::pool_cmd::PoolLiquidControllerCreateCmd>(
            "pool_cmd::PoolLiquidControllerCreateCmd",
            "controller_0_address",
        ),
        refuses_non_address::<super::pool_cmd::PoolLiquidControllerCreateCmd>(
            "pool_cmd::PoolLiquidControllerCreateCmd",
            "controller_1_address",
        ),
        refuses_non_address::<super::pool_cmd::PoolLiquidControllerCreateCmd>(
            "pool_cmd::PoolLiquidControllerCreateCmd",
            "validator_controller",
        ),
        refuses_non_address::<super::pool_cmd::PoolLiquidControllerAddCmd>(
            "pool_cmd::PoolLiquidControllerAddCmd",
            "address",
        ),
        refuses_non_address::<super::pool_cmd::PoolLiquidControllerAddCmd>(
            "pool_cmd::PoolLiquidControllerAddCmd",
            "controller",
        ),
        refuses_non_address::<super::proof_attestation_cmd::ProofAttestationDeployCmd>(
            "proof_attestation_cmd::ProofAttestationDeployCmd",
            "owner",
        ),
        refuses_non_address::<super::proof_attestation_cmd::ProofAttestationShowCmd>(
            "proof_attestation_cmd::ProofAttestationShowCmd",
            "address",
        ),
        refuses_non_address::<super::proof_attestation_cmd::ProofAttestationSendCmd>(
            "proof_attestation_cmd::ProofAttestationSendCmd",
            "address",
        ),
        refuses_non_address::<super::service_actor_cmd::ServiceActorDeployCmd>(
            "service_actor_cmd::ServiceActorDeployCmd",
            "owner",
        ),
        refuses_non_address::<super::service_actor_cmd::ServiceActorLsCmd>(
            "service_actor_cmd::ServiceActorLsCmd",
            "owner",
        ),
        refuses_non_address::<super::service_actor_cmd::ServiceActorShowCmd>(
            "service_actor_cmd::ServiceActorShowCmd",
            "address",
        ),
        refuses_non_address::<super::service_actor_cmd::ServiceActorRequestShowCmd>(
            "service_actor_cmd::ServiceActorRequestShowCmd",
            "address",
        ),
        refuses_non_address::<super::service_actor_cmd::ServiceActorRefundShowCmd>(
            "service_actor_cmd::ServiceActorRefundShowCmd",
            "address",
        ),
        refuses_non_address::<super::service_actor_cmd::ServiceActorSendCmd>(
            "service_actor_cmd::ServiceActorSendCmd",
            "address",
        ),
        refuses_non_address::<super::service_actor_cmd::ServiceActorSendCmd>(
            "service_actor_cmd::ServiceActorSendCmd",
            "destination",
        ),
        refuses_non_address::<super::service_actor_cmd::ServiceActorBuildStateCmd>(
            "service_actor_cmd::ServiceActorBuildStateCmd",
            "owner",
        ),
        refuses_non_address::<super::tx_cmd::TxBuildIntentCmd>(
            "tx_cmd::TxBuildIntentCmd",
            "address",
        ),
        refuses_non_address::<super::tx_cmd::TxSigningPayloadCmd>(
            "tx_cmd::TxSigningPayloadCmd",
            "address",
        ),
        refuses_non_address::<super::wallet_cmd::WalletSendCmd>("wallet_cmd::WalletSendCmd", "to"),
        refuses_non_address::<super::controller_cmd::ControllerOperationsStatusCmd>(
            "controller_cmd::ControllerOperationsStatusCmd",
            "controller",
        ),
        refuses_non_address::<super::controller_cmd::ControllerOperationsPlanCmd>(
            "controller_cmd::ControllerOperationsPlanCmd",
            "controller",
        ),
        refuses_non_address::<super::controller_cmd::ControllerOperationsPlanCmd>(
            "controller_cmd::ControllerOperationsPlanCmd",
            "payer",
        ),
        refuses_non_address::<super::agent_cmd::AgentAccountShowCmd>(
            "agent_cmd::AgentAccountShowCmd",
            "address",
        ),
    ]
    .into_iter()
    .flatten()
    .collect();
    assert!(
        failures.is_empty(),
        "{} flags accept a non-address:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

/// The case that motivated the parser: an address flag left empty before the next
/// option. It used to set the address to `--bounce` and drop the flag.
#[test]
fn a_missing_address_does_not_swallow_the_next_option() {
    use clap::FromArgMatches;
    let command = super::wallet_cmd::WalletSendCmd::augment_args(Command::new("send"));
    let error = command
        .clone()
        .try_get_matches_from(["send", "--from", "payer", "--amount", "1", "--to", "--bounce"])
        .err()
        .map(|error| error.kind());
    assert_eq!(error, Some(clap::error::ErrorKind::ValueValidation));

    // The raw and the user-friendly form are both addresses.
    let raw: chain_block::MsgAddressInt = MASTERCHAIN.parse().expect("raw address");
    let friendly = raw
        .to_string_custom(chain_block::ADDR_FORMAT_URL_SAFE | chain_block::ADDR_FORMAT_BOUNCE)
        .expect("user-friendly form");
    for to in [MASTERCHAIN.to_owned(), friendly] {
        let matches = command
            .clone()
            .try_get_matches_from([
                "send", "--from", "payer", "--amount", "1", "--to", &to, "--bounce",
            ])
            .expect("parses");
        assert!(matches.get_flag("bounce"), "{to}");
        assert!(super::wallet_cmd::WalletSendCmd::from_arg_matches(&matches).is_ok());
    }
}

/// Wallet-name flags are names looked up in the configuration, not addresses: they
/// take any name and are not validated as addresses.
#[test]
fn wallet_name_flags_take_names() {
    use clap::FromArgMatches;
    let controller = MASTERCHAIN;
    let single = super::pool_cmd::PoolSingleCreateCmd::augment_args(Command::new("create"))
        .try_get_matches_from([
            "create",
            "--name",
            "p",
            "--owner",
            "alice",
            "--validator",
            "bob",
            "--controller",
            controller,
        ])
        .expect("single-nominator create takes wallet names");
    assert!(super::pool_cmd::PoolSingleCreateCmd::from_arg_matches(&single).is_ok());
    let nominator = super::pool_cmd::PoolNominatorCreateCmd::augment_args(Command::new("create"))
        .try_get_matches_from([
            "create",
            "--name",
            "p",
            "--owner",
            "alice",
            "--validator",
            "bob",
            "--controller",
            controller,
        ])
        .expect("nominator-pool create takes wallet names");
    assert!(super::pool_cmd::PoolNominatorCreateCmd::from_arg_matches(&nominator).is_ok());
}

/// An address with surrounding whitespace (as from a quoted shell variable) is
/// accepted, trimmed, as the commands that read these values used to trim them.
#[test]
fn an_address_with_surrounding_whitespace_is_trimmed() {
    let padded = format!("  {MASTERCHAIN}\n");
    assert_eq!(super::utils::address_arg(&padded), Ok(MASTERCHAIN.to_owned()));
    let matches = super::config_pool_cmd::PoolAddCmd::augment_args(Command::new("add"))
        .ignore_errors(true)
        .try_get_matches_from(["add", "--controller", padded.as_str()])
        .expect("parses");
    assert_eq!(matches.get_one::<String>("controller").map(String::as_str), Some(MASTERCHAIN));
}
