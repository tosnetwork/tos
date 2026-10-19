//! Every flag that takes a workchain or another signed number accepts a negative
//! value as its own token. The masterchain is workchain `-1`; without
//! `allow_negative_numbers` clap reads `--workchain -1` as the short flag `-1`
//! and only the `--workchain=-1` spelling works.
use clap::{Args, Command};

/// `None` when every spelling in `spellings` gives the argument `id` exactly
/// `value`; otherwise what went wrong. Other required arguments are not
/// supplied, so errors about them are ignored.
fn check<T: Args>(name: &str, id: &str, value: &str) -> Option<String> {
    let command = T::augment_args(Command::new("t")).ignore_errors(true);
    let Some(arg) = command.get_arguments().find(|arg| arg.get_id().as_str() == id) else {
        return Some(format!("{name}: no argument {id}"));
    };
    let mut flags = Vec::new();
    if let Some(long) = arg.get_long() {
        flags.push(format!("--{long}"));
    }
    if let Some(short) = arg.get_short() {
        flags.push(format!("-{short}"));
    }
    if flags.is_empty() {
        return Some(format!("{name}: no flag for {id}"));
    }
    for flag in flags {
        match command.clone().try_get_matches_from(["t", flag.as_str(), value]) {
            Ok(matches) => {
                let raw: Option<Vec<String>> = matches
                    .get_raw(id)
                    .map(|values| values.map(|v| v.to_string_lossy().into_owned()).collect());
                if raw.as_deref() != Some(&[value.to_owned()][..]) {
                    return Some(format!("{name} {flag} {value}: parsed as {raw:?}"));
                }
            }
            Err(error) => return Some(format!("{name} {flag} {value}: {}", error.kind())),
        }
    }
    None
}

#[test]
fn every_workchain_flag_accepts_the_masterchain() {
    let failures: Vec<String> = [
        check::<super::wallet_cmd::WalletCreateCmd>("wallet create", "workchain", "-1"),
        check::<super::wallet_cmd::WalletImportCmd>("wallet import", "workchain", "-1"),
        check::<super::wallet_cmd::WalletMnemonicGenerateCmd>(
            "wallet mnemonic generate",
            "workchain",
            "-1",
        ),
        check::<super::wallet_cmd::WalletMnemonicImportCmd>(
            "wallet mnemonic import",
            "workchain",
            "-1",
        ),
        check::<super::wallet_cmd::WalletTestFixtureCmd>("wallet test-fixture", "workchain", "-1"),
        check::<super::config_wallet_cmd::WalletAddCmd>("config wallet add", "workchain", "-1"),
        check::<super::agent_cmd::AgentTaskCreateCmd>("agent task create", "workchain", "-1"),
        check::<super::agent_cmd::AgentTaskBuildStateCmd>(
            "agent task build-state",
            "workchain",
            "-1",
        ),
        check::<super::agent_cmd::AgentAccountBuildStateCmd>(
            "agent account build-state",
            "workchain",
            "-1",
        ),
        check::<super::agent_cmd::AgentAccountDeployCmd>("agent account deploy", "workchain", "-1"),
        check::<super::agent_cmd::AgentAccountStatusCmd>("agent account status", "workchain", "-1"),
        check::<super::agent_cmd::AgentAccountEconomicPaymentCorroborationProfileCmd>(
            "agent account corroboration profile",
            "workchain_id",
            "-1",
        ),
        check::<super::agent_cmd::AgentWalletCreateCmd>("agent wallet create", "workchain", "-1"),
        check::<super::capability_registry_cmd::CapabilityRegistryDeployCmd>(
            "capability registry deploy",
            "workchain",
            "-1",
        ),
        check::<super::capability_registry_cmd::CapabilityRegistryBuildStateCmd>(
            "capability registry build-state",
            "workchain",
            "-1",
        ),
        check::<super::dispute_cmd::DisputeDeployCmd>("dispute deploy", "workchain", "-1"),
        check::<super::proof_attestation_cmd::ProofAttestationDeployCmd>(
            "proof attestation deploy",
            "workchain",
            "-1",
        ),
        check::<super::service_actor_cmd::ServiceActorDeployCmd>(
            "service actor deploy",
            "workchain",
            "-1",
        ),
        check::<super::service_actor_cmd::ServiceActorBuildStateCmd>(
            "service actor build-state",
            "workchain",
            "-1",
        ),
    ]
    .into_iter()
    .flatten()
    .collect();
    assert!(failures.is_empty(), "flags refusing workchain -1:\n{}", failures.join("\n"));
}

#[test]
fn reputation_delta_accepts_a_negative_value() {
    let failure = check::<super::capability_registry_cmd::CapabilityRegistrySendCmd>(
        "capability registry send",
        "delta",
        "-5",
    );
    assert!(failure.is_none(), "{failure:?}");
}

#[test]
fn collator_shard_accepts_a_masterchain_shard_and_refuses_another_option() {
    const SHARD: &str = "-1:8000000000000000";
    let failures: Vec<String> = [
        check::<super::node_cmd::NodeCollatorAddCmd>("node collator add", "shard", SHARD),
        check::<super::node_cmd::NodeCollatorRmCmd>("node collator rm", "shard", SHARD),
    ]
    .into_iter()
    .flatten()
    .collect();
    assert!(failures.is_empty(), "shard flags refusing {SHARD}:\n{}", failures.join("\n"));

    // Allowing hyphen values must not let the flag swallow the next option.
    let command = <super::node_cmd::NodeCollatorAddCmd as Args>::augment_args(
        Command::new("t")
            .arg(clap::Arg::new("other").long("other").action(clap::ArgAction::SetTrue)),
    );
    let error = command
        .try_get_matches_from(["t", "--adnl-id", "x", "--shard", "--other"])
        .err()
        .map(|e| e.kind());
    assert_eq!(error, Some(clap::error::ErrorKind::ValueValidation));
}

#[test]
fn user_contract_workchain_defaults_are_basechain_and_operator_defaults_stay_masterchain() {
    use clap::Subcommand;

    fn visit(command: &Command, path: &str, checked: &mut usize) {
        if let Some(arg) = command.get_arguments().find(|arg| arg.get_long() == Some("workchain")) {
            if !arg.get_default_values().is_empty() {
                let expected = if path == "tosctl config wallet add" { "-1" } else { "0" };
                let matches = command
                    .clone()
                    .ignore_errors(true)
                    .try_get_matches_from([command.get_name()])
                    .expect("parse the deployment defaults without executing a command");
                let actual: Vec<_> = matches
                    .get_raw(arg.get_id().as_str())
                    .expect("workchain default was applied")
                    .map(|value| value.to_string_lossy().into_owned())
                    .collect();
                assert_eq!(actual, [expected], "{path}: wrong deployment workchain default");
                *checked += 1;
            }
        }
        for child in command.get_subcommands() {
            visit(child, &format!("{path} {}", child.get_name()), checked);
        }
    }

    let mut command =
        crate::commands::cli_cmd::Commands::augment_subcommands(Command::new("tosctl"));
    command.build();
    let mut checked = 0;
    visit(&command, "tosctl", &mut checked);
    assert!(checked >= 17, "the default inventory did not run: {checked} commands");
}

#[test]
fn omitted_wallet_config_workchain_keeps_the_operator_identity() {
    let wallet: common::app_config::WalletConfig = serde_json::from_value(serde_json::json!({
        "key": {"name": "operator-key"},
        "version": "V3R2",
        "subwallet_id": 42
    }))
    .expect("existing operator wallet configuration");
    assert_eq!(wallet.workchain, -1);
}
