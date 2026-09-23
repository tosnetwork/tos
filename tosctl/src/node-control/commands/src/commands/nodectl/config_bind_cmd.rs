/*
 * Copyright (C) 2025-2026 RSquad Blockchain Lab.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 *
 * This software is provided "AS IS", WITHOUT WARRANTY OF ANY KIND.
 */
use crate::commands::nodectl::{output_format::OutputFormat, utils::save_config};
use chain_block::{
    AccountStatus, Deserializable, Message, Serializable, Transaction, TransactionDescr,
    read_single_root_boc, write_boc,
};
use colored::Colorize;
use common::app_config::{AppConfig, BindingStatus, NodeBinding, PoolConfig};
use contracts::nominator::verified_controller_birth_witness;
use std::{fs::OpenOptions, io::Write, path::Path, str::FromStr};

#[derive(clap::Args, Clone)]
#[command(about = "Manage node bindings in the configuration")]
pub struct BindCmd {
    #[command(subcommand)]
    action: BindAction,
}

#[derive(clap::Subcommand, Clone)]
pub enum BindAction {
    /// Bind a wallet (and optionally a pool) to a node
    Add(BindAddCmd),
    /// Import a controller's original StateInit from its deployment transaction
    ImportBirth(BindImportBirthCmd),
    /// Remove a node binding (only allowed when binding is in idle state)
    Rm(BindRmCmd),
    /// List all node bindings
    Ls(BindLsCmd),
}

#[derive(clap::Args, Clone)]
#[command(about = "Bind a wallet and optional pool to a node")]
pub struct BindAddCmd {
    #[arg(short = 'n', long = "node", help = "Node name (must exist in nodes)")]
    node: String,
    #[arg(short = 'w', long = "wallet", help = "Wallet name (must exist in wallets)")]
    wallet: String,
    #[arg(short = 'p', long = "pool", help = "Pool name (optional, must exist in pools)")]
    pool: Option<String>,
    #[arg(
        long = "controller-birth-state-init-boc",
        help = "Absolute path to the controller's original public deployment StateInit BOC"
    )]
    controller_birth_state_init_boc: Option<String>,
}

#[derive(clap::Args, Clone)]
#[command(about = "Import the public controller birth StateInit from a deployment transaction BOC")]
pub struct BindImportBirthCmd {
    #[arg(short = 'n', long = "node", help = "Existing idle node binding")]
    node: String,
    #[arg(long = "transaction-boc", help = "BOC of the controller's deployment transaction")]
    transaction_boc: String,
    #[arg(long = "output", help = "New absolute path for the extracted public StateInit BOC")]
    output: String,
}

#[derive(clap::Args, Clone)]
#[command(about = "Remove a node binding")]
pub struct BindRmCmd {
    #[arg(short = 'n', long = "node", help = "Node name to remove from bindings")]
    node: String,
}

#[derive(clap::Args, Clone)]
#[command(about = "List all node bindings")]
pub struct BindLsCmd {
    #[arg(long = "format", default_value = "table", help = "Output format: table or json")]
    format: OutputFormat,
}

impl BindCmd {
    pub async fn run(&self, path: &Path) -> anyhow::Result<()> {
        match &self.action {
            BindAction::Add(cmd) => cmd.run(path).await,
            BindAction::ImportBirth(cmd) => cmd.run(path).await,
            BindAction::Rm(cmd) => cmd.run(path).await,
            BindAction::Ls(cmd) => cmd.run(path).await,
        }
    }
}

impl BindImportBirthCmd {
    pub async fn run(&self, path: &Path) -> anyhow::Result<()> {
        let mut config = AppConfig::load(path)?;
        let binding = config
            .bindings
            .get(&self.node)
            .ok_or_else(|| anyhow::anyhow!("node '{}' has no binding", self.node))?;
        anyhow::ensure!(
            binding.status == BindingStatus::Idle,
            "controller birth import requires an idle node binding"
        );
        let pool_name = binding
            .pool
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("controller birth import requires a pool binding"))?;
        let controller = configured_pool_controller(&config, pool_name)?;
        let output = Path::new(&self.output);
        anyhow::ensure!(output.is_absolute(), "controller birth output path must be absolute");
        let transaction = std::fs::read(&self.transaction_boc)?;
        let binding = config.bindings.get_mut(&self.node).expect("checked binding");
        import_birth_artifact(binding, &transaction, &controller, output)?;
        save_config(&config, path)?;
        println!(
            "Imported controller birth StateInit for node '{}' from deployment transaction; artifact={}",
            self.node,
            output.display()
        );
        Ok(())
    }
}

fn import_birth_artifact(
    binding: &mut NodeBinding,
    transaction: &[u8],
    controller: &chain_block::MsgAddressInt,
    output: &Path,
) -> anyhow::Result<()> {
    anyhow::ensure!(output.is_absolute(), "controller birth output path must be absolute");
    let artifact = controller_birth_from_transaction(transaction, controller)?;
    // Never replace a previously retained birth artifact: a changed deployment
    // is a changed validator identity and must be reviewed as such.
    let mut file = OpenOptions::new().write(true).create_new(true).open(output)?;
    file.write_all(&artifact)?;
    file.sync_all()?;
    binding.controller_birth_state_init_boc = Some(output.display().to_string());
    Ok(())
}

fn configured_pool_controller(
    config: &AppConfig,
    pool_name: &str,
) -> anyhow::Result<chain_block::MsgAddressInt> {
    let pool = config
        .pools
        .get(pool_name)
        .ok_or_else(|| anyhow::anyhow!("configured pool '{}' is missing", pool_name))?;
    let text = match pool {
        PoolConfig::SNP { controller, .. } | PoolConfig::NominatorPool { controller, .. } => {
            controller
        }
        _ => anyhow::bail!("pool '{}' has no PQ validator controller", pool_name),
    };
    let address = chain_block::MsgAddressInt::from_str(text)?;
    anyhow::ensure!(address.workchain_id() == -1, "validator controller must be in masterchain");
    Ok(address)
}

fn controller_birth_from_transaction(
    transaction_boc: &[u8],
    controller: &chain_block::MsgAddressInt,
) -> anyhow::Result<Vec<u8>> {
    let root = read_single_root_boc(transaction_boc)?;
    let transaction = Transaction::construct_from_cell(root)?;
    anyhow::ensure!(
        transaction.orig_status != AccountStatus::AccStateActive
            && transaction.end_status == AccountStatus::AccStateActive,
        "transaction did not deploy an active controller account"
    );
    let TransactionDescr::Ordinary(description) = transaction.read_description()? else {
        anyhow::bail!("controller deployment was not an ordinary transaction");
    };
    anyhow::ensure!(!description.aborted, "controller deployment transaction aborted");
    let id = controller.address();
    anyhow::ensure!(
        transaction.account_id() == id,
        "deployment transaction account is not the configured controller"
    );
    let inbound = transaction
        .in_msg_cell()
        .ok_or_else(|| anyhow::anyhow!("deployment transaction has no inbound message"))?;
    let message = Message::construct_from_cell(inbound)?;
    anyhow::ensure!(
        message.is_internal() && !message.is_bounced(),
        "controller deployment must be a non-bounced internal message"
    );
    anyhow::ensure!(
        message.dst_ref() == Some(controller),
        "deployment message destination is not the configured controller"
    );
    let state = message
        .state_init()
        .ok_or_else(|| anyhow::anyhow!("controller deployment message has no StateInit"))?;
    let code = state
        .code
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("controller deployment StateInit has no code"))?;
    let mut expected_id = [0u8; 32];
    expected_id.copy_from_slice(&id.get_bytestring(0));
    let mut code_hash = [0u8; 32];
    code_hash.copy_from_slice(code.repr_hash().as_slice());
    // Structural and address binding only. Live ConfigParam 47 admission is
    // checked again by both fee-bearing callers; this file is not a policy claim.
    verified_controller_birth_witness(state, &expected_id, &code_hash)?;
    write_boc(&state.clone().write_to_new_cell()?.into_cell()?).map_err(Into::into)
}

impl BindAddCmd {
    pub async fn run(&self, path: &Path) -> anyhow::Result<()> {
        let mut config = AppConfig::load(path)?;

        if !config.nodes.contains_key(&self.node) {
            anyhow::bail!("Node '{}' not found in configuration", self.node);
        }

        if !config.wallets.contains_key(&self.wallet) {
            anyhow::bail!("Wallet '{}' not found in configuration", self.wallet);
        }

        if let Some(pool_name) = &self.pool {
            if !config.pools.contains_key(pool_name) {
                anyhow::bail!("Pool '{}' not found in configuration", pool_name);
            }
            for (node_name, binding) in &config.bindings {
                if binding.pool.as_deref() == Some(pool_name) && *node_name != self.node {
                    anyhow::bail!(
                        "Pool '{}' is already bound to node '{}'. A pool can only be bound to one node.",
                        pool_name,
                        node_name
                    );
                }
            }
        }

        let previous = config.bindings.get(&self.node);
        let birth_artifact = select_birth_artifact_path(
            self.controller_birth_state_init_boc.as_deref(),
            previous,
            self.pool.as_deref(),
        )?;
        let binding = NodeBinding {
            wallet: self.wallet.clone(),
            pool: self.pool.clone(),
            controller_birth_state_init_boc: birth_artifact,
            enable: false,
            status: Default::default(),
        };
        config.bindings.insert(self.node.clone(), binding);
        save_config(&config, path)?;

        let pool_info = self.pool.as_deref().map(|p| format!(", pool='{}'", p)).unwrap_or_default();
        println!(
            "\n{} Binding added: node='{}', wallet='{}'{}\n",
            "OK".green().bold(),
            self.node,
            self.wallet,
            pool_info
        );
        Ok(())
    }
}

fn select_birth_artifact_path(
    requested: Option<&str>,
    previous: Option<&NodeBinding>,
    pool: Option<&str>,
) -> anyhow::Result<Option<String>> {
    if requested.is_some() && pool.is_none() {
        anyhow::bail!("controller birth StateInit BOC requires a pool binding");
    }
    let value = requested.or_else(|| {
        previous.and_then(|old| {
            (old.pool.as_deref() == pool)
                .then(|| old.controller_birth_state_init_boc.as_deref())
                .flatten()
        })
    });
    if let Some(path) = value {
        anyhow::ensure!(
            Path::new(path).is_absolute(),
            "controller birth StateInit BOC path must be absolute"
        );
    }
    Ok(value.map(str::to_string))
}

#[cfg(test)]
mod birth_artifact_binding_tests {
    use super::*;
    use chain_block::{BuilderData, CurrencyCollection, InternalMessageHeader, MsgAddressInt};

    #[test]
    fn binding_preserves_artifact_only_for_the_same_pool() {
        let old = NodeBinding {
            wallet: "wallet".into(),
            pool: Some("pool-a".into()),
            controller_birth_state_init_boc: Some("/var/lib/tos/controller.boc".into()),
            enable: false,
            status: Default::default(),
        };
        assert_eq!(
            select_birth_artifact_path(None, Some(&old), Some("pool-a")).unwrap(),
            old.controller_birth_state_init_boc
        );
        assert_eq!(select_birth_artifact_path(None, Some(&old), Some("pool-b")).unwrap(), None);
        let error = select_birth_artifact_path(Some("relative.boc"), Some(&old), Some("pool-a"))
            .unwrap_err()
            .to_string();
        assert!(error.contains("must be absolute"), "wrong refusal: {error}");
        let error = select_birth_artifact_path(Some("/tmp/controller.boc"), None, None)
            .unwrap_err()
            .to_string();
        assert!(error.contains("requires a pool"), "wrong refusal: {error}");
    }

    fn deployment_transaction(
        controller: &MsgAddressInt,
        state: Option<chain_block::StateInit>,
        destination: &MsgAddressInt,
    ) -> Vec<u8> {
        let source = MsgAddressInt::standard(-1, [0x22; 32]);
        let mut message = Message::with_int_header(InternalMessageHeader::with_addresses(
            source,
            destination.clone(),
            CurrencyCollection::with_coins(10_000_000_000),
        ));
        if let Some(state) = state {
            message.set_state_init(state);
        }
        let mut transaction = Transaction::with_address_and_status(
            controller.address().clone(),
            AccountStatus::AccStateNonexist,
        );
        transaction.write_in_msg(Some(&message)).expect("inbound");
        transaction.write_description(&TransactionDescr::default()).expect("description");
        write_boc(
            &transaction.write_to_new_cell().expect("transaction cell").into_cell().expect("cell"),
        )
        .expect("transaction BOC")
    }

    #[test]
    fn birth_import_extracts_exact_state_init_from_deployment_transaction() {
        let code = BuilderData::with_raw(vec![0x11; 4], 32).unwrap().into_cell().unwrap();
        let data = BuilderData::with_raw(vec![0x22; 4], 32).unwrap().into_cell().unwrap();
        let state = chain_block::StateInit::with_code_and_data(code, data);
        let state_cell = state.clone().write_to_new_cell().unwrap().into_cell().unwrap();
        let controller = MsgAddressInt::standard(-1, state_cell.hash(0));
        let transaction = deployment_transaction(&controller, Some(state), &controller);
        assert_eq!(
            controller_birth_from_transaction(&transaction, &controller).unwrap(),
            write_boc(&state_cell).unwrap()
        );
        let output = std::env::temp_dir().join(format!(
            "tosctl-controller-birth-import-{}-{}.boc",
            std::process::id(),
            hex::encode(state_cell.hash(0).as_slice())
        ));
        let mut binding = NodeBinding {
            wallet: "operator".into(),
            pool: Some("pool".into()),
            controller_birth_state_init_boc: None,
            enable: false,
            status: BindingStatus::Idle,
        };
        import_birth_artifact(&mut binding, &transaction, &controller, &output).expect("import");
        assert_eq!(std::fs::read(&output).unwrap(), write_boc(&state_cell).unwrap());
        assert_eq!(binding.controller_birth_state_init_boc.as_deref(), output.to_str());
        let error = import_birth_artifact(&mut binding, &transaction, &controller, &output)
            .unwrap_err()
            .to_string();
        assert!(error.contains("File exists"), "wrong overwrite refusal: {error}");
        std::fs::remove_file(&output).expect("remove test-only artifact");

        let wrong_controller = MsgAddressInt::standard(-1, [0x33; 32]);
        let error = controller_birth_from_transaction(&transaction, &wrong_controller)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("account is not the configured controller"),
            "wrong refusal: {error}"
        );
        let wrong_destination = deployment_transaction(
            &controller,
            Some(chain_block::StateInit::with_code_and_data(
                BuilderData::with_raw(vec![0x11; 4], 32).unwrap().into_cell().unwrap(),
                BuilderData::with_raw(vec![0x22; 4], 32).unwrap().into_cell().unwrap(),
            )),
            &wrong_controller,
        );
        let error = controller_birth_from_transaction(&wrong_destination, &controller)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("destination is not the configured controller"),
            "wrong refusal: {error}"
        );
        let missing = deployment_transaction(&controller, None, &controller);
        let error =
            controller_birth_from_transaction(&missing, &controller).unwrap_err().to_string();
        assert!(error.contains("has no StateInit"), "wrong refusal: {error}");
        let mut aborted = Transaction::construct_from_cell(
            read_single_root_boc(&transaction).expect("transaction root"),
        )
        .expect("transaction");
        let mut description = chain_block::TransactionDescrOrdinary::default();
        description.aborted = true;
        aborted
            .write_description(&TransactionDescr::Ordinary(description))
            .expect("aborted description");
        let aborted =
            write_boc(&aborted.write_to_new_cell().unwrap().into_cell().unwrap()).unwrap();
        let error =
            controller_birth_from_transaction(&aborted, &controller).unwrap_err().to_string();
        assert!(error.contains("transaction aborted"), "wrong refusal: {error}");
    }
}

impl BindRmCmd {
    pub async fn run(&self, path: &Path) -> anyhow::Result<()> {
        let mut config = AppConfig::load(path)?;

        let binding = config
            .bindings
            .get(&self.node)
            .ok_or_else(|| anyhow::anyhow!("Binding for node '{}' not found", self.node))?;

        if binding.status != BindingStatus::Idle {
            anyhow::bail!(
                "Cannot remove binding for node '{}': status is '{}', must be 'idle'. \
                 Disable elections first and wait for stake recovery to complete.",
                self.node,
                binding.status
            );
        }

        config.bindings.remove(&self.node);
        save_config(&config, path)?;

        println!("\n{} Binding {} removed\n", "OK".green().bold(), self.node);
        Ok(())
    }
}

#[derive(serde::Serialize)]
struct BindingView {
    node: String,
    wallet: String,
    pool: Option<String>,
    enable: bool,
    status: String,
}

impl BindLsCmd {
    pub async fn run(&self, path: &Path) -> anyhow::Result<()> {
        let config = AppConfig::load(path)?;

        if config.bindings.is_empty() {
            match self.format {
                OutputFormat::Json => println!("[]"),
                OutputFormat::Table => println!("\n{}\n", "No bindings configured".yellow()),
            }
            return Ok(());
        }

        let mut views: Vec<BindingView> = config
            .bindings
            .into_iter()
            .map(|(node, b)| BindingView {
                node,
                wallet: b.wallet,
                pool: b.pool,
                enable: b.enable,
                status: b.status.to_string(),
            })
            .collect();
        views.sort_by(|a, b| a.node.cmp(&b.node));

        match self.format {
            OutputFormat::Json => print_bindings_json(&views)?,
            OutputFormat::Table => print_bindings_table(&views),
        }
        Ok(())
    }
}

fn print_bindings_json(views: &[BindingView]) -> anyhow::Result<()> {
    println!("{}", serde_json::to_string_pretty(views)?);
    Ok(())
}

fn print_bindings_table(views: &[BindingView]) {
    println!("\n{} {} ({})\n", "OK".green().bold(), "Bindings:".green(), views.len());
    println!(
        "  {:<20} {:<20} {:<20} {:<12} {}",
        "Node".cyan().bold(),
        "Wallet".cyan().bold(),
        "Pool".cyan().bold(),
        "Enable".cyan().bold(),
        "Status".cyan().bold(),
    );
    println!("  {}", "─".repeat(90).dimmed());

    for v in views {
        let enable_str = if v.enable { "yes".green().to_string() } else { "no".red().to_string() };
        println!(
            "  {:<20} {:<20} {:<20} {:<21} {}",
            v.node,
            v.wallet,
            v.pool.as_deref().unwrap_or("-"),
            enable_str,
            v.status,
        );
    }
    println!();
}
