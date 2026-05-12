/*
 * Copyright (C) 2025-2026 RSquad Blockchain Lab.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 *
 * This software is provided "AS IS", WITHOUT WARRANTY OF ANY KIND.
 */
use crate::commands::{
    nodectl::{
        account_cmd::AccountCmd, admin_cmd::AdminCmd, auth_cmd::AuthCmd, backup_cmd::BackupCmd,
        config_cmd::ConfigCmd, deploy_cmd::DeployCmd, host_cmd::HostCmd, install_cmd::InstallCmd,
        jvm_wallet_cmd::JvmWalletCmd, key_cmd::KeyCmd, node_cmd::NodeCmd, observe_cmd::ObserveCmd,
        pool_cmd::PoolCmd, service_api_cmd::ApiCmd, service_cmd::ServiceCmd, tx_cmd::TxCmd,
        vote_cmd::VoteCmd, wallet_cmd::WalletCmd,
    },
    chain_rpc::get_config_param_cmd::GetConfigParamCmd,
};

#[derive(clap::Subcommand, Clone)]
pub enum Commands {
    // ─── Existing commands ───────────────────────────────────────────
    /// Query on-chain config parameters
    #[command(name = "config-param")]
    GetConfigParam(GetConfigParamCmd),
    /// REST API management
    #[command(name = "api")]
    Api(ApiCmd),
    /// Authentication and user management
    #[command(name = "auth")]
    Auth(AuthCmd),
    /// Declarative configuration management
    #[command(name = "config")]
    Config(ConfigCmd),
    /// Deploy wallets and contracts
    #[command(name = "deploy")]
    Deploy(DeployCmd),
    /// Vault key management
    #[command(name = "key")]
    Key(KeyCmd),
    /// Run as background service
    #[command(name = "service")]
    Service(ServiceCmd),

    // ─── New operator commands (legacy operator parity) ─────────────
    /// Host lifecycle, modes, settings, updates
    #[command(name = "host")]
    Host(HostCmd),
    /// Backup and recovery
    #[command(name = "backup")]
    Backup(BackupCmd),
    /// Imperative wallet operations
    #[command(name = "wallet", visible_alias = "w")]
    Wallet(WalletCmd),
    /// wc=3 JVM wallet operations
    #[command(name = "jvm-wallet", visible_alias = "jw")]
    JvmWallet(JvmWalletCmd),
    /// Pool lifecycle and staking operations
    #[command(name = "pool", visible_alias = "p")]
    Pool(PoolCmd),
    /// Validator governance: voting, elections, complaints
    #[command(name = "vote", visible_alias = "v")]
    Vote(VoteCmd),
    /// Live node control, collators, overlays
    #[command(name = "node", visible_alias = "n")]
    Node(NodeCmd),
    /// Account inspection and bookmarks
    #[command(name = "account", visible_alias = "ac")]
    Account(AccountCmd),
    /// Transaction build, sign, and submit operations
    #[command(name = "tx")]
    Tx(TxCmd),
    /// Validators, efficiency, alerts, metrics
    #[command(name = "observe", visible_alias = "ob")]
    Observe(ObserveCmd),
    /// Expert and admin-only operations
    #[command(name = "admin")]
    Admin(AdminCmd),
    /// Installation and setup utilities
    #[command(name = "install")]
    Install(InstallCmd),

    // ─── Hidden shortcuts (legacy-style mnemonics) ─────────────────
    /// Shortcut: list wallets (alias for `wallet ls`)
    #[command(name = "wl", hide = true)]
    WalletLs,
    /// Shortcut: list validators (alias for `observe validators`)
    #[command(name = "vl", hide = true)]
    ValidatorList,
    /// Shortcut: check efficiency (alias for `observe efficiency`)
    #[command(name = "ef", hide = true)]
    Efficiency,
    /// Shortcut: list offers (alias for `vote offer ls`)
    #[command(name = "ol", hide = true)]
    OfferList,
    /// Shortcut: list elections (alias for `vote election ls`)
    #[command(name = "el", hide = true)]
    ElectionList,
}
