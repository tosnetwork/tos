//! `tosctl-uno` — Uno Workchain (wc=2) wallet CLI, P.6 foundation.
//!
//! Subcommands:
//!
//! | Subcommand   | Status | Purpose                                                |
//! |--------------|--------|--------------------------------------------------------|
//! | `keygen`     | ✅     | Derive FVK from BIP-39 mnemonic or raw seed file       |
//! | `address`    | ✅     | Build diversified Address; emit wire bytes + string    |
//! | `scan`       | ✅     | Compact-filter GCS scan + hybrid-KEM trial-decrypt     |
//! | `balance`    | ✅     | Sum unspent notes (scan + nullifier-set delta)         |
//! | `chain-info` | ✅     | `uno_chainInfo` smoke-test                             |
//! | `send`       | 🔧    | Build + Schnorr-sign + submit a Transfer (stub Plonky3 proof — M-P2) |

use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand};
use tosctl_uno::{address, balance, genesis_build, keygen, rpc_client, scan, send};

/// Uno Workchain (wc=2) wallet CLI — P.6 foundation build.
#[derive(Debug, Parser)]
#[command(name = "tosctl-uno", version = tosctl_uno::VERSION, about)]
struct Cli {
    #[command(subcommand)]
    cmd: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Derive the Uno key hierarchy from a TOS mnemonic or seed file.
    Keygen(KeygenArgs),
    /// Generate a diversified address from the wallet's FVK.
    Address(AddressArgs),
    /// Scan a block range for notes belonging to this wallet.
    Scan(ScanArgs),
    /// Summarize balance = Σ unspent(owned notes).
    Balance(BalanceArgs),
    /// Fetch chain-info from an RPC endpoint (smoke test).
    ChainInfo(ChainInfoArgs),
    /// Build, Schnorr-sign, and submit a Transfer. Uses a STUB Plonky3
    /// proof (M-P2 integration point) — the resulting tx will be rejected
    /// by any real validator until the Transfer AIR lands.
    Send(SendArgs),
    /// Genesis-distribution tooling (§10.3 builder).
    #[command(subcommand)]
    Genesis(GenesisCmd),
}

#[derive(Debug, Subcommand)]
enum GenesisCmd {
    /// Build the canonical `zerostate-genesis-notes.json` from three CSV
    /// recipient lists (airdrop.csv, treasury.csv, team.csv). Validates the
    /// 60 / 25 / 15 split (§10.3) and emits the loader-compatible JSON.
    Build(GenesisBuildArgs),
}

#[derive(Debug, clap::Args)]
struct GenesisBuildArgs {
    /// Path to airdrop CSV — each line is `<address_hex_1259_bytes>,<value_nano>`.
    #[arg(long, required = true)]
    airdrop: std::path::PathBuf,
    /// Path to treasury CSV (same format as --airdrop).
    #[arg(long, required = true)]
    treasury: std::path::PathBuf,
    /// Path to team CSV (same format as --airdrop).
    #[arg(long, required = true)]
    team: std::path::PathBuf,
    /// Target chain_id: either `mainnet`, `testnet`, or a decimal / 0xhex u32.
    #[arg(long, default_value = "testnet")]
    chain_id: String,
    /// Output path for the JSON. `-` writes to stdout.
    #[arg(long, default_value = "-")]
    out: String,
}

fn run_genesis_build(args: &GenesisBuildArgs) -> Result<()> {
    let airdrop_text = std::fs::read_to_string(&args.airdrop)
        .with_context(|| format!("reading {}", args.airdrop.display()))?;
    let treasury_text = std::fs::read_to_string(&args.treasury)
        .with_context(|| format!("reading {}", args.treasury.display()))?;
    let team_text = std::fs::read_to_string(&args.team)
        .with_context(|| format!("reading {}", args.team.display()))?;

    let chain_id = parse_chain_id_arg(&args.chain_id)?;

    let inputs = genesis_build::GenesisDistributionInputs {
        chain_id,
        airdrop: genesis_build::parse_recipient_csv(
            &airdrop_text,
            &args.airdrop.display().to_string(),
        )?,
        treasury: genesis_build::parse_recipient_csv(
            &treasury_text,
            &args.treasury.display().to_string(),
        )?,
        team: genesis_build::parse_recipient_csv(
            &team_text,
            &args.team.display().to_string(),
        )?,
    };

    let json = genesis_build::build_genesis_notes_json(&inputs)?;

    if args.out == "-" {
        println!("{}", json);
    } else {
        std::fs::write(&args.out, &json)
            .with_context(|| format!("writing {}", args.out))?;
        eprintln!(
            "wrote genesis-notes JSON ({} notes, chain_id=0x{:08X}) to {}",
            inputs.airdrop.len() + inputs.treasury.len() + inputs.team.len(),
            chain_id,
            args.out
        );
    }
    Ok(())
}

fn parse_chain_id_arg(s: &str) -> Result<u32> {
    match s {
        "mainnet" => Ok(genesis_build::CHAIN_ID_MAINNET),
        "testnet" => Ok(genesis_build::CHAIN_ID_TESTNET),
        other => {
            if let Some(hex) = other.strip_prefix("0x").or_else(|| other.strip_prefix("0X")) {
                u32::from_str_radix(hex, 16)
                    .map_err(|e| anyhow!("invalid --chain-id hex {:?}: {}", other, e))
            } else {
                other
                    .parse::<u32>()
                    .map_err(|e| anyhow!("invalid --chain-id {:?}: {}", other, e))
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Keygen
// ---------------------------------------------------------------------------

#[derive(Debug, clap::Args)]
struct KeygenArgs {
    /// 24-word BIP-39 mnemonic (quoted). Mutually exclusive with --from-tos-seed.
    #[arg(long, conflicts_with = "from_tos_seed")]
    seed: Option<String>,

    /// Path to a TOS seed file (32 raw bytes, OR a line of 64-char hex).
    #[arg(long, value_name = "PATH")]
    from_tos_seed: Option<std::path::PathBuf>,

    /// BIP-39 passphrase (only used with --seed).
    #[arg(long, default_value = "")]
    passphrase: String,

    /// Where to write the FVK JSON. `-` prints to stdout.
    #[arg(long, default_value = "-")]
    out: String,
}

fn run_keygen(args: &KeygenArgs) -> Result<()> {
    let main_tos_seed = match (&args.seed, &args.from_tos_seed) {
        (Some(m), None) => keygen::tos_seed_from_mnemonic(m, &args.passphrase)?,
        (None, Some(p)) => keygen::tos_seed_from_file(p)?,
        _ => return Err(anyhow!("keygen requires exactly one of --seed or --from-tos-seed")),
    };

    let fvk = keygen::derive_fvk(&main_tos_seed)?;
    let json = serde_json::to_string_pretty(&fvk)?;

    if args.out == "-" {
        println!("{}", json);
    } else {
        std::fs::write(&args.out, &json)
            .with_context(|| format!("writing {}", args.out))?;
        eprintln!("wrote FVK to {}", args.out);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Address
// ---------------------------------------------------------------------------

#[derive(Debug, clap::Args)]
struct AddressArgs {
    /// Path to a previously-generated FVK JSON (produced by `keygen --out FILE`).
    #[arg(long, required = true)]
    fvk: std::path::PathBuf,

    /// Diversifier as 22 hex chars (11 bytes). Mutually exclusive with --random.
    #[arg(long, conflicts_with = "random")]
    diversifier: Option<String>,

    /// Pick a random 11-byte diversifier.
    #[arg(long)]
    random: bool,

    /// HRP for the human-readable string: "uno1" (testnet) | "unos" (mainnet).
    #[arg(long, default_value = "uno1")]
    hrp: String,
}

fn run_address(args: &AddressArgs) -> Result<()> {
    let fvk_json = std::fs::read_to_string(&args.fvk)
        .with_context(|| format!("reading FVK from {}", args.fvk.display()))?;
    let fvk: keygen::FullViewingKey = serde_json::from_str(&fvk_json)
        .context("parsing FVK JSON")?;

    let d: [u8; 11] = match (&args.diversifier, args.random) {
        (Some(hex_d), false) => {
            let raw = hex::decode(hex_d.trim()).context("hex-decoding --diversifier")?;
            if raw.len() != 11 {
                return Err(anyhow!("--diversifier must be 11 bytes (22 hex chars)"));
            }
            let mut arr = [0u8; 11];
            arr.copy_from_slice(&raw);
            arr
        }
        (None, true) => {
            use rand::RngCore;
            let mut arr = [0u8; 11];
            rand::thread_rng().fill_bytes(&mut arr);
            arr
        }
        _ => return Err(anyhow!("--diversifier or --random is required")),
    };

    let addr = address::Address::build(&fvk, &d)?;
    let addr_string = addr.to_string_with_hrp(&args.hrp);

    #[derive(serde::Serialize)]
    struct AddressOut {
        diversifier: String,
        pk_d: String,
        ivk_commitment: String,
        pk_mlkem_hex: String,
        wire_bytes_hex: String,
        address_string: String,
    }

    let out = AddressOut {
        diversifier:    hex::encode(addr.d),
        pk_d:           hex::encode(addr.pk_d),
        ivk_commitment: hex::encode(addr.ivk_commitment),
        pk_mlkem_hex:   hex::encode(&addr.pk_mlkem),
        wire_bytes_hex: hex::encode(addr.to_bytes()),
        address_string: addr_string,
    };
    println!("{}", serde_json::to_string_pretty(&out)?);
    Ok(())
}

// ---------------------------------------------------------------------------
// Scan
// ---------------------------------------------------------------------------

#[derive(Debug, clap::Args)]
struct ScanArgs {
    /// Path to FVK JSON.
    #[arg(long, required = true)]
    fvk: std::path::PathBuf,
    /// First block seqno (inclusive). Default: 0.
    #[arg(long, default_value_t = 0)]
    from_block: u64,
    /// Last block seqno (exclusive). Default: current head (fetched via RPC).
    #[arg(long)]
    to_block: Option<u64>,
    /// RPC endpoint base URL.
    #[arg(long, default_value = "http://localhost:8080")]
    rpc: String,
}

async fn run_scan(args: &ScanArgs) -> Result<()> {
    let fvk_json = std::fs::read_to_string(&args.fvk)?;
    let fvk: keygen::FullViewingKey = serde_json::from_str(&fvk_json)?;

    let rpc = rpc_client::RpcClient::new(&args.rpc)?;
    let end = match args.to_block {
        Some(e) => e,
        None => {
            let info = rpc.chain_info().await.context("fetching chain info")?;
            info.head_seqno + 1
        }
    };

    eprintln!("scanning blocks [{}, {}) via {}", args.from_block, end, args.rpc);
    let owned = scan::scan_range(&rpc, &fvk, args.from_block, end).await?;
    println!("{}", serde_json::to_string_pretty(&owned)?);
    eprintln!("found {} owned notes", owned.len());
    Ok(())
}

// ---------------------------------------------------------------------------
// Balance
// ---------------------------------------------------------------------------

#[derive(Debug, clap::Args)]
struct BalanceArgs {
    #[arg(long, required = true)]
    fvk: std::path::PathBuf,
    #[arg(long, default_value_t = 0)]
    from_block: u64,
    #[arg(long)]
    to_block: Option<u64>,
    #[arg(long, default_value = "http://localhost:8080")]
    rpc: String,
}

async fn run_balance(args: &BalanceArgs) -> Result<()> {
    let fvk_json = std::fs::read_to_string(&args.fvk)?;
    let fvk: keygen::FullViewingKey = serde_json::from_str(&fvk_json)?;

    let rpc = rpc_client::RpcClient::new(&args.rpc)?;
    let end = match args.to_block {
        Some(e) => e,
        None => rpc.chain_info().await?.head_seqno + 1,
    };
    let owned = scan::scan_range(&rpc, &fvk, args.from_block, end).await?;
    let bal = balance::balance_for_notes(&rpc, &owned).await?;
    println!("{}", serde_json::to_string_pretty(&bal)?);
    Ok(())
}

// ---------------------------------------------------------------------------
// Chain-info
// ---------------------------------------------------------------------------

#[derive(Debug, clap::Args)]
struct ChainInfoArgs {
    #[arg(long, default_value = "http://localhost:8080")]
    rpc: String,
}

async fn run_chain_info(args: &ChainInfoArgs) -> Result<()> {
    let rpc = rpc_client::RpcClient::new(&args.rpc)?;
    let info = rpc.chain_info().await?;
    println!("{}", serde_json::to_string_pretty(&info)?);
    Ok(())
}

// ---------------------------------------------------------------------------
// Send
// ---------------------------------------------------------------------------
//
// This is the M-send scaffold against a STUB Plonky3 prover — see
// `src/send.rs::plonky3_prove` for the M-P2 integration point.

#[derive(Debug, clap::Args)]
struct SendArgs {
    /// Path to FVK JSON (produced by `keygen`).
    #[arg(long, required = true)]
    fvk: std::path::PathBuf,
    /// Recipient address string (`uno1...` / `unos...`).
    #[arg(long, required = true)]
    to: String,
    /// Amount to send, in native UNO nano-units.
    #[arg(long, required = true)]
    amount: u64,
    /// Optional memo (UTF-8, max 479 bytes). Stored inside the encrypted
    /// note plaintext; never visible on-chain.
    #[arg(long)]
    memo: Option<String>,
    /// Explicit fee override, in nano-units. If omitted, the wallet queries
    /// `uno_estimateFee(spend_count=1, output_count=2)`.
    #[arg(long)]
    fee: Option<u64>,
    /// RPC endpoint.
    #[arg(long, default_value = "http://localhost:8080")]
    rpc: String,
    /// Build and print the Transfer but do NOT submit.
    #[arg(long)]
    dry_run: bool,
}

async fn run_send(args: &SendArgs) -> Result<()> {
    let send_args = send::SendArgs {
        fvk_path: args.fvk.clone(),
        rpc_url: args.rpc.clone(),
        to: args.to.clone(),
        amount: args.amount,
        memo: args.memo.clone(),
        fee: args.fee,
        dry_run: args.dry_run,
        skip_scan: false,
    };
    let summary = send::execute(&send_args).await?;
    println!("{}", serde_json::to_string_pretty(&summary)?);
    Ok(())
}

// ---------------------------------------------------------------------------
// Runtime entrypoint
// ---------------------------------------------------------------------------

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.cmd {
        Command::Keygen(args)    => run_keygen(&args),
        Command::Address(args)   => run_address(&args),
        Command::Scan(args)      => block_on(run_scan(&args)),
        Command::Balance(args)   => block_on(run_balance(&args)),
        Command::ChainInfo(args) => block_on(run_chain_info(&args)),
        Command::Send(args)      => block_on(run_send(&args)),
        Command::Genesis(GenesisCmd::Build(args)) => run_genesis_build(&args),
    }
}

fn block_on<F: std::future::Future<Output = Result<()>>>(f: F) -> Result<()> {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("creating tokio runtime")?;
    rt.block_on(f)
}
