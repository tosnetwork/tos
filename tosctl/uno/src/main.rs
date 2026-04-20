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
//! | `send`       | ⬜     | Build + prove + send a Transfer — **not in P.6 scope** |

use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand};
use tosctl_uno::{address, balance, keygen, rpc_client, scan};

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
    /// Build, prove, and submit a Transfer. **Not implemented in P.6
    /// foundation** — needs the full P.2 Transfer AIR.
    Send(SendArgs),
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
// Send (stub)
// ---------------------------------------------------------------------------

#[derive(Debug, clap::Args)]
struct SendArgs {
    #[arg(long)]
    fvk: Option<std::path::PathBuf>,
    #[arg(long)]
    to: Option<String>,
    #[arg(long)]
    amount: Option<u64>,
}

fn run_send(_args: &SendArgs) -> Result<()> {
    Err(anyhow!(
        "`tosctl uno send` is not implemented in the P.6 foundation. It \
         requires the full Plonky3 Transfer AIR (P.2), which is still in \
         flight. Use this CLI for keygen / address / scan / balance today; \
         `send` will land in a follow-up commit once P.2 passes internal review."
    ))
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
        Command::Send(args)      => run_send(&args),
    }
}

fn block_on<F: std::future::Future<Output = Result<()>>>(f: F) -> Result<()> {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("creating tokio runtime")?;
    rt.block_on(f)
}
