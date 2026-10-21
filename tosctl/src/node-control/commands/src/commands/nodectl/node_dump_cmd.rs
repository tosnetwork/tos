use anyhow::{Context, Result, ensure};
use clap::{Args, Subcommand};
use node_data_sync::{
    cas::Objects,
    catalog::{Catalog, verify_generation},
    model::{MANIFEST_LIMIT, Network, SignedManifest},
    safe_io::Root,
};
use std::path::{Path, PathBuf};

#[derive(Args, Clone)]
pub struct NodeDumpCmd {
    #[command(subcommand)]
    action: DumpAction,
}
#[derive(Subcommand, Clone)]
enum DumpAction {
    /// Stop a non-validating source, cold-copy and natively validate a signed generation
    #[cfg(feature = "node-data-sync-native")]
    Create(CreateArgs),
    /// Verify signed metadata and every object without opening or mutating databases
    Verify(VerifyArgs),
    /// List retained signed generations
    List(CatalogArgs),
    /// Publish an already verified generation from the same local object store
    Publish(PublishArgs),
    /// Remove old unleased generation metadata, retaining the newest two
    Prune(CatalogArgs),
}
#[cfg(feature = "node-data-sync-native")]
#[derive(Args, Clone)]
struct CreateArgs {
    #[arg(long)]
    context: PathBuf,
    #[arg(long)]
    operation: PathBuf,
    #[arg(long)]
    directory: PathBuf,
    /// Existing private 32-byte publisher seed; never a validator key
    #[arg(long)]
    signing_key: PathBuf,
}
#[derive(Args, Clone)]
struct CatalogArgs {
    #[arg(long)]
    directory: PathBuf,
    /// Independently held publisher public key, lower-case hex
    #[arg(long)]
    publisher_key: String,
}
#[derive(Args, Clone)]
struct VerifyArgs {
    #[arg(long)]
    manifest: PathBuf,
    #[arg(long)]
    objects: PathBuf,
    #[arg(long)]
    publisher_key: String,
    #[arg(long)]
    global_config: PathBuf,
    #[arg(long)]
    global_id: i32,
}
#[derive(Args, Clone)]
struct PublishArgs {
    /// Two independently selected reference endpoints, each queried before publication
    #[arg(long = "reference", required = true)]
    references: Vec<String>,
    #[command(flatten)]
    verify: VerifyArgs,
    /// Must be the same store whose objects were verified
    #[arg(long)]
    directory: PathBuf,
}
fn key(text: &str) -> Result<[u8; 32]> {
    node_data_sync::model::hash(text)?;
    hex::decode(text)?.try_into().map_err(|_| anyhow::anyhow!("publisher key length"))
}
fn bytes(path: &Path) -> Result<Vec<u8>> {
    let path = std::path::absolute(path)?;
    let parent = Root::open(path.parent().context("metadata parent")?)?;
    parent.bytes(
        path.file_name().and_then(|s| s.to_str()).context("metadata filename")?,
        MANIFEST_LIMIT,
    )
}
fn verify(args: &VerifyArgs) -> Result<(SignedManifest, Objects, [u8; 32])> {
    let trusted = key(&args.publisher_key)?;
    let signed = SignedManifest::parse(&bytes(&args.manifest)?, &trusted)?;
    let policy = bytes(&args.global_config)?;
    let held = Network::from_global(&policy, args.global_id)?;
    ensure!(
        signed.manifest.approved_forks == node_data_sync::model::approved_forks(&policy)?,
        "generation differs from locally approved fork policy"
    );
    ensure!(signed.manifest.network == held, "generation differs from held network identity");
    let objects = Objects::open(&args.objects)?;
    verify_generation(&signed, &objects, &trusted)?;
    Ok((signed, objects, trusted))
}
impl NodeDumpCmd {
    pub async fn run(&self) -> Result<()> {
        // Native file verification can be substantial; keep it off the async control scheduler.
        let action = self.action.clone();
        tokio::task::spawn_blocking(move || -> Result<()> {
            match action {
                #[cfg(feature = "node-data-sync-native")]
                DumpAction::Create(args) => {
                    let context = node_data_sync::context::NodeContext::load(&args.context)?;
                    let publisher =
                        node_data_sync::publisher::PublisherSecret::load(&args.signing_key)?;
                    println!(
                        "prepared generation {}",
                        node_data_sync::operations::create(
                            &context,
                            &args.operation,
                            &args.directory,
                            &publisher
                        )?
                    );
                }
                DumpAction::Verify(args) => {
                    let (signed, _, trusted) = verify(&args)?;
                    println!("verified generation {}", signed.verify(&trusted)?);
                }
                DumpAction::List(args) => {
                    let catalog = Catalog::open(&args.directory, key(&args.publisher_key)?)?;
                    for (digest, signed) in catalog.list()? {
                        println!(
                            "{digest} {} {}",
                            signed.manifest.created_utc, signed.manifest.frontier.seqno
                        );
                    }
                }
                DumpAction::Publish(args) => {
                    ensure!(
                        args.directory.canonicalize()? == args.verify.objects.canonicalize()?,
                        "catalog and object store must be one directory"
                    );
                    let (signed, objects, trusted) = verify(&args.verify)?;
                    let catalog = Catalog::open(&args.directory, trusted)?;
                    println!(
                        "published generation {}",
                        catalog.publish(
                            &signed,
                            &objects,
                            &node_data_sync::references::ReferencePolicy::from_endpoints(
                                &args.references
                            )?
                        )?
                    );
                }
                DumpAction::Prune(args) => {
                    let catalog = Catalog::open(&args.directory, key(&args.publisher_key)?)?;
                    println!("{}", serde_json::to_string(&catalog.prune()?)?);
                }
            }
            Ok(())
        })
        .await??;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    #[derive(Parser)]
    struct Cli {
        #[command(flatten)]
        dump: NodeDumpCmd,
    }
    #[test]
    fn publication_accepts_repeatable_reference_flags() {
        let parsed = Cli::try_parse_from([
            "dump",
            "publish",
            "--manifest",
            "manifest.json",
            "--objects",
            "catalog",
            "--directory",
            "catalog",
            "--publisher-key",
            "key",
            "--global-config",
            "global.json",
            "--global-id",
            "3",
            "--reference",
            "http://127.0.0.1:10001/jsonRPC",
            "--reference",
            "http://127.0.0.1:10002/jsonRPC",
        ])
        .expect("documented repeatable reference flags must parse");
        let DumpAction::Publish(args) = parsed.dump.action else {
            panic!("wrong action");
        };
        assert_eq!(args.references.len(), 2);
        node_data_sync::references::ReferencePolicy::from_endpoints(&args.references)
            .expect("two distinct documented endpoints");
    }
}
