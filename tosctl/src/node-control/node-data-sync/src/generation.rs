use crate::{
    capture::public_files,
    cas::Objects,
    engine::ValidationResult,
    model::{MANIFEST_LIMIT, Manifest, Network, SignedManifest, approved_forks},
    safe_io::Root,
    service::Frozen,
};
use anyhow::{Context, Result, ensure};
use chain_block::{Block, Deserializable, read_single_root_boc};
use ed25519_dalek::SigningKey;
use std::time::{SystemTime, UNIX_EPOCH};

pub struct GenerationPolicy<'a> {
    pub global_config: &'a [u8],
    pub global_id: i32,
    pub references: &'a crate::references::ReferencePolicy,
}
/// Assemble only a fully native-checked private image; no caller-supplied readiness flag.
pub fn assemble(
    image: &Root,
    checked: &Root,
    policy: GenerationPolicy<'_>,
    objects: &Objects,
    signing_key: &SigningKey,
    catalog: &crate::catalog::Catalog,
) -> Result<SignedManifest> {
    let GenerationPolicy { global_config: policy, global_id, references } = policy;
    let _frozen = Frozen::acquire(&image.path)?;
    let result: ValidationResult =
        serde_json::from_slice(&checked.bytes("validation.json", MANIFEST_LIMIT)?)?;
    let permanent_cells = result.validation.permanent_cells;
    let network = Network::from_global(policy, global_id)?;
    ensure!(
        result.validation.policy_sha256 == crate::model::sha256(policy),
        "validation used another held policy"
    );
    let chain =
        crate::records::ChainRecords::parse(&checked.bytes("state-records.cbor", MANIFEST_LIMIT)?)?;
    ensure!(chain.frontier()? == result.validation.frontier, "validated StateDb frontier changed");
    let forks = approved_forks(policy)?;
    crate::records::reconcile_forks(&forks, &chain, &[], &result.ancestors.into_iter().collect())?;
    let tip = checked.bytes("tip-block.boc", MANIFEST_LIMIT)?;
    let frontier_utime = u64::from(
        Block::construct_from_cell(read_single_root_boc(&tip)?)?.read_info()?.gen_utime(),
    );
    let writer = objects.writer()?;
    let mut files = Vec::new();
    for file in public_files(image)? {
        let native = file.path.strip_prefix("chain/").context("public file native path")?;
        files.push(writer.put(&file.path, image.read(native, file.size)?, file.size)?);
    }
    for (public, local) in [
        ("state-records.cbor", "state-records.cbor"),
        ("metadata/zero-state.boc", "zero-state.boc"),
        ("metadata/tip-block.boc", "tip-block.boc"),
    ] {
        let file = checked.read(local, MANIFEST_LIMIT)?;
        let size = file.metadata()?.len();
        files.push(writer.put(public, file, size)?);
    }
    files.sort_by(|a, b| a.path.cmp(&b.path));
    let frontier = result.validation.frontier.clone();
    let approval = references.corroborate(
        &network,
        &frontier,
        &crate::model::sha256(&serde_json::to_vec(&result.validation)?),
    )?;
    let manifest = Manifest {
        format: 2,
        corroboration: approval.receipt()?,
        network,
        frontier,
        frontier_utime,
        created_utc: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
        source_build: result.validation.engine_sha256.clone(),
        database_version: 2,
        retained_from: chain.gc()?,
        permanent_cells,
        coverage: result.coverage,
        approved_forks: forks,
        validation: result.validation,
        capture: serde_json::from_slice(
            &Root::open(checked.path.parent().context("capture receipt parent")?)?
                .bytes("capture.json", MANIFEST_LIMIT)?,
        )?,
        files,
    };
    // Bind the exact image to the independently held public anchor before making it signable.
    crate::metadata::validate(&manifest, &checked.bytes("zero-state.boc", MANIFEST_LIMIT)?, &tip)?;
    approval.receipt()?;
    let signed = SignedManifest::sign(manifest, signing_key)?;
    crate::catalog::verify_generation(&signed, objects, &signing_key.verifying_key().to_bytes())?;
    catalog.prepare(&signed, &writer)?;
    Ok(signed)
}
