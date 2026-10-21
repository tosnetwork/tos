use crate::{
    model::{MANIFEST_LIMIT, Network, hash},
    safe_io::{Root, file_hash},
    service::Service,
};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    path::{Path, PathBuf},
};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeContext {
    pub unit: String,
    pub user_manager: bool,
    pub database: PathBuf,
    pub engine: PathBuf,
    pub engine_sha256: String,
    pub validation_worker: PathBuf,
    pub validation_worker_sha256: String,
    pub global_config: PathBuf,
    pub global_id: i32,
    pub work_root: PathBuf,
    pub working_directory: PathBuf,
    pub operator_config: PathBuf,
    pub node_name: String,
    /// Every task-owned source, cache, staging and build root; include retained old operations.
    pub budget_roots: Vec<PathBuf>,
    #[serde(default)]
    pub disk_policy: crate::budget::DiskPolicy,
    pub vault_config_files: Vec<PathBuf>,
    pub references: crate::references::ReferencePolicy,
}
impl NodeContext {
    pub fn load(path: &Path) -> Result<Self> {
        let path = std::path::absolute(path)?;
        let root = Root::open(path.parent().context("node context parent")?)?;
        let bytes = root.bytes(
            path.file_name().and_then(|n| n.to_str()).context("node context filename")?,
            1 << 20,
        )?;
        let context: Self = serde_json::from_slice(&bytes)?;
        context.validate_paths()?;
        Ok(context)
    }
    pub fn preservation_files(&self) -> Result<Vec<PathBuf>> {
        ensure!(self.vault_config_files.len() <= 32, "vault configuration count limit");
        let mut paths = self.service().definitions()?;
        for path in &self.vault_config_files {
            ensure!(
                path.is_absolute() && path.canonicalize()? == *path,
                "vault configuration is not canonical"
            );
            self.private_path(path)?;
            paths.push(path.clone());
        }
        paths.sort();
        paths.dedup();
        Ok(paths)
    }
    pub fn service(&self) -> Service {
        Service {
            unit: self.unit.clone(),
            user_manager: self.user_manager,
            database: self.database.clone(),
            engine: self.engine.clone(),
            global_config: self.global_config.clone(),
            working_directory: self.working_directory.clone(),
        }
    }
    pub fn validate_paths(&self) -> Result<()> {
        self.references.normalized()?;
        ensure!(
            !self.node_name.is_empty() && self.node_name.len() <= 128,
            "missing or oversized configured node name"
        );
        for path in [
            &self.database,
            &self.engine,
            &self.validation_worker,
            &self.global_config,
            &self.work_root,
            &self.working_directory,
            &self.operator_config,
        ] {
            ensure!(
                path.is_absolute() && fs::canonicalize(path)? == *path,
                "node context paths must be canonical and link-free"
            );
        }
        ensure!(
            !self.budget_roots.is_empty() && self.budget_roots.len() <= 32,
            "task allocation inventory is missing or oversized"
        );
        for (index, root) in self.budget_roots.iter().enumerate() {
            ensure!(
                root.is_absolute() && root.canonicalize()? == *root,
                "budget root is not canonical"
            );
            ensure!(
                !self
                    .budget_roots
                    .iter()
                    .take(index)
                    .any(|previous| root.starts_with(previous) || previous.starts_with(root)),
                "overlapping budget roots"
            );
        }
        ensure!(
            self.budget_roots.iter().any(|root| self.database.starts_with(root)),
            "database missing from task allocation inventory"
        );
        self.disk_policy.threshold(Root::open(&self.database)?.space()?)?;
        hash(&self.engine_sha256)?;
        hash(&self.validation_worker_sha256)?;
        let (_, digest) = file_hash(read_file(&self.engine, 1 << 30)?, 1 << 30)?;
        ensure!(digest == self.engine_sha256, "installed engine differs from held build digest");
        ensure!(
            !self.engine.starts_with(&self.database)
                && !self.validation_worker.starts_with(&self.database),
            "installed executables must remain outside exchanged data"
        );
        self.private_path(&self.global_config)?;
        self.private_path(&self.operator_config)?;
        self.private_path(&self.work_root.join("keys"))?;
        ensure!(
            !self.working_directory.starts_with(self.database.join("tmp"))
                && !self.working_directory.starts_with(self.database.join("import")),
            "service working directory is old recovery/import context"
        );
        Ok(())
    }
    pub fn private_path(&self, path: &Path) -> Result<()> {
        ensure!(
            ![
                "celldb",
                "files",
                "archive",
                "static",
                "state",
                "tmp",
                "import",
                "consensus",
                "catchains"
            ]
            .iter()
            .any(|name| path.starts_with(self.database.join(name))),
            "private configuration or key overlaps chain, signing or recovery context"
        );
        Ok(())
    }
    pub fn policy(&self) -> Result<(Network, Vec<u8>)> {
        let bytes = read_bytes(&self.global_config, MANIFEST_LIMIT)?;
        Ok((Network::from_global(&bytes, self.global_id)?, bytes))
    }
    pub fn source_role(&self) -> Result<()> {
        let config: serde_json::Value = serde_json::from_slice(
            &Root::open(&self.database)?.bytes("config.json", MANIFEST_LIMIT)?,
        )?;
        ensure!(
            config.get("validators").and_then(|v| v.as_array()).is_some_and(Vec::is_empty),
            "snapshot source has validator registrations"
        );
        ensure!(
            config.pointer("/extraconfig/pq_consensus").is_none_or(|v| v.is_null()),
            "snapshot source has signing custody"
        );
        let operator = common::app_config::AppConfig::load(&self.operator_config)?;
        ensure!(
            operator.nodes.contains_key(&self.node_name),
            "operator configuration has no selected source node"
        );
        let selected =
            operator.nodes.get(&self.node_name).context("selected source node missing")?;
        let selected_key = serde_json::to_value(&selected.server_key)?;
        for (name, node) in &operator.nodes {
            let same_server = node.server_address == selected.server_address
                || serde_json::to_value(&node.server_key)? == selected_key;
            ensure!(
                !same_server || operator.bindings.get(name).is_none_or(|binding| !binding.enable),
                "snapshot source or a configured alias has an enabled election binding"
            );
        }
        Ok(())
    }
    pub fn bind_control(&self, server_id: &[u8; 32]) -> Result<()> {
        use base64::Engine;
        let config: serde_json::Value = serde_json::from_slice(
            &Root::open(&self.database)?.bytes("config.json", MANIFEST_LIMIT)?,
        )?;
        let controls = config
            .get("control")
            .and_then(|v| v.as_array())
            .context("node has no configured control identity")?;
        let mut matched = false;
        for control in controls {
            let key =
                control.get("id").and_then(|v| v.as_str()).context("control id is invalid")?;
            let key = base64::engine::general_purpose::STANDARD.decode(key)?;
            ensure!(key.len() == 32, "control id length");
            matched |= key == *server_id;
        }
        ensure!(
            matched,
            "configured control client belongs to a different node than the selected database"
        );
        Ok(())
    }
}
pub fn read_file(path: &Path, max: u64) -> Result<fs::File> {
    let path = std::path::absolute(path)?;
    let root = Root::open(path.parent().context("file parent")?)?;
    root.read(path.file_name().and_then(|n| n.to_str()).context("filename")?, max)
}
pub fn read_bytes(path: &Path, max: u64) -> Result<Vec<u8>> {
    use std::io::Read;
    let mut bytes = Vec::new();
    read_file(path, max)?
        .take(max.checked_add(1).context("read size overflow")?)
        .read_to_end(&mut bytes)?;
    ensure!(bytes.len() as u64 <= max, "file grew beyond byte limit");
    Ok(bytes)
}
