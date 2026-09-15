from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def replace_once(path: Path, before: str, after: str, label: str) -> None:
    text = path.read_text()
    count = text.count(before)
    if count != 1:
        raise RuntimeError(f"{label}: expected one anchor, found {count}")
    path.write_text(text.replace(before, after, 1))


# The first-pass patch adds a sandbox constructor that rebuilds BlockchainConfig
# through with_config(raw_config). The default raw config is intentionally
# minimal, so that route can require unrelated configuration entries. Mutate the
# already-valid local BlockchainConfig instead, updating its cached fields and
# matching ConfigParam 8 together.
config = ROOT / "tosctl/src/executor/src/blockchain_config.rs"
replace_once(
    config,
    "    pub fn global_version(&self) -> u32 {\n        self.global_version\n    }\n",
    "    pub fn global_version(&self) -> u32 {\n"
    "        self.global_version\n"
    "    }\n\n"
    "    /// Override the VM version and capability mask of a local executor\n"
    "    /// configuration while keeping its cached fields and ConfigParam 8\n"
    "    /// consistent. This changes only the in-process fixture/configuration\n"
    "    /// object; it does not activate a network configuration.\n"
    "    pub fn set_global_version_and_capabilities(\n"
    "        &mut self,\n"
    "        global_version: u32,\n"
    "        capabilities: u64,\n"
    "    ) -> Result<()> {\n"
    "        self.raw_config.set_config(ConfigParamEnum::ConfigParam8(ConfigParam8 {\n"
    "            global_version: GlobalVersion { version: global_version, capabilities },\n"
    "        }))?;\n"
    "        self.global_version = global_version;\n"
    "        self.capabilities = capabilities;\n"
    "        self.deferring_enabled = capabilities.bit(GlobalCapabilities::CapDeferMessages as u64);\n"
    "        Ok(())\n"
    "    }\n",
    "blockchain config local capability override",
)

sandbox = ROOT / "tosctl/src/sandbox/src/blockchain.rs"
replace_once(
    sandbox,
    "    tos_method_id, Account, ConfigParam8, ConfigParamEnum, ConfigParams, CurrencyCollection,\n"
    "    Deserializable, GlobalVersion, McStateExtra, MerkleProof, Message, MsgAddressInt,\n"
    "    Serializable, ShardIdent, ShardStateUnsplit, SizeLimitsConfig, Transaction,\n",
    "    tos_method_id, Account, ConfigParams, CurrencyCollection, Deserializable, McStateExtra,\n"
    "    MerkleProof, Message, MsgAddressInt, Serializable, ShardIdent, ShardStateUnsplit,\n"
    "    SizeLimitsConfig, Transaction,\n",
    "sandbox capability imports",
)
replace_once(
    sandbox,
    "    pub fn with_global_version_and_capabilities(\n"
    "        global_version: u32,\n"
    "        capabilities: u64,\n"
    "    ) -> SandboxResult<Self> {\n"
    "        let base = BlockchainConfig::default_with_global_version(global_version)\n"
    "            .map_err(|e| SandboxError::ConfigError(e.to_string()))?;\n"
    "        let mut config = base.raw_config().clone();\n"
    "        config\n"
    "            .set_config(ConfigParamEnum::ConfigParam8(ConfigParam8 {\n"
    "                global_version: GlobalVersion { version: global_version, capabilities },\n"
    "            }))\n"
    "            .map_err(|e| SandboxError::ConfigError(e.to_string()))?;\n"
    "        Self::with_config(config)\n"
    "    }\n",
    "    pub fn with_global_version_and_capabilities(\n"
    "        global_version: u32,\n"
    "        capabilities: u64,\n"
    "    ) -> SandboxResult<Self> {\n"
    "        let mut config = BlockchainConfig::default_with_global_version(global_version)\n"
    "            .map_err(|e| SandboxError::ConfigError(e.to_string()))?;\n"
    "        config\n"
    "            .set_global_version_and_capabilities(global_version, capabilities)\n"
    "            .map_err(|e| SandboxError::ConfigError(e.to_string()))?;\n"
    "        let mc_state_cell = Self::build_mc_state_cell(config.raw_config())?;\n"
    "        Ok(Self {\n"
    "            accounts: HashMap::new(),\n"
    "            config,\n"
    "            mc_state_cell,\n"
    "            next_lt: DEFAULT_BLOCK_LT,\n"
    "            block_unixtime: DEFAULT_BLOCK_UNIXTIME,\n"
    "            max_message_depth: DEFAULT_MAX_MESSAGE_DEPTH,\n"
    "            workchain: 0,\n"
    "            transaction_log: Vec::new(),\n"
    "            validator_auth_host: None,\n"
    "        })\n"
    "    }\n",
    "sandbox capability constructor",
)

print("CONFIG_PERSISTENCE_FIXUP_OK")
