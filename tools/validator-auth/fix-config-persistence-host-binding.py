from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def replace_once(path: Path, before: str, after: str, label: str) -> None:
    text = path.read_text()
    count = text.count(before)
    if count != 1:
        raise RuntimeError(f"{label}: expected one anchor, found {count}")
    path.write_text(text.replace(before, after, 1))


executor = ROOT / "tosctl/src/executor/src/transaction_executor.rs"
replace_once(
    executor,
    "#[derive(Clone, Default)]\n"
    "pub struct ExecuteParams {\n",
    "#[derive(Clone)]\n"
    "pub struct ValidatorAuthHostBinding {\n"
    "    account: MsgAddressInt,\n"
    "    host: Arc<Mutex<dyn tos_vm::validator_auth_host::ValidatorAuthHost>>,\n"
    "}\n\n"
    "impl ValidatorAuthHostBinding {\n"
    "    pub fn new(\n"
    "        account: MsgAddressInt,\n"
    "        host: Arc<Mutex<dyn tos_vm::validator_auth_host::ValidatorAuthHost>>,\n"
    "    ) -> Self {\n"
    "        Self { account, host }\n"
    "    }\n"
    "}\n\n"
    "#[derive(Clone, Default)]\n"
    "pub struct ExecuteParams {\n",
    "executor host binding type",
)
replace_once(
    executor,
    "    /// Native transaction authority supplied by the host process. Contract\n"
    "    /// registers and c7 cannot construct or replace this value.\n"
    "    pub validator_auth_host: Option<\n"
    "        Arc<Mutex<dyn tos_vm::validator_auth_host::ValidatorAuthHost>>,\n"
    "    >,\n",
    "    /// Native transaction authority supplied by the host process and bound\n"
    "    /// to exactly one destination account. Contract registers and c7 cannot\n"
    "    /// construct, replace, or retarget this value.\n"
    "    pub validator_auth_host: Option<ValidatorAuthHostBinding>,\n",
    "executor bound host parameter",
)
replace_once(
    executor,
    "        if let Some(host) = params.validator_auth_host.clone() {\n"
    "            vm.set_validator_auth_host(host);\n"
    "        }\n",
    "        if let Some(binding) = params.validator_auth_host.clone() {\n"
    "            if acc.get_addr().is_some_and(|address| address == &binding.account) {\n"
    "                vm.set_validator_auth_host(binding.host);\n"
    "            }\n"
    "        }\n",
    "executor account-bound host installation",
)

sandbox = ROOT / "tosctl/src/sandbox/src/blockchain.rs"
replace_once(
    sandbox,
    "    BlockchainConfig, ExecuteParams, OrdinaryTransactionExecutor, TransactionExecutor,\n",
    "    BlockchainConfig, ExecuteParams, OrdinaryTransactionExecutor, TransactionExecutor,\n"
    "    ValidatorAuthHostBinding,\n",
    "sandbox binding import",
)
replace_once(
    sandbox,
    "    validator_auth_host: Option<\n"
    "        Arc<Mutex<dyn tos_vm::validator_auth_host::ValidatorAuthHost>>,\n"
    "    >,\n",
    "    validator_auth_host: Option<ValidatorAuthHostBinding>,\n",
    "sandbox bound host field",
)
replace_once(
    sandbox,
    "    pub fn set_validator_auth_host(\n"
    "        &mut self,\n"
    "        host: Option<Arc<Mutex<dyn tos_vm::validator_auth_host::ValidatorAuthHost>>>,\n"
    "    ) {\n"
    "        self.validator_auth_host = host;\n"
    "    }\n",
    "    pub fn set_validator_auth_host(\n"
    "        &mut self,\n"
    "        account: MsgAddressInt,\n"
    "        host: Arc<Mutex<dyn tos_vm::validator_auth_host::ValidatorAuthHost>>,\n"
    "    ) {\n"
    "        self.validator_auth_host = Some(ValidatorAuthHostBinding::new(account, host));\n"
    "    }\n",
    "sandbox bound host setter",
)

rust_test = ROOT / "tosctl/src/node-control/contracts/tests/native_registry_sandbox.rs"
replace_once(
    rust_test,
    "        bc.set_validator_auth_host(Some(host));\n"
    "        (bc, address, applies)\n",
    "        bc.set_validator_auth_host(address.clone(), host);\n"
    "        (bc, address, applies)\n",
    "sandbox test bound host setup",
)
insert_after = '''    #[test]\n    fn refused_action_phase_rolls_registry_back() {\n        const NAME: &str = "refused_action_phase_rolls_registry_back";\n        println!("SETUP_OK {NAME}");\n        std::io::stdout().flush().unwrap();\n        let fixture = cells();\n        assert!(same_cell(parameter(&fixture.old_data, 46), &fixture.before), "fixture must contain the old registry");\n        let (mut bc, address, applies) = setup(fixture.old_data.clone(), &fixture);\n        let mut limits = SizeLimitsConfig::default();\n        limits.max_mc_acc_state_cells = 1;\n        bc.set_size_limits_config(limits).expect("tight account limit");\n\n        let result = send(&mut bc, &address, fixture.body.clone());\n        result.expect_aborted().expect_exit_code(0);\n        let descr = result.read_primary_description();\n        let TrComputePhase::Vm(compute) = descr.compute_ph else {\n            panic!("registry update did not execute in compute phase");\n        };\n        assert!(compute.success, "registry compute phase did not commit");\n        let action = descr.action.expect("action phase must run");\n        assert!(!action.success, "tight account limit must refuse the action phase");\n        assert_eq!(action.result_code, ACTION_LIMIT_FAILURE, "unexpected action refusal");\n        assert_eq!(applies.load(Ordering::SeqCst), 1, "native apply must execute before rollback");\n\n        let data = persisted_data(&bc, &address);\n        assert_eq!(data.hash(0), fixture.old_data.hash(0), "aborted action phase persisted compute data");\n        assert!(same_cell(parameter(&data, 46), &fixture.before), "aborted action phase half-applied the registry");\n        println!("CASE_PASS {NAME}");\n    }\n'''
addition = insert_after + '''\n    #[test]\n    fn validator_auth_host_is_bound_to_configuration_account() {\n        const NAME: &str = "validator_auth_host_is_bound_to_configuration_account";\n        println!("SETUP_OK {NAME}");\n        std::io::stdout().flush().unwrap();\n        let fixture = cells();\n        let (mut bc, authority_account, applies) = setup(fixture.empty_data.clone(), &fixture);\n        let other = MsgAddressInt::standard(-1, [0x78; 32].into());\n        assert_ne!(other, authority_account, "fixture accounts must differ");\n        let state_init = StateInit::with_code_and_data(fixture.contract.clone(), fixture.empty_data.clone());\n        let account = Account::active(\n            other.clone(),\n            CurrencyCollection::with_coins(CONFIG_BALANCE),\n            0,\n            bc.now(),\n            state_init,\n            DICT_HASH_MIN_CELLS,\n        )\n        .expect("other configuration-shaped account");\n        bc.set_account(other.clone(), account);\n\n        let before = persisted_data(&bc, &other);\n        let result = bc.send_message(MessageBuilder::external(&other).body(fixture.body.clone()).build());\n        assert!(result.is_err(), "authority leaked to an account other than the bound destination");\n        assert_eq!(applies.load(Ordering::SeqCst), 0, "native host was reached by the wrong account");\n        let after = persisted_data(&bc, &other);\n        assert_eq!(after.hash(0), before.hash(0), "rejected wrong-account execution changed data");\n        println!("CASE_PASS {NAME}");\n    }\n'''
replace_once(rust_test, insert_after, addition, "wrong-account sandbox case")

mutations = ROOT / "test/validator-auth-implementation/config_action_phase_mutations.py"
replace_once(
    mutations,
    "CASES = [\n"
    "    \"config_persistence_action_phase::accepted_registry_persists_after_action_phase\",\n"
    "    \"config_persistence_action_phase::refused_action_phase_rolls_registry_back\",\n"
    "]\n",
    "CASES = [\n"
    "    \"config_persistence_action_phase::accepted_registry_persists_after_action_phase\",\n"
    "    \"config_persistence_action_phase::refused_action_phase_rolls_registry_back\",\n"
    "    \"config_persistence_action_phase::validator_auth_host_is_bound_to_configuration_account\",\n"
    "]\n",
    "rust mutation case inventory",
)
replace_once(
    mutations,
    "        \"        if let Some(host) = params.validator_auth_host.clone() {\\n\"\n"
    "        \"            vm.set_validator_auth_host(host);\\n\"\n"
    "        \"        }\\n\",\n",
    "        \"        if let Some(binding) = params.validator_auth_host.clone() {\\n\"\n"
    "        \"            if acc.get_addr().is_some_and(|address| address == &binding.account) {\\n\"\n"
    "        \"                vm.set_validator_auth_host(binding.host);\\n\"\n"
    "        \"            }\\n\"\n"
    "        \"        }\\n\",\n",
    "host-removal mutation anchor",
)
# Add an explicit mutation that removes only the account comparison while still
# injecting the same authority, proving the binding is not decorative.
needle = '''    (\n        "action-refusal-rolls-back-data",\n        CASES[1],\n'''
if mutations.read_text().count(needle) != 1:
    raise RuntimeError("rollback mutation anchor changed")
wrong_account_mutation = '''    (\n        "transaction-host-account-bound",\n        CASES[2],\n        "            if acc.get_addr().is_some_and(|address| address == &binding.account) {\\n"\n        "                vm.set_validator_auth_host(binding.host);\\n"\n        "            }\\n",\n        "            vm.set_validator_auth_host(binding.host);\\n",\n        [],\n    ),\n'''
mutations.write_text(mutations.read_text().replace(needle, wrong_account_mutation + needle, 1))

print("CONFIG_PERSISTENCE_HOST_BINDING_FIXUP_OK")
