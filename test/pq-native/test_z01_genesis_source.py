import importlib.util
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("z01", ROOT / "scripts/check-z01-genesis-source.py")
Z01 = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(Z01)


class GenesisSourceTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.production = (ROOT / "crypto/smartcont/gen-zerostate.fif").read_text()
        cls.harness = (ROOT / "test/tostester/src/tostester/zerostate.py").read_text()
        cls.manager = (ROOT / "validator/manager.cpp").read_text()

    def check(self, production=None, harness=None, manager=None):
        return Z01.check(
            self.production if production is None else production,
            self.harness if harness is None else harness,
            self.manager if manager is None else manager,
        )

    def test_fixed_sources_green(self):
        self.assertEqual([], self.check())

    def test_one_of_two_production_param30_cells_changed_red(self):
        original = "<b 400 32 u, b> <s 0 rot 8 udict! drop"
        self.assertEqual(2, self.production.count(original))
        changed = self.production.replace(original, "<b 500 32 u, b> <s 0 rot 8 udict! drop", 1)
        self.assertTrue(any("Param30" in error for error in self.check(production=changed)))

    def test_production_param16_or_28_ceiling_red(self):
        self.assertTrue(any("Param16" in error for error in self.check(production=self.production.replace("21 21 4 config.validator_num!", "22 21 4 config.validator_num!", 1))))
        self.assertTrue(any("Param28" in error for error in self.check(production=self.production.replace("250 250 1000 21 true config.catchain_params!", "250 250 1000 22 true config.catchain_params!", 1))))

    def test_local_genesis_simplex_default_red(self):
        changed = self.harness.replace("protocol_version: int = 2", "protocol_version: int = 1", 1)
        self.assertTrue(any("protocol_version" in error for error in self.check(harness=changed)))

    def test_manager_chain_selected_config_red(self):
        changed = self.manager.replace("last_masterchain_state_->get_selected_new_consensus_config(shard.workchain)", "local_simplex_config(shard.workchain)", 1)
        self.assertTrue(any("chain Param30" in error for error in self.check(manager=changed)))

    def test_manager_param30_identity_red(self):
        changed = self.manager.replace(".simplex_config_cell_hash = selected_config.value().cell_hash", ".simplex_config_cell_hash = local_config.cell_hash", 1)
        self.assertTrue(any("selected Param30" in error for error in self.check(manager=changed)))


if __name__ == "__main__":
    unittest.main()
