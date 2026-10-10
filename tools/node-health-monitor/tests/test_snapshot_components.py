"""Keep admission, schema generation and shipped snapshot contracts in agreement."""

import importlib.util
import json
import re
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SUPPORTED = ["process", "host", "chain", "consensus", "storage"]


class SnapshotComponents(unittest.TestCase):
    def test_admission_and_regeneration_agree(self):
        source = (ROOT / "crates/health-core/src/query.rs").read_text()
        declaration = re.search(r"SNAPSHOT_COMPONENTS:.*?=\s*&\[(.*?)\];", source, re.S)
        self.assertIsNotNone(declaration)
        self.assertEqual(re.findall(r'"([a-z_]+)"', declaration[1]), SUPPORTED)
        spec = importlib.util.spec_from_file_location(
            "contract_generator", ROOT / "scripts/generate-contracts.py"
        )
        generator = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(generator)
        with tempfile.TemporaryDirectory() as directory:
            generator.ROOT = Path(directory)
            generator.main()
            regenerated = json.loads(
                (
                    generator.ROOT / "contracts/tools/tos_get_node_snapshot.input.schema.json"
                ).read_text()
            )
            output = json.loads(
                (
                    generator.ROOT / "contracts/tools/tos_get_node_snapshot.output.schema.json"
                ).read_text()
            )
        self.assertEqual(regenerated["properties"]["components"]["items"]["enum"], SUPPORTED)
        self.assertEqual(output["$defs"]["component"]["properties"]["kind"]["enum"], SUPPORTED)
        self.assertIn("host_cgroup", output["$defs"])
        for path in [
            "contracts/tool-input-schemas.json",
            "contracts/tools/tos_get_node_snapshot.input.schema.json",
        ]:
            document = json.loads((ROOT / path).read_text())
            if "tool-input" in path:
                document = document["tos_get_node_snapshot"]
            self.assertEqual(document["properties"]["components"]["items"]["enum"], SUPPORTED)
        shipped = json.loads(
            (ROOT / "contracts/tools/tos_get_node_snapshot.output.schema.json").read_text()
        )
        self.assertEqual(shipped["$defs"]["component"]["properties"]["kind"]["enum"], SUPPORTED)
        self.assertEqual(shipped["$defs"]["host_cgroup"], output["$defs"]["host_cgroup"])


if __name__ == "__main__":
    unittest.main()
