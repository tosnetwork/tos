import hashlib
import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "test/tostester/src"))
SPEC = importlib.util.spec_from_file_location("z01_lite_quartet", ROOT / "scripts/z01_lite_quartet.py")
assert SPEC and SPEC.loader
lite = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(lite)

# Mimics lite-client batch mode: exit 0 whenever the liteserver answered, and
# save files only in the places the production client writes them.
FAKE_LITE = r'''
import os, sys, shutil
args = sys.argv[1:]
db = args[args.index("-D") + 1] if "-D" in args else None
command = args[args.index("-c") + 1]
mode = os.environ["FAKE_MODE"]
payload = os.environ["FAKE_PAYLOAD"]
if command.startswith("getblock "):
    file_hash = command.rsplit(":", 1)[1]
    if mode != "no-save":
        target = os.path.join(db, file_hash[0:2], file_hash[2:4], file_hash[4:6], file_hash[6:8])
        os.makedirs(target)
        shutil.copyfile(payload, os.path.join(target, file_hash + ".boc"))
elif command.startswith("saveconfig "):
    _, filename, _ = command.split(" ")
    if mode != "no-save":
        shutil.copyfile(payload, filename)
        size = os.path.getsize(filename)
        print(f"saved configuration dictionary into file `{filename}` ({size} bytes written)")
sys.exit(0)
'''


def exact(file_hash: str) -> tuple:
    return (-1, -(1 << 63), 12, "11" * 32, file_hash)


def config_dictionary(values: dict[int, bytes]) -> tuple[bytes, dict[str, str]]:
    from pytosiq_core import Builder
    from pytosiq_core.boc.hashmap.hashmap import HashMap

    mapping = HashMap(32, value_serializer=lambda src, dest: dest.store_ref(src))
    hashes = {}
    for key, data in values.items():
        cell = Builder().store_bytes(data).end_cell()
        mapping.set_int_key(key, cell)
        hashes[str(key)] = cell.hash.hex()
    return mapping.serialize().to_boc(), hashes


class LiteQuartet(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.dir = Path(self.temp.name)
        self.fake = self.dir / "lite-client.py"
        self.fake.write_text(FAKE_LITE)
        self.config = self.dir / "lite.json"
        self.config.write_text("{}")

    def tearDown(self):
        self.temp.cleanup()
        for name in ("FAKE_MODE", "FAKE_PAYLOAD"):
            os.environ.pop(name, None)

    def arm(self, mode: str, payload: bytes) -> None:
        path = self.dir / f"payload-{mode}"
        path.write_bytes(payload)
        os.environ["FAKE_MODE"] = mode
        os.environ["FAKE_PAYLOAD"] = str(path)

    def test_block_id_text_matches_lite_client_parser_shape(self):
        text = lite.block_id_text(exact("ab" * 32))
        self.assertEqual(text, "(-1,8000000000000000,12):" + "11" * 32 + ":" + "AB" * 32)
        self.assertEqual(len(text) - text.index(")") - 1, 2 * 65)
        with self.assertRaisesRegex(lite.LiteError, "digests are invalid"):
            lite.block_id_text((-1, -(1 << 63), 12, "00" * 32, "ab" * 32))
        with self.assertRaisesRegex(lite.LiteError, "not a masterchain"):
            lite.block_id_text((0, -(1 << 63), 12, "11" * 32, "ab" * 32))

    def test_fetch_block_requires_saved_bytes_with_the_exact_file_hash(self):
        block = b"raw block boc bytes"
        file_hash = hashlib.sha256(block).hexdigest()
        self.arm("ok", block)
        out = self.dir / "ok"
        out.mkdir()
        row = lite.fetch_block(self.fake, self.config, exact(file_hash), out, "b12", [sys.executable])
        self.assertEqual(Path(row["path"]).read_bytes(), block)

        self.arm("ok", b"other bytes")
        out = self.dir / "wrong"
        out.mkdir()
        with self.assertRaisesRegex(lite.LiteError, "saved block bytes differ from the full-ID file hash"):
            # The fake names the file by the requested hash but writes other bytes.
            lite.fetch_block(self.fake, self.config, exact(file_hash), out, "b12", [sys.executable])

        self.arm("no-save", block)
        out = self.dir / "absent"
        out.mkdir()
        with self.assertRaisesRegex(lite.LiteError, "did not save the requested block"):
            lite.fetch_block(self.fake, self.config, exact(file_hash), out, "b12", [sys.executable])

    def test_saved_config_binds_each_parameter_cell(self):
        raw, hashes = config_dictionary({16: b"p16", 28: b"p28", 30: b"p30"})
        self.assertEqual(lite.config_param_hashes(raw, [16, 28, 30]), hashes)
        self.arm("ok", raw)
        out = self.dir / "config-ok"
        out.mkdir()
        row = lite.fetch_proven_config(self.fake, self.config, exact("ab" * 32), out, "c12",
                                       hashes, [sys.executable])
        self.assertEqual(row["param_cell_hashes"], hashes)

        wrong = {**hashes, "30": "00" * 32}
        out = self.dir / "config-wrong"
        out.mkdir()
        with self.assertRaisesRegex(lite.LiteError, "proven parameter cells differ"):
            lite.fetch_proven_config(self.fake, self.config, exact("ab" * 32), out, "c12",
                                     wrong, [sys.executable])

        missing, _ = config_dictionary({16: b"p16", 28: b"p28"})
        self.arm("ok", missing)
        out = self.dir / "config-missing"
        out.mkdir()
        with self.assertRaisesRegex(lite.LiteError, "ConfigParam30 is absent"):
            lite.fetch_proven_config(self.fake, self.config, exact("ab" * 32), out, "c12",
                                     hashes, [sys.executable])

        # Exit 0 without the post-verification save (lite-client's behavior when
        # the proof fails after a successful transport reply) must be refused.
        self.arm("no-save", raw)
        out = self.dir / "config-unverified"
        out.mkdir()
        with self.assertRaisesRegex(lite.LiteError, "did not report the proven dictionary save"):
            lite.fetch_proven_config(self.fake, self.config, exact("ab" * 32), out, "c12",
                                     hashes, [sys.executable])


if __name__ == "__main__":
    unittest.main()
