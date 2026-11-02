"""The committed differential corpus is exactly what the reference produces."""

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "test/bonded-relayer"))
from br1_wire_corpus import corpus  # noqa: E402

FIXTURE = ROOT / "test/bonded-relayer/fixtures/br1-wire-corpus.json"


class WireCorpusTests(unittest.TestCase):
    def test_committed_corpus_matches_the_reference(self):
        committed = json.loads(FIXTURE.read_text())
        self.assertEqual(committed, corpus(), "regenerate the fixture with br1_wire_corpus.py")

    def test_corpus_has_refusals_and_acceptances_on_both_sides(self):
        data = corpus()
        for group in ("terms", "request"):
            refused = {case["refused"] for case in data[group]["cases"]}
            self.assertEqual(refused, {True}, group)
        self.assertEqual({case["refused"] for case in data["parse"]}, {True, False})
        self.assertEqual({case["answered"] for case in data["status_lines"]}, {True, False})


if __name__ == "__main__":
    unittest.main()
