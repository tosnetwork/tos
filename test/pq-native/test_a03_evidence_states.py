import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('states', Path(__file__).resolve().parents[2] / 'scripts/a03_evidence_states.py')
states = importlib.util.module_from_spec(spec)
spec.loader.exec_module(states)


class EvidenceStatesTest(unittest.TestCase):
    def inputs(self):
        tasks = [{'id': f'ID{i:02}', 'owner': 'test', 'status': '✅'} for i in range(72)]
        ledger = {'units': {t['id']: {'status': t['status'], 'scope': 'synthetic lane',
                    'accepted': False, 'partial_evidence': {}} for t in tasks}}
        return {'tasks': tasks, 'memo_commit': 'a' * 40}, ledger, {'accepted_ids': [], 'units': {}}

    def test_empty_extraction_is_not_absence(self):
        out = states.classify(*self.inputs())
        self.assertEqual(out['counts']['signed-citation-not-yet-mapped'], 72)
        self.assertEqual(out['accepted_ids'], [])
        self.assertNotIn('absent-original', {r['evidence_state'] for r in out['units']})

    def test_audit_is_not_runtime_and_unmapped_report_is_not_verified(self):
        snapshot, ledger, pointer = self.inputs()
        pointer['units']['ID00'] = {'delivery_type': 'independent-audit', 'scope': 'review only',
                                  'invalidation': ['raw changes']}
        out = states.classify(snapshot, ledger, pointer)['units'][0]
        self.assertEqual(out['delivery_type'], 'independent-audit')
        self.assertEqual(out['evidence_state'], 'recoverable-but-unmapped-citation')
        self.assertEqual(out['current_file_verification'], 'not performed by this classifier')

    def test_rejects_stale_unknown_and_promoted(self):
        for field in ('status', 'accepted', 'unknown', 'owner', 'scope'):
            snapshot, ledger, pointers = self.inputs()
            if field == 'status': ledger['units']['ID00']['status'] = '□'
            elif field == 'accepted': ledger['units']['ID00']['accepted'] = True
            elif field == 'unknown': pointers['units']['other'] = {}
            elif field == 'owner': snapshot['tasks'][0]['owner'] = ''
            else: ledger['units']['ID00']['scope'] = ''
            with self.subTest(field=field), self.assertRaises(ValueError):
                states.classify(snapshot, ledger, pointers)


if __name__ == '__main__':
    unittest.main()
