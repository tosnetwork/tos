#!/usr/bin/env python3
"""Finite typed inventory classification, never an acceptance/run receipt."""
import argparse
import json
from pathlib import Path


def classify(snapshot, ledger, pointers):
    tasks = snapshot['tasks']
    ids = [row['id'] for row in tasks]
    if len(ids) != 72 or len(set(ids)) != 72:
        raise ValueError('expected exactly 72 distinct frozen IDs')
    if set(ledger['units']) != set(ids):
        raise ValueError('ledger IDs differ from frozen snapshot')
    if pointers.get('accepted_ids') != []:
        raise ValueError('partial pointers must not grant acceptance')
    if not set(pointers['units']) <= set(ids):
        raise ValueError('pointer names unknown ID')
    rows = []
    for task in tasks:
        unit = ledger['units'][task['id']]
        if unit['status'] != task['status'] or not task['owner'] or not unit['scope']:
            raise ValueError('missing owner/scope or stale status: ' + task['id'])
        if unit.get('accepted') is not False:
            raise ValueError('this inventory cannot promote an accepted row')
        pointer = pointers['units'].get(task['id'])
        partial = unit.get('partial_evidence') or {}
        reports = partial.get('review_reports', [])
        signed = task['status'] == '✅'
        deferred = task['status'] == '◇'
        state = ('testnet-only-deferred' if deferred else
                 'open-development' if not signed else
                 'recoverable-but-unmapped-citation' if reports or pointer else
                 'signed-citation-not-yet-mapped')
        # No report/raw path is silently upgraded to current existence or hash proof.
        rows.append({
            'id': task['id'], 'owner': task['owner'], 'status': task['status'],
            'scope': pointer['scope'] if pointer else unit['scope'],
            'scope_precision': 'fixed-reviewed-pointer' if pointer else 'lane-only-unreconciled',
            'delivery_type': pointer['delivery_type'] if pointer else 'not-yet-classified',
            'evidence_state': state, 'accepted': False,
            'review_citations': reports,
            'typed_pointer': pointer,
            'source_references': partial.get('source_references', []),
            'local_artifact_citations': partial.get('local_raw_artifacts', []),
            'memo_artifact_citations': partial.get('memo_raw_artifacts', []),
            'current_file_verification': 'not performed by this classifier',
            'original_absence': 'only explicit typed unproven items; empty extraction is not absence proof',
            'legacy_gate_gaps': partial.get('missing_required_fields', []),
            'ci': pointer.get('ci', 'separate exact-record/applicability mapping remains required') if pointer else 'not yet individually mapped',
            'invalidation': pointer['invalidation'] if pointer else ['fixed scope/source/raw/control/binary/review applicability must be reconciled before acceptance'],
        })
    return {'schema': 'a03.evidence-states.v1', 'memo_commit': snapshot['memo_commit'],
            'accepted_ids': [], 'counts': {key: sum(row['evidence_state'] == key for row in rows)
                for key in sorted({row['evidence_state'] for row in rows})},
            'units': rows}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--snapshot', type=Path, required=True)
    parser.add_argument('--ledger', type=Path, required=True)
    parser.add_argument('--pointers', type=Path, required=True)
    args = parser.parse_args()
    result = classify(*(json.loads(path.read_text()) for path in
                        (args.snapshot, args.ledger, args.pointers)))
    print(json.dumps(result, indent=2, ensure_ascii=False))


if __name__ == '__main__':
    main()
