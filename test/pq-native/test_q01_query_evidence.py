"""Offline Q01 controls over raw journald bytes and fixed query attempts."""

import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

REPO = Path(__file__).resolve().parents[2]
SOURCE = Path(__import__('os').environ.get('Q01_CHECKER_SOURCE',
                                         REPO / 'scripts/check-adnl-query-evidence.py'))
spec = importlib.util.spec_from_file_location('q01_evidence', SOURCE)
q01 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(q01)
legacy_spec = importlib.util.spec_from_file_location(
    'q01_legacy', REPO / 'scripts/analyze-adnl-query-id-trace.py')
legacy = importlib.util.module_from_spec(legacy_spec)
legacy_spec.loader.exec_module(legacy)
BOOT = '12345678123412341234123456789abc'
A = 'A' * 64
B = 'B' * 64
CLIENT = '127.0.0.1:50000'
SERVER = '127.0.0.1:30000'
STAGE_FILES = {'client_create': 'adnl-ext-client.hpp', 'client_refuse': 'adnl-ext-client.hpp',
               'client_transmit': 'adnl-ext-client.hpp', 'client_answer': 'adnl-ext-client.cpp',
               'client_complete': 'adnl-query.cpp', 'client_timeout': 'adnl-query.cpp',
               'server_ingress': 'adnl-ext-server.cpp', 'server_completion': 'adnl-ext-server.cpp',
               'server_answer_enqueue': 'adnl-ext-server.cpp'}


def stage(name, query_id, time, **fields):
    message = f'ADNL_EXT_QUERY {name} id={query_id}'
    if fields:
        message += ' ' + ' '.join(f'{key}={value}' for key, value in fields.items())
    message = (f'[ 4][t 1][1970-01-01 00:00:01.{time * 1000:09d}]'
               f'[{STAGE_FILES[name]}:123]\t' + message)
    role = 'server' if name.startswith('server_') else 'client'
    return role, {'_PID': '202' if role == 'server' else '101', '_BOOT_ID': BOOT,
                  '__MONOTONIC_TIMESTAMP': str(time),
                  '__REALTIME_TIMESTAMP': str(1_000_000 + time + 100), 'MESSAGE': message}


def success(query_id=A, offset=0):
    return [
        stage('client_create', query_id, offset + 10, server=SERVER,
              function_id='7', connection_present='true'),
        stage('client_transmit', query_id, offset + 20, server=SERVER),
        stage('server_ingress', query_id, offset + 30, peer='127.0.0.1', admission='accepted'),
        stage('server_completion', query_id, offset + 40, outcome='success', response_ready='true'),
        stage('server_answer_enqueue', query_id, offset + 50, enqueued='true'),
        stage('client_answer', query_id, offset + 60, answer_bytes='5'),
        stage('client_complete', query_id, offset + 70, outcome='answer', elapsed_ms='1'),
    ]


class Q01EvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='q01-offline-')
        cls.root = Path(cls.temp.name)
        cls.source = cls.root / 'source'
        cls.source.mkdir()
        for name in q01.SOURCE_FILES:
            target = cls.source / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(REPO / name, target)
        subprocess.run(['git', 'init', '-q', str(cls.source)], check=True)
        subprocess.run(['git', '-C', str(cls.source), 'add', '.'], check=True)
        subprocess.run(['git', '-C', str(cls.source), '-c', 'user.name=Q01',
                        '-c', 'user.email=q01@example.invalid', 'commit', '-qm', 'fixed source'], check=True)
        cls.commit = subprocess.check_output(['git', '-C', str(cls.source), 'rev-parse', 'HEAD'],
                                             text=True).strip()
        cls.source_hashes = {name: q01.sha((cls.source / name).read_bytes())
                             for name in q01.SOURCE_FILES}
        cls.binary = cls.root / 'binary'
        cls.binary.write_bytes(b'q01 frozen executable fixture')

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def setUp(self):
        self.case = Path(tempfile.mkdtemp(prefix='case-', dir=self.root))

    def bundle(self, rows=None, attempts=None):
        rows = success() if rows is None else rows
        paths = {}
        for role in ('client', 'server'):
            path = self.case / f'{role}.jsonl'
            path.write_bytes(b''.join(json.dumps(entry).encode() + b'\n'
                                      for row_role, entry in rows if row_role == role))
            paths[role] = {'path': str(path), 'sha256': q01.sha(path.read_bytes()),
                           'pid': 101 if role == 'client' else 202, 'boot_id': BOOT,
                           'endpoint': CLIENT if role == 'client' else SERVER}
        binary = {'path': str(self.binary), 'sha256': q01.sha(self.binary.read_bytes())}
        return {'schema': 'tos.q01.query-evidence.v1', 'source_root': str(self.source),
                'source_commit': self.commit, 'source_files': self.source_hashes,
                'binaries': {'client': binary, 'node1': binary}, 'boot_id': BOOT,
                'client_peer_ip': '127.0.0.1',
                'client_log': paths['client'], 'server_logs': {'node1': paths['server']},
                'attempts': attempts or [{'logical_request': 'read-head', 'attempt': 0,
                                          'retry_of': None, 'query_id': A, 'operation': '7',
                                          'server': 'node1'}]}

    def test_full_raw_answer_has_all_stages_and_bytes(self):
        result = q01.verify(self.bundle())
        self.assertTrue(result['trace_attribution_passed'])
        self.assertEqual(result['queries'][A]['classification'], 'transport_answered')
        self.assertEqual(len(result['queries'][A]['events']), 7)
        for event in result['queries'][A]['events']:
            self.assertEqual(q01.sha(__import__('base64').b64decode(event['raw_b64'])),
                             event['raw_sha256'])
            self.assertGreater(event['journal_mono_us'], 0)
            self.assertGreater(event['source_event_wall_ns'], 0)
            self.assertEqual(q01.sha(__import__('base64').b64decode(event['message_b64'])),
                             event['message_sha256'])

    def test_create_plus_answer_is_not_answered(self):
        rows = [success()[0], success()[5]]
        result = q01.verify(self.bundle(rows))
        self.assertFalse(result['trace_attribution_passed'])
        self.assertEqual(result['queries'][A]['classification'], 'unproven_answer')
        self.assertNotEqual(legacy.classify([
            f'ADNL_EXT_QUERY client_create id={A}',
            f'ADNL_EXT_QUERY client_answer id={A}']), 'transport_answered')

    def test_text_classifier_rejects_mixed_ids(self):
        self.assertEqual(legacy.classify([
            f'ADNL_EXT_QUERY client_create id={A}',
            f'ADNL_EXT_QUERY client_answer id={B}']), 'invalid_mixed_query_ids')

    def test_mixed_ids_cannot_supply_missing_answer(self):
        rows = success()[:5] + [stage('client_answer', B, 60, answer_bytes='5')]
        with self.assertRaisesRegex(ValueError, 'unmapped query ID'):
            q01.verify(self.bundle(rows))

    def test_mixed_attempts_cannot_join_stages(self):
        rows = success()[:5] + [stage('client_create', B, 80, server=SERVER,
                                     function_id='7', connection_present='true'),
                              stage('client_answer', B, 90, answer_bytes='5')]
        attempts = [{'logical_request': 'read-head', 'attempt': 0, 'retry_of': None,
                     'query_id': A, 'operation': '7', 'server': 'node1'},
                    {'logical_request': 'read-head', 'attempt': 1, 'retry_of': A,
                     'query_id': B, 'operation': '7', 'server': 'node1'}]
        with self.assertRaisesRegex(ValueError, 'retry client terminal/create absent'):
            q01.verify(self.bundle(rows, attempts))

    def test_terminal_complete_mixed_attempts_still_cannot_join(self):
        rows = success()[:5] + [stage('client_timeout', A, 70, outcome='timeout')]
        rows += [stage('client_create', B, 80, server=SERVER, function_id='7',
                       connection_present='true'),
                 stage('client_transmit', B, 90, server=SERVER),
                 stage('client_answer', B, 100, answer_bytes='5'),
                 stage('client_complete', B, 110, outcome='answer', elapsed_ms='1')]
        attempts = [{'logical_request': 'read-head', 'attempt': 0, 'retry_of': None,
                     'query_id': A, 'operation': '7', 'server': 'node1'},
                    {'logical_request': 'read-head', 'attempt': 1, 'retry_of': A,
                     'query_id': B, 'operation': '7', 'server': 'node1'}]
        result = q01.verify(self.bundle(rows, attempts))
        self.assertFalse(result['trace_attribution_passed'])
        self.assertFalse(result['queries'][A]['transport_answer'])
        self.assertFalse(result['queries'][B]['transport_answer'])

    def test_fail_fast_no_connection_is_separate(self):
        rows = [stage('client_create', A, 10, server=SERVER, function_id='7',
                      connection_present='false'),
                stage('client_refuse', A, 20, reason='no-live-connection', pending_queries='0')]
        result = q01.verify(self.bundle(rows))
        self.assertFalse(result['trace_attribution_passed'])
        self.assertEqual(result['queries'][A]['classification'], 'client_no_connection_fail_fast')

    def test_fail_fast_then_retry_answer_has_distinct_query_ids(self):
        rows = [stage('client_create', A, 10, server=SERVER, function_id='7',
                      connection_present='false'),
                stage('client_refuse', A, 20, reason='no-live-connection', pending_queries='0')]
        rows += success(B, offset=100)
        attempts = [{'logical_request': 'read-head', 'attempt': 0, 'retry_of': None,
                     'query_id': A, 'operation': '7', 'server': 'node1'},
                    {'logical_request': 'read-head', 'attempt': 1, 'retry_of': A,
                     'query_id': B, 'operation': '7', 'server': 'node1'}]
        result = q01.verify(self.bundle(rows, attempts))
        self.assertTrue(result['trace_attribution_passed'])
        self.assertEqual(result['queries'][A]['classification'], 'client_no_connection_fail_fast')
        self.assertEqual(result['queries'][B]['classification'], 'transport_answered')

    def test_retry_predecessor_mismatch_rejected(self):
        rows = [stage('client_create', A, 10, server=SERVER, function_id='7',
                      connection_present='false'),
                stage('client_refuse', A, 20, reason='no-live-connection', pending_queries='0')]
        rows += success(B, offset=100)
        attempts = [{'logical_request': 'read-head', 'attempt': 0, 'retry_of': None,
                     'query_id': A, 'operation': '7', 'server': 'node1'},
                    {'logical_request': 'read-head', 'attempt': 1, 'retry_of': 'F' * 64,
                     'query_id': B, 'operation': '7', 'server': 'node1'}]
        with self.assertRaisesRegex(ValueError, 'retry predecessor differs'):
            q01.verify(self.bundle(rows, attempts))

    def test_retry_cannot_reuse_query_id(self):
        attempts = [{'logical_request': 'read-head', 'attempt': 0, 'retry_of': None,
                     'query_id': A, 'operation': '7', 'server': 'node1'},
                    {'logical_request': 'read-head', 'attempt': 1, 'retry_of': A,
                     'query_id': A, 'operation': '7', 'server': 'node1'}]
        with self.assertRaisesRegex(ValueError, 'query ID reused'):
            q01.verify(self.bundle(attempts=attempts))

    def test_wrong_server_pid_rejected(self):
        manifest = self.bundle()
        manifest['server_logs']['node1']['pid'] = 999
        with self.assertRaisesRegex(ValueError, 'PID or boot differs'):
            q01.verify(manifest)

    def test_wrong_ingress_endpoint_rejected(self):
        rows = success()
        rows[2] = stage('server_ingress', A, 30, peer='127.0.0.2', admission='accepted')
        with self.assertRaisesRegex(ValueError, 'ingress peer IP differs'):
            q01.verify(self.bundle(rows))

    def test_client_local_socket_host_must_match_peer_ip(self):
        manifest = self.bundle()
        manifest['client_log']['endpoint'] = '127.0.0.2:50000'
        with self.assertRaisesRegex(ValueError, 'peer IP differs from local socket host'):
            q01.verify(manifest)

    def test_missing_server_completion_is_unproven(self):
        rows = [row for row in success() if 'ADNL_EXT_QUERY server_completion ' not in row[1]['MESSAGE']]
        result = q01.verify(self.bundle(rows))
        self.assertFalse(result['trace_attribution_passed'])
        self.assertEqual(result['queries'][A]['classification'], 'unproven_answer')

    def test_answer_enqueue_false_rejected(self):
        rows = success()
        rows[4] = stage('server_answer_enqueue', A, 50, enqueued='false')
        with self.assertRaisesRegex(ValueError, 'do not show successful answer'):
            q01.verify(self.bundle(rows))

    def test_server_source_wall_regression_is_separate(self):
        rows = success()
        rows[3] = stage('server_completion', A, 25, outcome='success', response_ready='true')
        result = q01.verify(self.bundle(rows))
        self.assertTrue(result['trace_attribution_passed'])
        self.assertFalse(result['source_sequence_consistent'])

    def test_log_bytes_sha_rejected(self):
        manifest = self.bundle()
        manifest['client_log']['sha256'] = 'f' * 64
        with self.assertRaisesRegex(ValueError, 'retained bytes differ'):
            q01.verify(manifest)


    def test_ansi_byte_arrays_preserve_original_bytes(self):
        rows = success()
        for _, entry in rows:
            entry['MESSAGE'] = list(b'\x1b[0m\x1b[1;32m' + entry['MESSAGE'].encode())
        result = q01.verify(self.bundle(rows))
        self.assertTrue(result['trace_attribution_passed'])
        for event in result['queries'][A]['events']:
            raw_message = __import__('base64').b64decode(event['message_b64'])
            self.assertTrue(raw_message.startswith(b'\x1b[0m'))
            self.assertEqual(q01.sha(raw_message), event['message_sha256'])

    def test_unrelated_server_peer_query_is_separate(self):
        role, entry = stage('client_complete', B, 35, outcome='answer')
        entry['_PID'] = '202'
        result = q01.verify(self.bundle(success() + [('server', entry)]))
        self.assertTrue(result['trace_attribution_passed'])
        self.assertEqual(len(result['queries'][A]['events']), 7)
        self.assertEqual(result['excluded_server_client_events'][0]['query_id'], B)
        self.assertEqual(result['excluded_server_client_event_counts']['node1']['client_complete'], 1)

    def test_same_id_server_client_complete_is_wrong_role(self):
        rows = success()
        rows[6][1]['_PID'] = '202'
        rows[6] = ('server', rows[6][1])
        with self.assertRaisesRegex(ValueError, 'wrong process role'):
            q01.verify(self.bundle(rows))

    def test_unrelated_server_client_create_is_not_peer_exclusion(self):
        _, entry = stage('client_create', B, 35, server=SERVER, function_id='7')
        entry['_PID'] = '202'
        with self.assertRaisesRegex(ValueError, 'wrong process role'):
            q01.verify(self.bundle(success() + [('server', entry)]))

    def test_journal_receipt_inversion_does_not_reverse_execution(self):
        rows = success()
        rows[1][1]['__MONOTONIC_TIMESTAMP'] = '1000'
        rows[1][1]['__REALTIME_TIMESTAMP'] = '1001000'
        result = q01.verify(self.bundle(rows))
        self.assertTrue(result['trace_attribution_passed'])
        self.assertEqual([e['stage'] for e in result['queries'][A]['events'] if e['role'] == 'client'],
                         ['client_create', 'client_transmit', 'client_answer', 'client_complete'])

    def test_source_regression_with_ordered_metadata_is_separate(self):
        rows = success()
        rows[3][1]['MESSAGE'] = rows[3][1]['MESSAGE'].replace('.000040000]', '.000025000]')
        result = q01.verify(self.bundle(rows))
        self.assertTrue(result['trace_attribution_passed'])
        self.assertFalse(result['source_sequence_consistent'])

    def test_negative_metadata_delta_is_diagnostic_not_causal_gate(self):
        rows = success()
        for _, entry in rows:
            entry['__REALTIME_TIMESTAMP'] = '1'
        result = q01.verify(self.bundle(rows))
        self.assertTrue(result['trace_attribution_passed'])
        self.assertTrue(result['source_sequence_consistent'])
        self.assertLess(result['min_journal_metadata_minus_source_ns'], 0)
        self.assertFalse(result['cross_process_time_proven'])

    def test_late_metadata_is_diagnostic_not_delay_proof(self):
        rows = success()
        rows[0][1]['__REALTIME_TIMESTAMP'] = '7000000'
        result = q01.verify(self.bundle(rows))
        self.assertTrue(result['trace_attribution_passed'])
        self.assertGreater(result['max_journal_metadata_minus_source_ns'], 5_000_000_000)
        self.assertFalse(result['deadline_proven'])

    def test_actor_raw_order_cannot_be_repaired_by_wall_sort(self):
        rows = success()
        rows[0], rows[1] = rows[1], rows[0]
        with self.assertRaisesRegex(ValueError, 'actor raw stage order differs'):
            q01.verify(self.bundle(rows))

    def test_cross_process_source_order_is_not_causal_proof(self):
        rows = success()
        for _, entry in rows[2:5]:
            entry['MESSAGE'] = entry['MESSAGE'].replace('00:00:01.', '00:00:02.')
        result = q01.verify(self.bundle(rows))
        self.assertTrue(result['trace_attribution_passed'])
        self.assertTrue(result['source_sequence_consistent'])
        self.assertFalse(result['queries'][A]['cross_process_source_wall_order_observed'])
        self.assertFalse(result['cross_process_time_proven'])

    def test_multifile_actor_order_is_unproven(self):
        result = q01.verify(self.bundle())
        rows = [dict(row) for row in result['queries'][A]['events'] if row['role'] == 'client']
        rows[1]['log_path'] += '.other'
        sequence = q01.actor_sequence(rows, ('client_create', 'client_transmit',
                                             'client_answer', 'client_complete'))
        self.assertEqual(sequence['status'], 'unproven')
        self.assertFalse(sequence['source_wall_consistent'])

    def test_new_scope_does_not_enable_legacy_or_application_acceptance(self):
        result = q01.verify(self.bundle())
        self.assertEqual(result['schema'], 'tos.q01.trace-attribution-result.v2')
        self.assertEqual(result['evidence_scope'], 'trace-attribution')
        self.assertTrue(result['trace_attribution_passed'])
        for field in ('passed', 'q01_signoff', 'cross_process_time_proven',
                      'deadline_proven', 'socket_flush_proven'):
            self.assertFalse(result[field])
        self.assertIsNone(result['finite_error_bound'])
        self.assertTrue(result['queries'][A]['transport_answer'])
        self.assertFalse(result['queries'][A]['application_success_proven'])

    def test_missing_source_timestamp_rejected(self):
        rows = success()
        rows[0][1]['MESSAGE'] = rows[0][1]['MESSAGE'].split('\t', 1)[1]
        with self.assertRaisesRegex(ValueError, 'timestamp absent'):
            q01.verify(self.bundle(rows))

    def test_source_file_mismatch_rejected(self):
        rows = success()
        rows[2][1]['MESSAGE'] = rows[2][1]['MESSAGE'].replace('adnl-ext-server.cpp', 'adnl-query.cpp')
        with self.assertRaisesRegex(ValueError, 'source file differs'):
            q01.verify(self.bundle(rows))

    def test_marker_inside_quoted_body_rejected(self):
        rows = success()
        rows[0][1]['MESSAGE'] = rows[0][1]['MESSAGE'].replace('\tADNL_EXT_QUERY', '\tcopied ADNL_EXT_QUERY')
        with self.assertRaisesRegex(ValueError, 'not the source message body'):
            q01.verify(self.bundle(rows))

    def test_invalid_message_shape_rejected(self):
        for value in (None, [True], [256], [-1], [255]):
            with self.subTest(value=value):
                rows = success()
                rows[0][1]['MESSAGE'] = value
                with self.assertRaises(ValueError):
                    q01.verify(self.bundle(rows))

    def test_unknown_ansi_escape_rejected(self):
        for escape in ('\x1b[2J', '\x1b[1;35m'):
            with self.subTest(escape=escape):
                rows = success()
                rows[0][1]['MESSAGE'] = escape + rows[0][1]['MESSAGE']
                with self.assertRaisesRegex(ValueError, 'unsupported escape'):
                    q01.verify(self.bundle(rows))

    def test_source_dirt_rejected(self):
        manifest = self.bundle()
        path = self.source / q01.SOURCE_FILES[0]
        original = path.read_bytes()
        try:
            path.write_bytes(original + b'\n')
            with self.assertRaisesRegex(ValueError, 'source tree is not fixed and clean'):
                q01.verify(manifest)
        finally:
            path.write_bytes(original)


if __name__ == '__main__':
    unittest.main()
