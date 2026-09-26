#!/usr/bin/env python3
"""Full four-validator StageA partial-loss coordinator inside one private service.

No live action at import. Entry is the existing hash-verified ordinary driver.
All capture, callbacks, natural StageA settlement and owned cleanup are required.
"""
from __future__ import annotations

import base64
from collections import Counter
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import threading
import time
import types

REPO = Path(__file__).resolve().parents[1]
INPUT_PATH = REPO / 'scripts/x02_four_node_inputs.json'
RUN_ID = '2026092600040001'
SETUP_SECONDS = 900
SERVICE_SECONDS = 2400
CHILD_BOOTSTRAP = '''import ctypes,hashlib,os,sys,types
libc=ctypes.CDLL(None,use_errno=True)
assert os.getresuid()==(1000,1000,1000) and os.getresgid()==(1000,1000,1000) and not os.getgroups(), 'child IDs/groups differ'
assert libc.prctl(47,4,0,0,0)==0, 'child ambient clear failed'
class H(ctypes.Structure):
 _fields_=[('version',ctypes.c_uint32),('pid',ctypes.c_int)]
class D(ctypes.Structure):
 _fields_=[('effective',ctypes.c_uint32),('permitted',ctypes.c_uint32),('inheritable',ctypes.c_uint32)]
h=H(0x20080522,0);d=(D*2)()
assert libc.capset(ctypes.byref(h),ctypes.byref(d))==0, 'child caps clear failed'
s=dict(line.split(':',1) for line in open('/proc/self/status') if ':' in line)
assert all(int(s[k],16)==0 for k in ('CapEff','CapPrm','CapInh','CapAmb')) and int(s['CapBnd'],16)==0x3000 and int(s['NoNewPrivs'])==1, 'child final privilege state differs'
p,ph,q,qh=sys.argv[1:5];b=open(p,'rb').read();c=open(q,'rb').read()
assert hashlib.sha256(b).hexdigest()==ph and hashlib.sha256(c).hexdigest()==qh, 'child/helper execution bytes differ'
m=types.ModuleType('x02_four_node_binding');m.__file__=q;m.__executed_sha256__=qh;sys.modules[m.__name__]=m
exec(compile(c,q,'exec'),m.__dict__)
sys.argv=[p]+sys.argv[5:]
exec(compile(b,p,'exec'),{'__name__':'__main__','__file__':p,'__x02_child_sha256__':ph})
'''


def require(value, reason):
    if not value:
        raise ValueError(reason)


def recovery_target_met(anchor, current, deadline_ns):
    return (current['full_id'][2] >= anchor['full_id'][2] + 2
            and current['completed_ns'] <= deadline_ns)


def write_once(path, value):
    raw = (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()
    with path.open('xb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    return hashlib.sha256(raw).hexdigest()


def fixed_module(name, context):
    path = REPO / 'scripts' / (name + '.py')
    raw = path.read_bytes()
    frozen = subprocess.check_output(['git', '-C', str(REPO), 'show',
                                      context['source_sha'] + ':scripts/' + path.name])
    require(raw == frozen and name not in sys.modules, 'coordinator source changed/already loaded')
    module = types.ModuleType(name)
    module.__file__ = str(path)
    sys.modules[name] = module
    exec(compile(raw, str(path), 'exec'), module.__dict__)
    return module


def socket_and_namespace(node, context):
    proc = Path('/proc') / str(node['pid'])
    require(os.readlink(proc / 'ns/net') == context['netns']
            and (proc / 'cgroup').read_text() == context['cgroup'],
            'validator outside private namespace/cgroup')
    status = dict(line.split(':', 1) for line in (proc / 'status').read_text().splitlines()
                  if ':' in line)
    require(all(int(status[key], 16) == 0 for key in ('CapEff', 'CapPrm', 'CapInh', 'CapAmb'))
            and int(status['CapBnd'], 16) == 0x3000 and int(status['NoNewPrivs']) == 1
            and status['Uid'].split() == ['1000'] * 4
            and status['Gid'].split() == ['1000'] * 4 and not status['Groups'].split(),
            'validator IDs/groups/capabilities/NNP differ')
    inodes = set()
    for fd in (proc / 'fd').iterdir():
        try:
            link = os.readlink(fd)
        except OSError:
            continue
        if link.startswith('socket:['):
            inodes.add(int(link[8:-1]))
    table = Path('/proc/net/tcp').read_text()
    port = int(node['rpc_url'].split(':')[2].split('/')[0])
    matches = []
    for line in table.splitlines()[1:]:
        fields = line.split()
        if len(fields) >= 10:
            addr, encoded_port = fields[1].split(':')
            if int(encoded_port, 16) == port and int(fields[9]) in inodes and fields[3] == '0A':
                require(str(ipaddress.IPv4Address(bytes.fromhex(addr)[::-1])) == '127.0.0.1',
                        'RPC listener is not frozen loopback address')
                matches.append(int(fields[9]))
    require(len(matches) == 1, 'RPC socket is absent or ambiguous for validator PID')
    return {'tcp_table': table, 'rpc_inode': matches[0], 'socket_inodes': sorted(inodes),
            'status': (proc / 'status').read_text(), 'netns': os.readlink(proc / 'ns/net'),
            'cgroup': (proc / 'cgroup').read_text()}


class ChainCapture:
    def __init__(self, evidence, nodes, zerostate, ledger, context):
        self.e, self.nodes, self.zero, self.ledger, self.context = evidence, nodes, zerostate, ledger, context
        self.previous = {}
        self.native = {node['name']: {} for node in nodes}
        self.global_ids = {}
        self.tips = {node['name']: 0 for node in nodes}
        self.samples = []

    def sample(self, phase, anchor=None, deadline=None, event_start=None):
        e = self.e
        row = {'event': 'chain_sample', 'phase': phase, 'started_ns': time.monotonic_ns(),
               'anchor': anchor, 'nodes': {}, 'headers': {}}
        self.ledger.append({'event': 'chain_capture_started', 'phase': phase,
                            'started_ns': row['started_ns']})
        for node in self.nodes:
            name = node['name']
            process = e.capture_process(node)
            e.process_identity(process, node)
            socket_receipt = socket_and_namespace(node, self.context)
            prior = self.previous.get(name)
            native = e.capture_native_log(node, prior)
            self.ledger.append({'event': 'node_original', 'phase': phase, 'node': name,
                                'process': process, 'socket_namespace': socket_receipt, 'native': native})
            parsed = e.native_log_ids(native, node, prior)
            self.previous[name] = native
            for height, value in parsed.items():
                old = self.native[name].get(height)
                require(old is None or old[:2] == value[:2], 'same-height native fullID conflict')
                self.native[name][height] = value if old is None else old
            tip = e.rpc(node['rpc_url'], 'getMasterchainInfo', None, len(self.samples) * 100 + len(row['nodes']))
            # Raw request, status/body/timing survives even if parse fails.
            self.ledger.append({'event': 'rpc_original', 'phase': phase, 'node': name, 'raw': tip})
            block = e.parse_rpc(tip, node, 'getMasterchainInfo', expected_init=self.zero)
            self.global_ids.setdefault(block[2], block)
            require(self.global_ids[block[2]] == block, 'first-tip same-height RPC fullID conflict')
            require(block[2] >= self.tips[name], 'validator masterchain tip regressed')
            self.tips[name] = block[2]
            row['nodes'][name] = {'process': process, 'socket_namespace': socket_receipt,
                                  'native': native, 'tip_rpc': tip, 'tip_full_id': block}
        common = min(value['tip_full_id'][2] for value in row['nodes'].values())
        require(anchor is None or common >= anchor['full_id'][2], 'common height below frozen anchor')
        first = common if anchor is None else anchor['full_id'][2]
        require(common - first <= 512, 'chain range exceeded fixed capture bound')
        for height in range(first, common + 1):
            by_node = {}
            for node in self.nodes:
                name = node['name']
                params = {'workchain': -1, 'shard': str(-(1 << 63)), 'seqno': height}
                raw = e.rpc(node['rpc_url'], 'getBlockHeader', params, height)
                self.ledger.append({'event': 'rpc_original', 'phase': phase, 'node': name, 'raw': raw})
                block = e.parse_rpc(raw, node, 'getBlockHeader', expected_seq=height)
                require(block[2] == height, 'returned header height differs from requested height')
                self.global_ids.setdefault(height, block)
                require(self.global_ids[height] == block, 'same-height RPC fullID conflict')
                by_node[name] = {'raw': raw, 'full_id': block}
            row['headers'][str(height)] = by_node
        # Post-RPC native reads prove full-ID joins and preserve complete byte cursors.
        row['post_native'] = {}
        for node in self.nodes:
            name, prior = node['name'], self.previous[node['name']]
            native = e.capture_native_log(node, prior)
            self.ledger.append({'event': 'post_native_original', 'phase': phase,
                                'node': name, 'native': native})
            parsed = e.native_log_ids(native, node, prior)
            self.previous[name] = native
            row['post_native'][name] = native
            for height, value in parsed.items():
                old = self.native[name].get(height)
                require(old is None or old[:2] == value[:2], 'post-RPC native conflict')
                self.native[name][height] = value if old is None else old
            for height in range(first, common + 1):
                block = row['headers'][str(height)][name]['full_id']
                value = self.native[name].get(height)
                require(value is not None and value[:2] == block[3:5],
                        'common fullID absent or differs in native finalized log')
        row['full_id'] = row['headers'][str(common)][self.nodes[0]['name']]['full_id']
        row['completed_ns'] = time.monotonic_ns()
        row['rpc_completed_ns'] = max(item['raw']['completed_ns']
                                     for group in row['headers'].values() for item in group.values())
        row['native_join_completed_ns'] = max(item['completed_ns'] for item in row['post_native'].values())
        self.ledger.append(row)
        require(deadline is None or max(row['rpc_completed_ns'], row['native_join_completed_ns']) <= deadline,
                'chain evidence completed after fixed phase deadline')
        self.samples.append(row)
        return {'full_id': row['full_id'], 'sample_sha256': hashlib.sha256(
            json.dumps(row, sort_keys=True, separators=(',', ':')).encode()).hexdigest(),
                'completed_ns': row['completed_ns']}

    def progress_after(self, anchor, current, event_start):
        """Require two consecutive joined full IDs actually finalized after install.

        Preserve all earlier joined heights too; an in-flight pre-install block
        cannot be one of the two progress IDs, even if it exceeds baseline.
        """
        height = current['full_id'][2]
        return (height >= anchor['full_id'][2] + 2
                and all(self.native[node['name']][seq][2] >= event_start
                        for node in self.nodes for seq in (height - 1, height)))


def freeze_senders(nodes, ledger, stopped):
    for node in nodes:
        pid = node['pid']
        fields = Path(f'/proc/{pid}/stat').read_bytes().rsplit(b') ', 1)[1].split()
        require(int(fields[19]) == node['pid_start_ticks'], 'sender PID generation changed before stop')
        os.kill(pid, signal.SIGSTOP)
        stopped.add(pid)
    deadline = time.monotonic() + 5
    for node in nodes:
        while True:
            states = {task.name: (task / 'stat').read_bytes().rsplit(b') ', 1)[1].split()[0].decode()
                      for task in Path(f"/proc/{node['pid']}/task").iterdir()}
            if all(state in ('T', 't') for state in states.values()):
                ledger.append({'event': 'owned_sender_stopped', 'node': node['name'],
                               'pid': node['pid'], 'start_ticks': node['pid_start_ticks'],
                               'task_states': states, 'monotonic_ns': time.monotonic_ns()})
                break
            require(time.monotonic() < deadline, 'owned sender did not quiesce')
            time.sleep(.02)


def run(args, context):
    require(args.case == 'positive' and args.run_id == RUN_ID, 'full-chain entry is not the fixed preset')
    # Missing full runtime closure stops BEFORE any socket, loopback, node or helper reuse.
    require(INPUT_PATH.is_file(), 'full StageA executable/dependency closure is not frozen')
    raw = INPUT_PATH.read_bytes()
    frozen = subprocess.check_output(['git', '-C', str(REPO), 'show',
                                     context['source_sha'] + ':scripts/' + INPUT_PATH.name])
    require(raw == frozen, 'four-node runtime input binding differs from fixed source')
    binding = json.loads(raw)
    closure = fixed_module('x02_four_node_binding', context)
    closure.verify_binding(binding)
    require(binding['source_root'] == str(REPO), 'full StageA source must be the reviewed driver tree')
    args.output.mkdir(exist_ok=False)
    # Driver calls this after verified module load; imports below refer to those bytes.
    from x02_partial_sequence import DIRECTIONS, candidate_policy, verify_selection_trace
    from x02_partial_adapter import DecisionAdapter, DurableLedger, udp_datagram
    from x02_queue_stats_fd import QueueStatsFD
    from x02_nfqueue_backend import QueueBackend
    from x02_nft_rules import RuleManager
    evidence = fixed_module('x02_fault_evidence', context)
    prepare = fixed_module('x02_prepare_policy', context)
    ledger = DurableLedger(args.output / 'kernel.jsonl')
    chain_ledger = DurableLedger(args.output / 'chain.jsonl')
    delivered = DurableLedger(args.output / 'delivered.jsonl')
    stats = QueueStatsFD(args.queue_stats_fd, args.queue_receipt_fd, args.host_netns)
    stop, observer_idle, errors, stopped = threading.Event(), threading.Event(), [], set()
    stage, backend, manager, worker, observer, observer_worker = (None,) * 6
    nodes, cleanup_ok, checks_passed, stage_natural = [], False, False, False
    received = Counter()
    invocation = time.monotonic()
    try:
        ledger.append({'event': 'context', **context})
        stats.inverse_controls(ledger)
        setup = subprocess.run(['/usr/sbin/ip', 'link', 'set', 'dev', 'lo', 'up'],
                               capture_output=True, timeout=5, check=False)
        ledger.append({'event': 'private_loopback_setup', 'exit': setup.returncode,
                       'stdout_hex': setup.stdout.hex(), 'stderr_hex': setup.stderr.hex()})
        require(setup.returncode == 0, 'private loopback configuration failed')
        binding.update(private_netns=context['netns'], host_netns=context['host_netns'],
                       cgroup=context['cgroup'])
        require(binding['stage_output'] == str(args.output / 'stage-a'), 'StageA output is not exclusive run leaf')
        binding_path = args.output / 'binding.json'
        binding_sha = write_once(binding_path, binding)
        child = REPO / 'scripts/x02_stage_a_child.py'
        helper = REPO / 'scripts/x02_four_node_binding.py'
        argv = [binding['interpreter'], '-I', '-S', '-B', '-c', CHILD_BOOTSTRAP,
                str(child), binding['files'][str(child)]['sha256'],
                str(helper), binding['files'][str(helper)]['sha256'], '--binding', str(binding_path),
                '--binding-sha256', binding_sha, '--output', str(args.output)]
        env = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C.UTF-8',
               'HOME': str(args.output / 'home'), 'TMPDIR': str(args.output / 'tmp'),
               'PYTHONHASHSEED': '0', 'UV_OFFLINE': '1'}
        Path(env['HOME']).mkdir()
        Path(env['TMPDIR']).mkdir()
        with (args.output / 'stage.stdout.raw').open('xb') as stdout, \
             (args.output / 'stage.stderr.raw').open('xb') as stderr:
            stage = subprocess.Popen(argv, stdout=stdout, stderr=stderr, cwd=REPO,
                                     env=env, close_fds=True, start_new_session=True)
        ledger.append({'event': 'stage_started', 'argv': argv, 'env': env,
                       'pid': stage.pid, 'monotonic_ns': time.monotonic_ns()})
        readiness = None
        setup_deadline = invocation + SETUP_SECONDS
        while readiness is None:
            require(stage.poll() is None, 'StageA exited before readiness')
            require(time.monotonic() < setup_deadline, 'full StageA setup deadline exceeded')
            candidates = list(Path(binding['stage_output']).glob('*/readiness-manifest.json'))
            require(len(candidates) <= 1, 'multiple StageA readiness runs')
            if candidates:
                readiness = candidates[0]
                break
            time.sleep(.25)
        readiness_raw = readiness.read_bytes()
        manifest = json.loads(readiness_raw)
        require(manifest['schema'] == 'tos.validator-election-experiment-readiness.v2'
                and manifest['status'] == 'ready' and manifest['mode'] == 'experiment'
                and manifest['network']['validator_count'] == 4
                and manifest['network']['internal_base_port'] == 32600
                and manifest['provenance']['source_commit'] == context['source_sha'],
                'StageA readiness source/schema/preset differs')
        nodes = [prepare.live_node(item) for item in manifest['validators']]
        require(len(nodes) == 4 and {node['name'] for node in nodes} == {f'node{i}' for i in range(1, 5)}
                and len({node['pid'] for node in nodes}) == 4
                and len({node['data_dir'] for node in nodes}) == 4
                and len({(node['log_dev'], node['log_ino']) for node in nodes}) == 4,
                'four distinct native identities/DB/logs absent')
        for key in ('consensus_key_id', 'adnl_id'):
            require(len({evidence.hex64(node[key], key) for node in nodes}) == 4,
                    'four validator keys alias')
        for i, node in enumerate(nodes):
            require(node['name'] == f'node{i + 1}' and node['peer_port'] == 32602 + i * 3
                    and node['quic_port'] == 33602 + i * 3
                    and node['rpc_url'] == f'http://127.0.0.1:{34600 + i}/jsonRPC'
                    and node['exe_sha256'] == binding['native_binary_sha256']
                    and node['harness_pid'] == stage.pid, 'native node preset/provenance differs')
            socket_and_namespace(node, context)
        zero = manifest['network']['zero_state']['masterchain']
        zerostate = {'root_hash': zero['root_hash_hex'], 'file_hash': zero['file_hash_hex']}
        by_name = {node['name']: node for node in nodes}
        endpoints = {}
        for direction in DIRECTIONS:
            pair, transport = direction.split('/')
            source, destination = pair.split('>')
            field = 'peer_port' if transport == 'adnl' else 'quic_port'
            endpoints[direction] = (by_name[source]['peer_ip'], by_name[source][field],
                                    by_name[destination]['peer_ip'], by_name[destination][field])
        policy = candidate_policy(context['source_sha'])
        policy_record = {'schema': 'tos.x02.four-node-live-policy.v1', 'selection': policy,
                         'nodes': nodes, 'endpoints': endpoints, 'zerostate': zerostate,
                         'readiness_sha256': hashlib.sha256(readiness_raw).hexdigest(),
                         'readiness_b64': base64.b64encode(readiness_raw).decode(),
                         'native_source_sha': binding['native_source_sha'],
                         'binding_sha256': binding_sha, 'network_namespace': context['netns'],
                         'original_config34': manifest['network']['initial_config34'],
                         'partial_seconds': 120, 'recovery_seconds': 180, 'halt_claim': False}
        policy_sha = write_once(args.output / 'policy.json', policy_record)
        chain = ChainCapture(evidence, nodes, zerostate, chain_ledger, context)
        baseline = chain.sample('baseline')
        ledger.append({'event': 'policy_and_baseline_frozen', 'policy_sha256': policy_sha,
                       'baseline': baseline, 'monotonic_ns': time.monotonic_ns()})
        engine = DecisionAdapter(policy, endpoints, ledger)
        # Stop every native sender before queue bind/rule install/observer start.
        freeze_senders(nodes, ledger, stopped)
        backend = QueueBackend(ledger, stats)
        backend.bind()
        manager = RuleManager(args.run_id, engine, backend, ledger)
        manager.preflight()
        # Receive-only raw observer proves input delivery bytes separately from ACKs/counters.
        observer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
        observer.bind(('127.0.0.1', 0))
        observer.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1048576)
        observer.settimeout(.2)
        tuples = set(endpoints.values())
        def receive_delivered():
            try:
                while not stop.is_set():
                    try:
                        packet = observer.recv(65535)
                    except socket.timeout:
                        observer_idle.set()
                        continue
                    observer_idle.clear()
                    if udp_datagram(packet) in tuples:
                        digest = hashlib.sha256(packet).hexdigest()
                        received[digest] += 1
                        delivered.append({'event': 'raw_delivered', 'packet_hex': packet.hex(),
                                          'packet_sha256': digest, 'monotonic_ns': time.monotonic_ns()})
            except Exception as error:
                errors.append('observer: ' + repr(error))
        def process_queues():
            try:
                while not stop.is_set():
                    require(time.monotonic() - invocation < SERVICE_SECONDS, 'callback service deadline')
                    try:
                        backend.process_one(engine)
                    except socket.timeout:
                        require(not engine.failed, 'verdict ACK timeout poisoned adapter')
                        continue
            except Exception as error:
                errors.append('queue: ' + repr(error))
        observer_worker = threading.Thread(target=receive_delivered, name='x02-delivery')
        worker = threading.Thread(target=process_queues, name='x02-nfqueue')
        observer_worker.start()
        worker.start()
        manager.install()
        partial_start = time.monotonic_ns()
        partial_deadline = partial_start + 120_000_000_000
        ledger.append({'event': 'partial_started', 'started_ns': partial_start,
                       'deadline_ns': partial_deadline, 'baseline': baseline})
        for pid in list(stopped):
            os.kill(pid, signal.SIGCONT)
            stopped.remove(pid)
        last_partial, progress_proved = baseline, False
        while time.monotonic_ns() + 2_000_000_000 < partial_deadline:
            require(not errors and not engine.failed and stage.poll() is None,
                    'callback or full StageA failed during partial')
            last_partial = chain.sample('partial_four_live', baseline, partial_deadline, partial_start)
            progress_proved |= chain.progress_after(baseline, last_partial, partial_start)
            time.sleep(min(5, max(0, (partial_deadline - time.monotonic_ns()) / 1e9 - 2)))
        require(progress_proved and all(count['seen'] >= 8 for count in engine.counts.values()),
                'partial lacks two new common IDs or actual traffic in all24 directions')
        # Freeze LAST complete partial fullID BEFORE sender stop, drain or removal.
        anchor = last_partial
        ledger.append({'event': 'recovery_anchor_frozen', 'anchor': anchor,
                       'monotonic_ns': time.monotonic_ns()})
        freeze_senders(nodes, ledger, stopped)
        drain_deadline = time.monotonic() + 10
        while True:
            require(not errors and not engine.failed, 'callback failed while draining')
            try:
                backend.health(require_empty=True)
                require(engine.pending is None, 'queue is not drained')
                break
            except ValueError as error:
                require(str(error) == 'queue is not drained' and time.monotonic() < drain_deadline,
                        'queue drain failed: ' + str(error))
                time.sleep(.05)
        require(observer_idle.wait(5), 'raw delivery observer did not drain to idle')
        # Thread consumes only receives now; request/unbind is exclusively main after join.
        counts = manager.counters_quiescent()
        ledger.append({'event': 'partial_quiescent_counters', 'counts': counts,
                       'adapter_counts': engine.counts, 'monotonic_ns': time.monotonic_ns()})
        removal_start = time.monotonic_ns()
        manager.remove_owned_table()
        removal_complete = time.monotonic_ns()
        stop.set()
        worker.join(5)
        observer_worker.join(5)
        require(not worker.is_alive() and not observer_worker.is_alive() and not errors,
                'callback/observer did not stop cleanly')
        observer.close()
        backend.close_drained()
        # Stable counters and exact raw delivery multiset are checked independently.
        records = [json.loads(line) for line in (args.output / 'kernel.jsonl').read_text().splitlines()]
        intents = [row for row in records if row.get('event') == 'intent']
        submitted = [row for row in records if row.get('event') == 'verdict_submitted']
        require(len(intents) == len(submitted) and engine.pending is None and not engine.failed,
                'verdict receipt missing or adapter poisoned')
        fields = ('direction', 'index', 'queue_packet_id', 'dropped')
        require([tuple(row[key] for key in fields) for row in intents]
                == [tuple(row[key] for key in fields) for row in submitted]
                and all(hashlib.sha256(bytes.fromhex(row['packet_hex'])).hexdigest()
                        == row['packet_sha256'] for row in intents),
                'intent/ACK identity or captured datagram digest differs')
        selection = verify_selection_trace(policy, [{key: row[key] for key in
                    ('direction', 'index', 'packet_sha256', 'dropped')} for row in intents])
        accepted = Counter(row['packet_sha256'] for row in intents if not row['dropped'])
        require(received == accepted, 'native datagram delivery differs from selected accepts')
        for ordinal, direction in enumerate(DIRECTIONS):
            actual = engine.counts[direction]
            require(counts[f'entry{ordinal}']['packets'] == actual['seen']
                    and counts[f'post{ordinal}']['packets'] == actual['submitted_accept']
                    and counts[f'entry{ordinal}']['bytes'] == sum(len(bytes.fromhex(row['packet_hex']))
                        for row in intents if row['direction'] == direction)
                    and counts[f'post{ordinal}']['bytes'] == sum(len(bytes.fromhex(row['packet_hex']))
                        for row in intents if row['direction'] == direction and not row['dropped']),
                    'actual native nft counter does not match serialized verdicts')
        ledger.append({'event': 'owned_partial_removed', 'started_ns': removal_start,
                       'completed_ns': removal_complete, 'selection': selection,
                       'raw_delivery_verified': True})
        for pid in list(stopped):
            os.kill(pid, signal.SIGCONT)
            stopped.remove(pid)
        # Conservative recovery clock starts at removal START, never at drain or first tip.
        recovery_deadline = removal_start + 180_000_000_000
        recovery = None
        while recovery is None:
            require(time.monotonic_ns() < recovery_deadline and stage.poll() is None,
                    'recovery deadline/StageA failed')
            current = chain.sample('recovery', anchor, recovery_deadline)
            if (recovery_target_met(anchor, current, recovery_deadline)
                    and chain.progress_after(anchor, current, removal_start)):
                recovery = current
            else:
                time.sleep(5)
        ledger.append({'event': 'partial_and_recovery_verified', 'anchor': anchor,
                       'recovery': recovery, 'deadline_ns': recovery_deadline})
        remaining = SERVICE_SECONDS - (time.monotonic() - invocation)
        require(remaining > 0, 'no budget for natural StageA settlement')
        code = stage.wait(timeout=remaining)
        stage_natural = True
        write_once(args.output / 'stage-exit.json', {'natural': True, 'exit': code,
                   'observed_ns': time.monotonic_ns(), 'pid': stage.pid})
        require(code == 0, 'full StageA experiment/settlement naturally failed')
        report_path = readiness.parent / 'report.json'
        report_raw = report_path.read_bytes()
        report = json.loads(report_raw)
        ledger.append({'event': 'stage_report_original', 'path': str(report_path),
                       'raw_hex': report_raw.hex(), 'sha256': hashlib.sha256(report_raw).hexdigest()})
        require(report['status'] == 'pass' and report['mode'] == 'experiment'
                and report['experiment']['final_status'] == 'complete'
                and report['source_commit'] == context['source_sha']
                and report['source_commit_at_report'] == context['source_sha']
                and not report['git_status'], 'natural StageA report/settlement/source differs')
        closure.verify_binding(binding)
        cgroup_path = Path('/sys/fs/cgroup') / context['cgroup'].split(':', 2)[-1].strip().lstrip('/')
        remaining_pids = (cgroup_path / 'cgroup.procs').read_text()
        ledger.append({'event': 'post_stage_cgroup', 'raw': remaining_pids,
                       'path': str(cgroup_path), 'monotonic_ns': time.monotonic_ns()})
        require(set(map(int, remaining_pids.split())) == {os.getpid()},
                'StageA tools/DHT or descendants remain in service cgroup')
        require(all(not Path(f"/proc/{node['pid']}").exists() for node in nodes),
                'validator child remains after natural StageA exit')
        checks_passed = True
    finally:
        cleanup_errors = []
        def attempt(label, action):
            try:
                action()
            except Exception as error:
                cleanup_errors.append(label + ': ' + repr(error))
                ledger.append({'event': 'cleanup_failed', 'action': label, 'error': repr(error)})
        # Each owned cleanup is attempted independently; an unknown nft owner
        # must never suppress child termination or turn a failed delete green.
        if manager is not None and not manager.removed:
            attempt('owned_table', manager.remove_owned_table)
        for pid in list(stopped):
            def resume(pid=pid):
                node = next(node for node in nodes if node['pid'] == pid)
                current = Path(f'/proc/{pid}/stat').read_bytes().rsplit(b') ', 1)[1].split()
                require(int(current[19]) == node['pid_start_ticks'], 'cleanup sender generation changed')
                os.kill(pid, signal.SIGCONT)
                stopped.remove(pid)
            attempt('resume_owned_sender', resume)
        stop.set()
        for thread in (worker, observer_worker):
            if thread is not None:
                def join(thread=thread):
                    thread.join(5)
                    require(not thread.is_alive(), 'cleanup thread remains')
                attempt('join_' + thread.name, join)
        if observer is not None:
            attempt('close_observer', observer.close)
        if backend is not None and backend.bound:
            def close_backend():
                require(worker is None or not worker.is_alive(), 'worker owns queue socket')
                backend.close_drained()
            attempt('queue_empty_unbind', close_backend)
        if stage is not None:
            def terminate_stage():
                if stage.poll() is None:
                    os.killpg(stage.pid, signal.SIGTERM)
                    try:
                        code = stage.wait(timeout=15)
                    except subprocess.TimeoutExpired:
                        os.killpg(stage.pid, signal.SIGKILL)
                        code = stage.wait(timeout=5)
                    write_once(args.output / 'stage-abort.json', {'natural': False, 'exit': code,
                               'pid': stage.pid, 'observed_ns': time.monotonic_ns()})
                elif not stage_natural:
                    write_once(args.output / 'stage-exit.json', {'natural': True, 'exit': stage.returncode,
                               'pid': stage.pid, 'observed_ns': time.monotonic_ns()})
            attempt('StageA_terminal', terminate_stage)
        def verify_children_gone():
            require(all(not Path(f"/proc/{node['pid']}").exists() for node in nodes),
                    'validator remains after internal cleanup')
        attempt('owned_children_gone', verify_children_gone)
        cleanup_ok = not cleanup_errors and not errors
        ledger.append({'event': 'final', 'checks_passed': checks_passed,
                       'cleanup_ok': cleanup_ok, 'stage_natural': stage_natural,
                       'worker_alive': bool(worker and worker.is_alive()),
                       'observer_alive': bool(observer_worker and observer_worker.is_alive()),
                       'errors': errors, 'monotonic_ns': time.monotonic_ns()})
        for stream in (ledger, chain_ledger, delivered):
            stream.close()
    require(checks_passed and cleanup_ok, 'full four-node run or owned cleanup incomplete')
