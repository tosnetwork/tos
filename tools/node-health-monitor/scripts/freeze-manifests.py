#!/usr/bin/env python3
"""Freeze inspected anchors, dependency checksums and explicit unsupported boundaries."""
import hashlib,json,subprocess,tomllib
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];REPO=ROOT.parents[1]
BASE='86db5fe9e93fe0a04c324dc0aa58dcfe88ce4b9f'
def write(name,v): (ROOT/'contracts'/name).write_text(json.dumps(v,indent=2)+'\n')
def anchor(path,symbol):
 text=subprocess.check_output(['git','show',BASE+':'+path],cwd=REPO,text=True); assert symbol in text,(path,symbol)
 return dict(commit=BASE,path=path,symbol=symbol,source_sha256=hashlib.sha256(text.encode()).hexdigest())
sources=[]
for name,path,symbol,interface,kind,unit,scope,owner,cost in [
 ('native_exporter','metrics/prometheus-exporter.cpp','PrometheusExporter::on_request','GET /metrics','mixed','per metric','node','health_edge','bounded fan-out; per-provider contiguous work not accepted'),
 ('process','tools/node-health-monitor/crates/health-services/src/edge.rs','sample_process','fixed proc fields','gauge','bytes/ticks','node','health_edge','two stat reads, one status read and boot identity'),
 ('consensus_status','validator-engine/json-rpc-server-blocks.cpp','getNodeConsensusStatus','JSON-RPC getNodeConsensusStatus','snapshot','typed raw','masterchain','health_edge','manager actor snapshot; adapter unsupported'),
 ('quic','quic/quic-sender.cpp','collect_stats','native collector summary','raw','RTT unverified; bytes may decrease','node','health_edge','connection traversal; performance gate not run'),
 ('vote_intent','validator/consensus/simplex/pool.cpp','publish<PersistOwnVoteIntent>','core hook not connected','counter','operations','masterchain','native_core','anchor only'),
 ('vote_signed_commit','validator/consensus/simplex/pool.cpp','publish<PersistOwnSignedVote>','core hook not connected','counter','operations','masterchain','native_core','anchor only'),
 ('pq_sign','crypto/pq/consensus-pq-signer.cpp','ValidatorPQKeyStore::sign_consensus','opt-in native metrics','histogram','seconds','node','native_core','fixed atomic counters and clock'),
 ('pq_verify','validator/consensus/types.cpp','PeerValidator::check_signature','opt-in native metrics','histogram','seconds','node','native_core','fixed atomic counters and clock'),
 ('rocksdb','scripts/validator_rss_rocksdb_monitor.sh','rocksdb','fixed incremental reader not connected','raw','per field','node','health_edge','unimplemented'),
]:
 sources.append(dict(source_id=name,anchor=anchor(path,symbol),interface=interface,grammar='strict schema required before adapter enablement',semantic_type=kind,unit=unit,scope=scope,absence='unavailable; never zero',reset='process/source epoch',generation='increments only at valid source completion',owner=owner,cost=cost,capacity={'max_bytes':2097152 if name=='native_exporter' else 262144},fixture=None,capability={'supported':name in ['process','native_exporter','pq_sign','pq_verify'],'enabled':False,'contract_valid':False,'performance_gate':'not_run'}))
write('source-manifest.json',dict(schema_version=1,design_revision='R4',design_blob='b6ee93b81ad3794eecff3b6c8ed2faf28072120c',base_commit=BASE,complete_manifest=False,sources=sources))
actions=[]
for name in ['proposal','notarize_vote','finalize_vote','skip_vote']:
 if name=='proposal':
  phases=[dict(phase='requested',anchor=anchor('validator/consensus/block-producer.cpp','generate_candidates')),dict(phase='candidate_published',anchor=anchor('validator/consensus/block-producer.cpp','CandidateGenerated'))]
 else:
  phases=[dict(phase=p,anchor=anchor('validator/consensus/simplex/pool.cpp',s)) for p,s in [('requested','cast_our_vote'),('intent_committed','publish<PersistOwnVoteIntent>'),('signed','sign_vote'),('signed_committed','publish<PersistOwnSignedVote>'),('local_applied','handle_vote(*bus.local_id'),('broadcast_enqueued','OutgoingProtocolMessage::BroadcastToAll')]]
 actions.append(dict(action=name,phases=phases,local_population='logical request keyed by epoch/session/scope/action/slot/candidate; retry dedupe required',scheduled_population='leader window' if name=='proposal' else None,network_population='separate observer evidence; unsupported',protocol_deadline=None,deadline_reason='no frozen deadline contract; do not infer from block interval',early_returns=['finality_behind','journal_unusable','duplicate','intent_failure','sign_failure','signed_commit_failure','apply_false','cancelled'],replay='separate origin; never a new live broadcast',instrumented=False))
write('action-manifest.json',dict(schema_version=1,actions=actions))
write('persistence-contract.json',dict(schema_version=1,contract_id='simplex_vote_commit_ack',anchors=[anchor('validator/consensus/simplex/db.cpp','PersistOwnVoteIntent'),anchor('validator/consensus/simplex/db.cpp','PersistOwnSignedVote'),anchor('validator/consensus/bridge.cpp','KeyValueAsync'),anchor('tddb/td/db/KeyValueAsync.h','commit_transaction()'),anchor('tddb/td/db/RocksDb.cpp','options.sync = true')],ordering=['intent commit acknowledgement','sign','signed bytes commit acknowledgement','apply/enqueue'],durability='commit_acknowledged',wal='not disabled in inspected write options; actual deployment verification pending',restart_verified_in_test=False,power_loss_verified=False,durable_finality_supported=False))
write('diagnostic-catalog.json',dict(schema_version=1,header_bytes=64,max_record_bytes=512,endian='little',records=[dict(source_catalog_id=7,record_type=1,name='synthetic_interoperability_fixture',payload_bytes=2,production_enabled=False)],fixture='tests/fixtures/diagnostic-v1.hex'))
buckets=[.001,.002,.005,.01,.02,.05,.1,.2,.5,1,2,5]
tuples=[[op,'mldsa44',result] for op in ['sign','verify'] for result in ['success','failure']]
metrics=[dict(name='tos_pq_operation_duration_seconds',semantic_type='histogram',label_names=['operation','suite','result'],allowed_tuples=tuples,finite_buckets=buckets,bytes_per_tuple=128),dict(name='tos_pq_operations_total',semantic_type='counter',label_names=['operation','suite','result'],allowed_tuples=tuples,finite_buckets=[],bytes_per_tuple=8),dict(name='tos_health_pq_accounting_complete',semantic_type='gauge',label_names=['operation'],allowed_tuples=[['sign'],['verify']],finite_buckets=[],bytes_per_tuple=1)]
write('metric-manifest.json',dict(schema_version=1,profile='initial_pq_contract',scopes=['node','masterchain'],max_series=2048,max_bytes=4194304,families=metrics,scope_note='masterchain action metrics not enabled; this catalog is not the full validator-core profile'))
lock=tomllib.loads((ROOT/'Cargo.lock').read_text())
write('dependency-lock.json',dict(schema_version=1,rust='1.97.1',packages=[{k:p[k] for k in ['name','version','checksum'] if k in p} for p in lock['package'] if p['name'] in ['axum','reqwest','tokio','rusqlite','libsqlite3-sys']],aura={'commit':'1000f119d38f4c4656ced0ae883c90f6f7610890','enabled':False,'integration':'not_run'},mcp={'enabled':False,'sdk':None,'reason':'not integrated; must pin before C08'},prometheus={'enabled':False,'version':None,'reason':'runtime package and promtool not installed; C03 pending'}))
config=json.loads((ROOT/'contracts/config.schema.json').read_text())['properties']
for placement,name in [('development_fixture','development-fixture.yaml'),('production_off_validator','production.example.yaml')]:
 value={k:(v['const'] if 'const' in v else None) for k,v in config.items()};value['placement']=placement
 if placement=='development_fixture': value['max_contiguous_monitor_work_us']='1000'
 # JSON is valid YAML; use one parser and avoid implicit scalar coercions.
 (ROOT/'config'/name).write_text(json.dumps(value,indent=2)+'\n')
