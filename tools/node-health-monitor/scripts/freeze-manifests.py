#!/usr/bin/env python3
"""Freeze inspected anchors, dependency checksums and explicit unsupported boundaries."""
import hashlib,json,subprocess,tomllib
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];REPO=ROOT.parents[1]
BASE='86db5fe9e93fe0a04c324dc0aa58dcfe88ce4b9f'
MEMO_COMMIT='cb84e1684b46b2d94e0f9c4654020a96ac71ca66'
C01_IMPL='be690c9252b962d21017026f5665b61547dccbdd'
DESIGN_BLOB='c28a6b2506c98fc728f868081a8192f7d0cd0d0a'
WORK_ORDER_BLOB='f7cd3371c8023bb61409d5e77fd96a3741f0cddd'
def write(name,v): (ROOT/'contracts'/name).write_text(json.dumps(v,indent=2)+'\n')
def anchor(path,symbol):
 return anchor_at(BASE,path,symbol)
def anchor_at(commit,path,symbol):
 text=subprocess.check_output(['git','show',commit+':'+path],cwd=REPO,text=True); assert symbol in text,(path,symbol)
 return dict(commit=commit,path=path,symbol=symbol,source_sha256=hashlib.sha256(text.encode()).hexdigest())
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
for source in sources:
 if source['source_id']=='native_exporter':
  source['anchor']=anchor_at(C01_IMPL,'metrics/prometheus-exporter.cpp','PrometheusExporter::on_request')
  source['grammar']='OpenMetrics 1.0 exact immutable body including EOF; paired native_core hash/generation'
  source['cost']='one admitted fan-out per >=15 seconds; 2-second owner response; child lease drains; isolated publisher-prepare measurement only'
 if source['source_id']=='quic':
  source['anchor']=anchor_at(C01_IMPL,'quic/quic-sender.cpp','health_metrics_policy::build_per_path')
  source['cost']='summary collection only; per-path construction compile-time disabled; production performance gate not run'
fixtures={
 'native_exporter':('crates/health-core/tests/fixtures/native-core.prom','openmetrics_text','isolated production exporter actor with synthetic collector','test/test-health-native-snapshot.cpp'),
 'process':('crates/health-core/tests/fixtures/process-source.json','source-envelope.schema.json','synthetic fixed process fields matching sample_process contract','crates/health-services/tests/http.rs'),
 'pq_sign':('crates/health-core/tests/fixtures/native-core.json','source-envelope.schema.json','isolated production exporter actor with synthetic PQ counters','test/test-health-native-snapshot.cpp'),
 'pq_verify':('crates/health-core/tests/fixtures/native-core.json','source-envelope.schema.json','isolated production exporter actor with synthetic PQ counters','test/test-health-native-snapshot.cpp'),
}
for source in sources:
 if source['source_id'] in fixtures:
  fixture,schema,kind,test_source=fixtures[source['source_id']]
  source.update(fixture=fixture,fixture_schema=schema,fixture_provenance={'kind':kind,'test_source':test_source,'production_node':False})
  source['capability']['contract_valid']=True
def unsupported(source_id,commit,path,symbol,interface,grammar,semantic_type,unit,scope,absence,reset,generation,owner,cost,max_bytes=262144):
 return dict(source_id=source_id,anchor=anchor_at(commit,path,symbol),interface=interface,grammar=grammar,semantic_type=semantic_type,unit=unit,scope=scope,absence=absence,reset=reset,generation=generation,owner=owner,cost=cost,capacity={'max_bytes':max_bytes},fixture=None,capability={'supported':False,'enabled':False,'contract_valid':False,'performance_gate':'not_run'})
sources.extend([
 unsupported('host_cgroup','0a3aafda25ad9fa9d93be45156e2df2838646085','tools/node-health-monitor/crates/health-services/src/edge.rs','sample_process','fixed proc/cgroup fields; full adapter not connected','host/cgroup SourceEnvelope variant not frozen','snapshot','per field','node','unsupported; never zero','source epoch','not implemented','health_edge','fixed file set required; not accepted'),
 unsupported('readiness',BASE,'validator-engine/json-rpc-server-utils.cpp','handle_readyz','GET /healthcheck and GET /readyz adapter not connected','strict readiness payload not frozen','snapshot','typed raw','node','unsupported; never healthy by default','source epoch','not implemented','health_edge','sequential RPC lane required'),
 unsupported('guard','0a3aafda25ad9fa9d93be45156e2df2838646085','tools/node-health-monitor/crates/health-core/src/guard.rs','pub struct Guard','fixed guard signal adapter incomplete','guard state contract exists; full signal SourceEnvelope absent','state','state','node','unsupported source; missing signal forces guarded state','edge epoch','not implemented','health_edge','fixed 5 second reads; full adapter not accepted'),
 unsupported('witness','0a3aafda25ad9fa9d93be45156e2df2838646085','tools/node-health-monitor/crates/health-core/src/observer.rs','pub fn compare','observer schedule and witness adapter not implemented','typed block comparison primitive only','external observation','typed anchor','masterchain','unsupported; never infer network result','observer epoch','not implemented','observer','fixed approved endpoints required'),
 unsupported('diagnostic_trace',BASE,'validator/consensus/trace-collector.cpp','TraceCollectorImpl','legacy trace is not connected to diagnostic IPC','only synthetic catalog 7/type 1 is frozen','diagnostic','records','masterchain','unsupported; core health remains independent','process epoch','not implemented','native_core','producer early gate and bounded IPC not implemented',4194304),
 unsupported('validator_stats',BASE,'validator-engine/validator-engine.cpp','run_control_query(tos::tos_api::engine_validator_getStats','engine.validator.getStats authenticated control protocol','provider allowlist and payload schemas not frozen','snapshot','typed raw','node','unsupported and disabled; never zero','source epoch','not implemented','health_edge','default disabled pending source cost gate'),
])
sources.append(dict(source_id='native_core',anchor=anchor_at(C01_IMPL,'metrics/native-core-snapshot.h','NativeCorePublisher'),interface='GET /health-snapshot (loopback, configured alias and network only)',grammar='source-envelope.schema.json native_core payload; exact decimal u64; exact bytes/hash/generation paired to immutable OpenMetrics body',semantic_type='cumulative counter and source metadata',unit='operations/bytes/milliseconds',scope='node',absence='unavailable or explicit null; never zero',reset='process/source epoch',generation='same valid completion as OpenMetrics',owner='health_edge',cost='cache-only reads; publisher preparation measured only in isolated fixture; upstream/full-callback and production acceptance not measured',capacity={'max_bytes':262144},fixture='crates/health-core/tests/fixtures/native-core.json',fixture_schema='source-envelope.schema.json',fixture_provenance={'kind':'isolated production exporter actor with synthetic collector','test_source':'test/test-health-native-snapshot.cpp','openmetrics_fixture':'crates/health-core/tests/fixtures/native-core.prom','implementation_commit':C01_IMPL,'production_node':False},capability={'supported':True,'enabled':False,'contract_valid':True,'performance_gate':'not_run'}))
write('source-manifest.json',dict(schema_version=1,design_revision='R4',design_blob=DESIGN_BLOB,work_order_blob=WORK_ORDER_BLOB,memo_commit=MEMO_COMMIT,base_commit=BASE,c01_implementation_commit=C01_IMPL,complete_manifest=False,c00_contract_inventory_complete=True,c01_source_publisher_inventory_complete=True,production_adapter_inventory_complete=False,completeness_note='C01 closes only the bounded native source publisher inventory. Synthetic isolated exporter fixtures are not production fixtures; unavailable C02-C05 adapters remain null/disabled and production performance is not accepted.',sources=sources))
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
top_sources=[[source] for source in ['exporter','exporter_internal','quic','overlay','json_rpc']]
exporter_sources=[['http_server']]
metrics=[
 dict(name='tos_pq_operation_duration_seconds',semantic_type='histogram',label_names=['operation','suite','result'],allowed_tuples=tuples,finite_buckets=buckets,bytes_per_tuple=128),
 dict(name='tos_pq_operations_total',semantic_type='counter',label_names=['operation','suite','result'],allowed_tuples=tuples,finite_buckets=[],bytes_per_tuple=8),
 dict(name='tos_health_pq_accounting_complete',semantic_type='gauge',label_names=['operation'],allowed_tuples=[['sign'],['verify']],finite_buckets=[],bytes_per_tuple=1),
]
for prefix,allowed in [('tos_health_source_',top_sources),('tos_exporter_health_source_',exporter_sources)]:
 for suffix,kind in [('collection_completed_timestamp_seconds','gauge'),('last_success_timestamp_seconds','gauge'),('usable','gauge'),('failures_total','counter'),('observed_timestamp_available','gauge')]:
  metrics.append(dict(name=prefix+suffix,semantic_type=kind,label_names=['source'],allowed_tuples=allowed,finite_buckets=[],bytes_per_tuple=8))
for name,kind in [
 ('tos_exporter_collectors','gauge'),('tos_exporter_collections_total','counter'),
 ('tos_exporter_last_collection_duration_seconds','gauge'),('tos_exporter_last_collection_timestamp_seconds','gauge'),
 ('tos_exporter_snapshot_generation','gauge'),('tos_exporter_snapshot_completed_timestamp_seconds','gauge'),
 ('tos_exporter_collection_inflight','gauge'),('tos_exporter_collection_skipped_total','counter'),
 ('tos_exporter_collection_failures_total','counter'),
 ('tos_health_core_registry_instrumentation_complete','gauge'),
 ('tos_health_core_registry_dropped_updates_total','counter'),
]:
 metrics.append(dict(name=name,semantic_type=kind,label_names=[],allowed_tuples=[[]],finite_buckets=[],bytes_per_tuple=8))
write('metric-manifest.json',dict(schema_version=1,profile='c01_source_publisher_contract',scopes=['node','masterchain'],max_series=128,computed_max_series=107,r4_global_core_max_series=2048,max_openmetrics_bytes=2097152,declared_tuple_value_bytes=874,tuple_storage_note='Value-field accounting only; not total registry, strings, actor, heap or publisher body memory.',registry_capacity_slots=64,approved_registry_metric_names=[],registry_memory_bytes_max=16384,generic_counter_wire_precision='OpenMetrics double only; exact u64 is unavailable for generic registry values and requires a future typed approved adapter',families=metrics,scope_note='C01 fixed publisher/source subset. The 128 cap is not the R4 global core cap. No C04 business metric is approved or registered; fixture-only source labels are excluded. Production performance acceptance is not_run.'))
lock=tomllib.loads((ROOT/'Cargo.lock').read_text())
sha=lambda path:hashlib.sha256((ROOT/path).read_bytes()).hexdigest()
write('dependency-lock.json',dict(schema_version=1,rust='1.97.1',rust_toolchain_sha256=sha('rust-toolchain.toml'),cargo_lock_sha256=sha('Cargo.lock'),contract_python={'version':(ROOT/'.python-version').read_text().strip(),'requirements_lock':'requirements-contracts.lock','requirements_lock_sha256':sha('requirements-contracts.lock')},packages=[{k:p[k] for k in ['name','version','checksum'] if k in p} for p in lock['package'] if p['name'] in ['axum','reqwest','tokio','rusqlite','libsqlite3-sys']],aura={'commit':'1000f119d38f4c4656ced0ae883c90f6f7610890','enabled':False,'integration':'not_run'},mcp={'enabled':False,'protocol_version':'2025-06-18','sdk':'rmcp','version':'3.5.0','tag_commit':'0cde3c5cf3e6aff0cc852ce6045f107e95991f48','crate_sha256':'fae7019994ae0fe4ada40b732f798f3ff26f0f04facb1477f1bf37eb4f18a2d3','runtime_gate':'C08_not_run','reason':'inventory pin only; no MCP dependency or endpoint is enabled before C08 integration tests'},prometheus={'enabled':False,'version':'3.9.1','tag_commit':'9ec59baffb547e24f1468a53eb82901e58feabd8','artifact':'prometheus-3.9.1.linux-amd64.tar.gz','artifact_sha256':'86a6999dd6aacbd994acde93c77cfa314d4be1c8e7b7c58f444355c77b32c584','runtime_gate':'C03_not_run','reason':'inventory pin only; promtool and Alertmanager integration remain a C03 runtime gate'}))
config=json.loads((ROOT/'contracts/config.schema.json').read_text())['properties']
for placement,name in [('development_fixture','development-fixture.yaml'),('production_off_validator','production.example.yaml')]:
 value={k:(v['const'] if 'const' in v else None) for k,v in config.items()};value['placement']=placement
 if placement=='development_fixture': value['max_contiguous_monitor_work_us']='1000'
 # JSON is valid YAML; use one parser and avoid implicit scalar coercions.
 (ROOT/'config'/name).write_text(json.dumps(value,indent=2)+'\n')
