#!/usr/bin/env python3
"""Generate closed draft-2020-12 wire contracts; no live source discovery."""
import copy
import importlib.util
import json
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('inputs', ROOT/'tests/generate_schemas.py')
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
S = lambda n=256: {'type':'string','maxLength':n}
I = lambda a=0,b=4294967295: {'type':'integer','minimum':a,'maximum':b}
E = lambda *v: {'type':'string','enum':list(v)}
O = lambda **p: {'type':'object','properties':p,'required':list(p),'additionalProperties':False}
A = lambda x,n=128: {'type':'array','items':x,'maxItems':n}
N = lambda x: {'anyOf':[x,{'type':'null'}]}
R = lambda x: {'$ref':'#/$defs/'+x}
B = {'type':'boolean'}
U = {'type':'string','pattern':'^(0|[1-9][0-9]{0,19})$','format':'uint64'}
H = {'type':'string','pattern':'^[0-9a-f]{64}$'}
TIME = m.TIME
ALIAS = m.NODE
COMMON = {
 'u64':U,'hash':H,'utc':TIME,'alias':ALIAS,
 'quality':O(instrumentation_complete=B,producer_dropped=U,relay_dropped=U,parse_errors=U,shed_reason=N(S(96))),
 'coverage':O(status=E('complete','partial','unknown'),missing_fields=A(S(96),64),gaps=A(S(256),32),sampling_policy=S(128)),
 'capability':O(supported=B,enabled=B,contract_valid=B,performance_gate=E('pass','fail','not_run')),
 'gate':O(name=ALIAS,status=E('pass','fail','not_run'),evidence_digest=N(H)),
 'budget':O(remaining_calls=I(0,16),remaining_bytes=I(0,131072),expires_at=TIME),
 'pagination':O(next_cursor=N(S(2048)),truncated=B,scan_complete=B),
 'error':O(code=S(96),message=S(512),retryable=B,retry_after_seconds=N(I(0,300))),
 'missing':O(source_id=ALIAS,reason=S(256)),
 'label':O(name=ALIAS,value=S(96)),
 'block':O(kind={'const':'block'},network_id=H,scope_id=ALIAS,workchain=I(-2147483648,2147483647),shard=U,seqno=I(),root_hash=H,file_hash=H,point=S(64)),
 'consensus':O(kind={'const':'consensus'},network_id=H,scope_id=ALIAS,session_id=H,slot=I(),candidate_id=N(S(160)),phase=S(64)),
 'storage_ack':O(kind={'const':'storage_ack'},operation=S(64),logical_reference=S(160),contract_id=ALIAS,source_epoch=S(128),completion_sequence=U,durability=E('commit_acknowledged','restart_verified_in_test','unknown')),
 'process':O(kind={'const':'process'},pid=I(1),rss_bytes=N(U),anon_bytes=N(U),file_bytes=N(U),swap_bytes=N(U),cpu_user_ticks=N(U),cpu_system_ticks=N(U)),
 'host_cgroup':O(kind={'const':'host_cgroup'},memory_current_bytes=U,memory_max_bytes=U,cpu_usage_usec=U,cpu_quota_usec=U,cpu_period_usec=U,oom_events=U),
 'pq_snapshot':O(complete=B,failed=U,succeeded=U),
 'native_core':O(kind={'const':'native_core'},generation=U,network_id=H,openmetrics_hash=H,bytes=I(0,2097152),pq_sign=N(R('pq_snapshot')),pq_verify=N(R('pq_snapshot'))),
 'native':O(kind={'const':'native'},generation=U,openmetrics_hash=H,bytes=I(0,2097152)),
 'unavailable':O(kind={'const':'unavailable'},reason=S(256)),
 'scalar':O(kind={'const':'scalar'},metric_id=S(96),value=N({'type':'number'}),unit=S(32)),
 'diagnostic':O(kind={'const':'diagnostic_fixture'},record_type={'const':1},payload={'type':'string','pattern':'^[0-9a-f]{4}$'}),
}
COMMON['anchor']={'oneOf':[R('block'),R('consensus'),R('storage_ack')]}
COMMON['payload']={'oneOf':[R(x) for x in ['process','host_cgroup','native','native_core','unavailable','scalar','diagnostic','block','consensus','storage_ack']]}
COMMON['source']=O(schema_version={'const':1},source_id=ALIAS,node_id=ALIAS,scope_id=ALIAS,process_epoch=S(128),source_epoch=S(128),source_version=S(96),generation=U,availability=E('available','disabled','unsupported','unauthorized','error','unknown'),observed_at=N(TIME),last_success_at=N(TIME),received_at=N(TIME),source_age_ms=N(I(0,9007199254740991)),clock_quality=E('valid','uncertain','invalid'),coverage=R('coverage'),content_hash=H,payload=R('payload'),quality=R('quality'))
COMMON['evidence']=O(evidence_id=S(128),kind=E('observation','derived','event','change'),node_id=ALIAS,source_id=ALIAS,source_version=S(96),source_record_id=S(256),process_epoch=S(128),observed_at=N(TIME),received_at=TIME,clock_quality=E('valid','uncertain','invalid'),scope_id=ALIAS,payload=R('payload'),content_hash=H,quality=R('quality'),redacted={'const':True},parent_evidence_ids=A(S(128),32),derivation_version=N(S(96)))
COMMON['component']=O(kind=E('process','host','chain','consensus','network','storage','index','gpu','telemetry','deployment'),sources=A(ALIAS,32),value=N(R('payload')),quality=R('quality'))
COMMON['event']=O(event_id=S(128),evidence_id=S(128),source_id=ALIAS,source_record_id=S(256),process_epoch=S(128),observed_at=N(TIME),scope_id=ALIAS,kind=S(64),stage=N(S(64)),reason=N(S(256)),correlation_id=N(S(160)),excerpt=S(512),content_hash=H,quality=R('quality'))
COMMON['change_field']=O(field=S(96),value=N(S(512)))
COMMON['dimensions']=O(local_action=E('requested','signed','committed','applied','enqueued','failed','unknown'),network_observation=E('observed','not_observed_in_window','unavailable'),certificate_membership=E('included','not_in_this_certificate','not_checked','unavailable'),proof_verification=E('not_checked','reported_valid','locally_verified','invalid','unavailable'),local_persistence=E('commit_acknowledged','restart_verified_in_test','unknown'))
COMMON['summary_value']=O(value=N({'type':'number'}),reason=N(S(128)))
DATA = {
 'tos_get_capabilities': O(contract_version={'const':'R4-v1'},catalog_digest=H,inventory_revision=S(96),watermark=U,network=H,node_capabilities=A(O(node_id=ALIAS,capabilities=A(O(name=ALIAS,value=R('capability')),32)),4),allowed_scopes=A(ALIAS,8),metric_ids=A(S(96),256),windows=O(start=TIME,end=TIME,change_start=TIME),query_mode={'const':'cache_only'},gates=A(R('gate'),64),remaining_budget=R('budget')),
 'tos_get_node_snapshot':O(node_id=ALIAS,as_of=TIME,process_epoch=S(128),role=E('validator','observer','rpc','unknown'),components=A(R('component'),10)),
 'tos_get_metric_window':O(series=A(O(metric_id=S(96),node_id=ALIAS,scope_id=ALIAS,labels=A(R('label'),8),unit=S(32),semantic_type=E('counter','gauge','histogram','raw'),population=S(256),clock=E('valid','uncertain','invalid'),points=N(A(O(at=TIME,value=N({'type':'number'})),240)),summary=N(O(**{k:R('summary_value') for k in ['first','last','min','max','mean','delta','rate','quantile']})),samples_count=U,expected_samples=N(U),coverage=R('coverage'),reset_count=U,source_evidence_ids=A(S(128),4096)),32)),
 'tos_get_event_window':O(events=A(R('event'),100),gaps=A(R('missing'),32)),
 'tos_get_change_history':O(changes=A(O(change_id=S(128),evidence_id=S(128),node_id=ALIAS,kind=E('deploy','restart','config','maintenance','load_test','resource_limit'),started=TIME,completed=N(TIME),actor_alias=ALIAS,before=A(R('change_field'),32),after=A(R('change_field'),32),reason=S(512),trusted_origin=B,quality=R('quality')),100),gaps=A(R('missing'),32)),
 'tos_get_block_evidence':O(selector=S(160),per_node=A(O(node_id=ALIAS,identity=N(R('anchor')),stage_events=A(R('event'),100),observed_durations=A(O(stage=S(64),duration_ns=N(U),reason=N(S(128))),32),ancestor_evidence=A(R('evidence'),100),dimensions=R('dimensions')),4),comparison_status=E('same','incomparable','observed_block_disagreement','unavailable'),missing_evidence=A(R('missing'),32)),
}
def envelope(data):
 return O(schema_version={'const':1},request_id=S(128),run_id=m.RUN,network_id=H,generated_at=TIME,status=E('ok','partial','unavailable','error'),data=N(data),evidence=A(R('evidence'),128),missing_evidence=A(R('missing'),32),coverage=R('coverage'),pagination=R('pagination'),error=N(R('error')),budget=R('budget'))
def document(body):
 used=set()
 def visit(v):
  if isinstance(v,dict):
   ref=v.get('$ref','')
   if ref.startswith('#/$defs/'):
    name=ref.rsplit('/',1)[1]
    if name not in used:used.add(name);visit(COMMON[name])
   for child in v.values():visit(child)
  elif isinstance(v,list):
   for child in v:visit(child)
 visit(body)
 return {'$schema':'https://json-schema.org/draft/2020-12/schema',**copy.deepcopy(body),'$defs':{k:copy.deepcopy(COMMON[k]) for k in sorted(used)}}
def write(path,body):
 path=ROOT/'contracts'/path;path.parent.mkdir(parents=True,exist_ok=True);path.write_text(json.dumps(document(body),indent=2)+'\n')
def main():
 write('common.schema.json',R('u64'))
 write('source-envelope.schema.json',R('source'))
 write('edge-heartbeat.schema.json',O(schema_version={'const':1},node_id=ALIAS,edge_epoch=S(128),state=E('available','degraded','unknown'),guard=E('normal','guarded','emergency','recovering'),validator_epoch=N(S(128)),sources=A(O(source_id=ALIAS,age_ms=N(U),usable=B),32)))
 write('edge-snapshot.schema.json',O(schema_version={'const':1},status=E('ok','partial'),sources=A(R('source'),32),anchors=A(R('anchor'),32)))
 write('edge-capabilities.schema.json',O(schema_version={'const':1},node_id=ALIAS,catalog_digest=H,capabilities=A(O(name=ALIAS,value=R('capability')),32),sources=A(O(source_id=ALIAS,status=E('available','disabled','unsupported','unauthorized','error','unknown')),32)))
 write('diagnostic-batch.schema.json',O(schema_version={'const':1},node_id=ALIAS,edge_epoch=S(128),process_epoch=S(128),source_id=ALIAS,batch_id=H,records=A(O(sequence=U,monotonic_ns=U,observed_at=N(TIME),record_type={'const':1},payload={'type':'string','pattern':'^[0-9a-f]{4}$'}),128),quality=O(dropped=U,gaps=B)))
 for name,body in m.INPUT_SCHEMAS.items(): write('tools/'+name+'.input.schema.json',body);write('tools/'+name+'.output.schema.json',envelope(DATA[name]))
 write('diagnosis.schema.json',O(status=E('analysis','insufficient_evidence'),summary=S(2000),findings=A(O(claim=S(1000),basis=E('observed','hypothesis'),evidence_ids={**A(S(128),8),'uniqueItems':True}),6),missing_evidence=A(S(256),16),recommended_runbooks={**A(E('inspect_duty_accounting','inspect_persistence_progress','inspect_consensus_queues','inspect_storage_pressure','inspect_quic_backlog','inspect_observer_coverage','inspect_telemetry_unavailable','inspect_ai_unavailable'),6),'uniqueItems':True}))
 write('config.schema.json',O(schema_version={'const':1},placement=E('development_fixture','production_off_validator'),native_owner={'const':'health_edge'},remote_native_mode={'const':'cached_only'},native_interval_seconds={'const':15},native_actual_inflight={'const':1},native_source_budget_ms={'const':2000},native_http_timeout_ms={'const':3000},native_cache_max_age_seconds={'const':30},native_max_bytes={'const':2097152},native_build_per_path={'const':False},getstats_enabled={'const':False},skip_missed_ticks={'const':True},retry_on_timeout={'const':False},core_max_bytes={'const':4194304},core_max_series={'const':2048},core_max_scopes={'const':8},diagnostics_enabled={'const':False},ai_enabled={'const':False},live_fallback={'const':False},max_contiguous_monitor_work_us=N(U),network_id=N(H),binary_digest=N(H),performance_digest=N(H),failure_domains=N(O(validator=ALIAS,monitor=ALIAS,watchdog=ALIAS)),mtls_digest=N(H),receiver_digest=N(H),effective_resource_digest=N(H)))
if __name__=='__main__':main()
