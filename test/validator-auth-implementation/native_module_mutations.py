"""Require production state/authority/native proof guards to fail their real tests."""
import argparse,json,subprocess
from pathlib import Path
from mutation_support import replace_once
MUTATIONS=[
 ('permit-registry-shape','service-auth','body.registry_root_ == Hash{} ||',''),
 ('poll-terminal-regression','service-auth','if ((previous->state_ == 2 || previous->state_ == 3) && *previous != next) return Error{"terminal-state-regression"};',''),
 ('poll-reserved-regression','service-auth','if (previous->state_ == 1)','if (false)'),
 ('poll-reserved-binding','service-auth','if (next.statement_id_ != previous->statement_id_ || next.fence_ != previous->fence_) return Error{"reserved-state-binding"};',''),
 ('proof-no-detached-cells','native-proof','reachable.cells != static_cast<unsigned>(info.cell_count)','false'),
 ('publication-before-manifest','native-proof','if (!published.value()) return Error{"proof-publication"};',''),
 ('duplicate-key-epoch','state','if (!unique_epochs.emplace(k.identity_, KeySlot{k.role_, k.suite_, k.parameters_}, k.epoch_).second) return Error{"duplicate-key-epoch"};',''),
 ('stale-permit-policy','service-auth','if (current == current_.end() || current->second != permit.body_.service_policy_) return Error{"stale-permit-policy"};',''),
 ('key-hash-binding','state','hash.value() != id ||',''),
 ('apply-owned-state','state','RegistryState next = *this;','RegistryState& next = const_cast<RegistryState&>(*this);'),
 ('pop-signature','context','if (!signature.value()) return Error{"possession-signature"};',''),
 ('admin-freshness','context','if (inclusion < expected.anchor_mc_ || inclusion - expected.anchor_mc_ > 128) return Error{"admin-freshness"};',''),
 ('current-admin-binding','context','!active ||',''),
 ('permit-live','service-auth','if (!live) return Error{"duty-not-permitted"};',''),
 ('receipt-frontier','service-auth','if (!retained.value()) return Error{"receipt-frontier"};',''),
 ('authenticated-state-root','native-proof','if (!hash_equal(root, anchor.state_)) return Error{"state-root"};',''),
 ('range-omission','native-proof','if (canonical.value().size() != response.size() || !std::equal(canonical.value().begin(), canonical.value().end(), response.begin())) return Error{"response-association"};',''),
 ('unrelated-proof-values','native-proof','minimal.ok()->get_hash() != cell.value()->get_hash()','false'),
 ('capability-gate','native-proof','if (!(cap.fetch_ulong(64) & 1024)) return Error{"config-capability"};','cap.fetch_ulong(64);'),
]
def main(build,out):
 build=build.resolve();folder=build/'test/validator-auth-implementation';report=[]
 for name,module,before,after in MUTATIONS:
  source=folder/f'mutated-{module}.cpp';original=source.read_text();target=f'test-p0-{module}-mutant'
  def run(text):
   source.write_text(text);subprocess.run(['cmake','--build',str(build),'--target',target,'-j2'],check=True,capture_output=True,text=True)
   return subprocess.run([str(folder/target)],capture_output=True,text=True)
  try:
   baseline=run(original);assert baseline.returncode==0,(name,baseline.stderr)
   result=run(replace_once(original,before,after))
   assert result.returncode==1 and result.stderr.strip()=='ASSERTION: '+name,(name,result.returncode,result.stderr)
   report.append({'guard':name,'compiled':True,'assertion_failed':True});print('KILLED:',name,flush=True)
  finally:
   restored=run(original);assert restored.returncode==0,(name,restored.stderr)
 out.write_text(json.dumps({'native_module_mutations':report,'restored_baselines':True},indent=2)+'\n')
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--build',type=Path,required=True);p.add_argument('--out',type=Path,required=True);a=p.parse_args();main(a.build,a.out)
