"""Compile native committee guard removals and require named assertion failures."""
import argparse,json,subprocess
from pathlib import Path
from mutation_support import replace_once
MUTATIONS=[
 ('unselected-duplicate-binding','native-committee','!identities.insert(identity).second || !stakes.insert(stake).second || !network_keys.insert(hash(member.pubkey.as_bits256().as_slice())).second','(identities.insert(identity), stakes.insert(stake), network_keys.insert(hash(member.pubkey.as_bits256().as_slice())), false)'),
 ('native-shuffle','mc-config','const auto& v = vset.list[idx[i]]; nodes.emplace_back(v.pubkey, v.weight, v.adnl_addr); nodes.back().auth_binding = v.auth_binding;','const auto& v = vset.list[idx[i]]; nodes.emplace_back(v.pubkey, v.weight, v.adnl_addr);'),
 ('native-full-roster','mc-config','const auto& v = vset.list[i]; nodes.emplace_back(v.pubkey, v.weight, v.adnl_addr); nodes.back().auth_binding = v.auth_binding;','const auto& v = vset.list[i]; nodes.emplace_back(v.pubkey, v.weight, v.adnl_addr);'),
 ('descriptor-equality','descriptor-equality','if (auth_binding != other.auth_binding) return false;',''),
 ('state-root','native-committee','hash(root->get_hash().as_slice()) != anchor.state_','false'),
 ('network','native-committee','header.global_id != chain.network','false'),
 ('native-version','native-committee','cfg.get_global_version() < 16','false'),
 ('native-capability','native-committee','!(cfg.get_capabilities() & tos::capValidatorAuth)','false'),
 ('chain-domain','native-committee','registry.value().chain_domain() != chain.chain_domain','false'),
 ('validator-ceiling','native-committee','count.max_validators > 400','false'),
 ('elected-ceiling','native-committee','static_cast<unsigned>(elected.total) > count.max_validators','false'),
 ('election-time','native-committee','header.gen_utime >= elected.utime_until','false'),
 ('mandatory-config','native-committee','if (entry.is_null() || entry->size() != 0 || entry->size_refs() != 0) return Error{"config-mandatory"};',''),
 ('unsupported-selector','native-committee','if (selector.is_null() || !block::gen::t_CatchainConfig.validate_ref(selector)) return Error{"committee-selector"};',''),
 ('stake-substitution','native-committee','found->second.stake_id_ != stake','false'),
 ('network-key-reuse','native-committee','network_keys.contains(hash({reinterpret_cast<const char*>(key.public_key_.data()), key.public_key_.size()}))','false'),
 ('native-full-weight','native-committee','member.weight, hash(member.addr.as_slice())','1, hash(member.addr.as_slice())'),
 ('election-id-binding','native-committee','cfg.get_config_param(35, 34)','cfg.get_config_param(34)'),
 ('descriptor-zero-identity','mc-config','binding.identity.is_zero() ||',''),
 ('descriptor-zero-stake','mc-config','binding.stake_id.is_zero()','false'),
 ('native-full-roster','mc-config','ptr->list.back().auth_binding = auth_binding;',''),
 ('native-shard-roster','mc-config','nodes.back().auth_binding = entry.auth_binding;',''),
 ('export-binding','mc-config','l.back().auth_binding = node.auth_binding;',''),
]
def main(args):
 build=args.build.resolve();folder=build/'test/validator-auth-implementation';report=[]
 for label,module,before,after in (MUTATIONS[:4] if args.propagation_only else MUTATIONS):
  source=folder/('mutated-include/tos/tos-types.h' if module=='descriptor-equality' else f'mutated-{module}.cpp');original=source.read_text();target=f'test-p0-{module}-mutant'
  def run(text):
   source.write_text(text)
   result=subprocess.run(['cmake','--build',str(build),'--target',target,'-j2'],capture_output=True,text=True)
   if result.returncode:raise RuntimeError(result.stdout+result.stderr)
   return subprocess.run([str(folder/target)],capture_output=True,text=True)
  try:
   baseline=run(original);assert baseline.returncode==0,baseline.stderr
   result=run(replace_once(original,before,after))
   assert result.returncode==1 and result.stderr.strip()=='ASSERTION: '+label,(label,result.returncode,result.stderr)
   report.append(dict(guard=label,compiled=True,assertion_failed=True));print('KILLED:',label,flush=True)
  finally:
   restored=run(original);assert restored.returncode==0,restored.stderr
 args.out.write_text(json.dumps(dict(native_committee_mutations=report,restored_baselines=True),indent=2)+'\n')
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--build',type=Path,required=True);p.add_argument('--out',type=Path,required=True);p.add_argument('--propagation-only',action='store_true');main(p.parse_args())
