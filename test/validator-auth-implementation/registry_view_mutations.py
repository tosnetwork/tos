"""Compile removals in each independent registry entry reader; require assertions."""
import argparse,json,shutil,subprocess,tempfile
from pathlib import Path
import re
from mutation_support import replace_once, TOKEN

# Guards the policy-activation branch repeats, so the bare anchor matches twice.
TWINNED_RUST_GUARDS = {'view-budget-charge', 'entry-tail', 'dictionary-shape'}


def matches(text, before):
 """How many times the harness's own matcher would find this anchor."""
 return len(list(re.finditer(r'\s*'.join(re.escape(t) for t in TOKEN.findall(before)), text)))
ROOT=Path(__file__).resolve().parents[2]
CPP=[
 ('view-entry-budget','if (budget_.entries == 0) return Error{"state-resource"};',''),
 ('view-budget-charge','--budget_.entries;',''),
 # Followed by its own next line, because a second byte charge was added later
 # in `open` as `result.budget_.bytes -= ...`, and the matcher is token-based:
 # the shorter form is a suffix of the longer one, so the anchor silently
 # stopped being unique and took the whole harness down with it.
 ('view-budget-charge','budget_.bytes -= raw.value().size();\n    return raw;','return raw;'),
 # The byte charge for the policy-activation read in `RegistryView::open` is
 # covered by `attestation-byte-charge` in the activation harness instead. That
 # branch runs only for a policy that took effect after genesis, and this
 # suite's fixture has none, so a case here could not reach it; the case that
 # kills it asserts the remainder after a successful open, which is the only
 # place the charge shows. It went uncovered for a while because the anchor
 # above was ambiguous and the harness died before reaching anything here.
 ('view-byte-budget','std::min(budget_.bytes, maximum)','maximum'),
 ('identity-binding','value.value().identity_ != id ||',''),
 ('identity-stake','value.value().stake_id_ == Hash{}','false'),
 # Extended by its own refusal, because `open`'s policy-activation branch
 # repeats the same shape check and the bare form matches both.
 ('entry-tail','leaf->size() != 0 || leaf->size_refs() != 1)\n      return Error{"dictionary-shape"};',
  'false)\n      return Error{"dictionary-shape"};'),
 ('key-hash','hash.value() != id','false'),
 ('key-descriptor','key.capacity_limit_ != 0','false'),
 ('key-admission','if (!admitted.ok()) return admitted.error();',''),
 ('policy-hash','id.value() != result.current_policy_','false'),
 # Likewise: the same wrapper check guards the registry root and, since the
 # policy-activation branch was added, the control dictionary as well.
 ('dictionary-shape','vm::CellSlice wrapper{vm::NoVm{}, root};\n    if (!wrapper.is_valid() || wrapper.is_special() || wrapper.size() != 1 ||',
  'vm::CellSlice wrapper{vm::NoVm{}, root};\n    if (!wrapper.is_valid() || wrapper.is_special() ||'),
 ('view-cache','auto cached = identities_.find(id);','auto cached = identities_.end();'),
 ('view-cache','auto cached = keys_.find(id);','auto cached = keys_.end();'),
 ('view-read-only','Result<std::uint64_t> RegistryView::latest_epoch(const Hash&, KeySlot) const { return Error{"read-only-view"}; }','Result<std::uint64_t> RegistryView::latest_epoch(const Hash&, KeySlot) const { return std::uint64_t(0); }'),
 ('view-read-only','Result<bool> RegistryView::ever_registered(const Hash&) const { return Error{"read-only-view"}; }','Result<bool> RegistryView::ever_registered(const Hash&) const { return false; }'),
]
RUST=[
 ('view-budget-charge','budget.entries = budget.entries.checked_sub(1).ok_or(Error("state-resource"))?;',''),
 ('view-budget-charge','budget.bytes = budget.bytes.checked_sub(raw.len()).ok_or(Error("state-resource"))?;',''),
 ('identity-binding','value.identity != *id ||',''),
 ('identity-stake','value.stake_id == [0; 32]','false'),
 ('entry-tail','leaf.remaining_bits() != 0 ||',''),
 ('key-hash','object_id("key", &key)? != *id','false'),
 ('key-descriptor','key.capacity_limit != 0','false'),
 ('key-admission','AdmittedKey::admit(&key.public_key)?;',''),
 ('policy-hash','object_id("policy", &p)? != current_policy','false'),
 ('dictionary-shape','if wrapper.remaining_bits() != 1 { return Err(Error("dictionary-shape")); }',''),
 ('view-cache','cache.identities.get(id)','None::<&Identity>'),
 ('view-cache','cache.keys.get(id)','None::<&Key>'),
 ('view-read-only','fn latest_epoch(&self, _identity: &Hash, _slot: KeySlot) -> Result<u64, Error> { Err(Error("read-only-view")) }','fn latest_epoch(&self, _identity: &Hash, _slot: KeySlot) -> Result<u64, Error> { Ok(0) }'),
 ('view-read-only','fn ever_registered(&self, _identity: &Hash) -> Result<bool, Error> { Err(Error("read-only-view")) }','fn ever_registered(&self, _identity: &Hash) -> Result<bool, Error> { Ok(false) }'),
]
def mutations(source,build,execute,cases,out):
 original=source.read_text();report=[]
 def run(text):
  source.write_text(text)
  compiled=subprocess.run(build,capture_output=True,text=True)
  if compiled.returncode:raise RuntimeError(compiled.stdout+compiled.stderr)
  return subprocess.run(execute,capture_output=True,text=True)
 baseline=run(original);assert baseline.returncode==0,baseline.stderr
 try:
  for label,before,after in cases:
   if source.name=='registry_view.rs' and label in TWINNED_RUST_GUARDS:
    # Four guards in this file exist twice: once in the ordinary entry read and
    # once in the policy-activation branch, which reads an entry of its own the
    # same way. The bare anchor therefore matches twice and the matcher refuses
    # to guess, so these are mutated inside the ordinary read. The activation
    # copies of the two budget debits are mutated against the activation corpus
    # instead -- see activation_mutations.py -- because this corpus cannot reach
    # that branch at all. The activation copies of the two shape checks are not
    # yet mutated anywhere; that gap is recorded rather than hidden.
    #
    # The counts are asserted rather than assumed: if one of these stops being
    # a twin, or the region moves, this fails loudly instead of silently
    # mutating whichever copy the slice happened to contain.
    start=original.index('fn read<T: Wire>(')
    stop=original.index('impl RegistryView',start)
    region=original[start:stop]
    if matches(original,before)!=2 or matches(region,before)!=1:
     raise ValueError(('twinned-guard-moved',label,matches(original,before),matches(region,before)))
    changed=original[:start]+replace_once(region,before,after)+original[stop:]
   else:
    changed=replace_once(original,before,after)
   result=run(changed)
   assert result.returncode==1 and result.stderr.startswith('ASSERTION: '+label) and 'panicked at' not in result.stderr,(label,result.stderr)
   report.append(dict(guard=label,compiled=True,assertion_failed=True));print('KILLED:',label,flush=True)
 finally:
  baseline=run(original);assert baseline.returncode==0,baseline.stderr
 out.write_text(json.dumps(dict(registry_view_mutations=report,restored_baselines=True),indent=2)+'\n')
def main(args):
 if args.language=='cpp':
  folder=args.build.resolve()/'test/validator-auth-implementation'
  mutations(folder/'mutated-registry-view.cpp',['cmake','--build',str(args.build.resolve()),'--target','test-p0-registry-view-mutant','-j2'],[str(folder/'test-p0-registry-view-mutant')],CPP,args.out)
 else:
  with tempfile.TemporaryDirectory(prefix='p0-rust-view-') as tmp:
   base=Path(tmp);src=base/'src';src.mkdir();crate=src/'validator-auth-native'
   shutil.copytree(ROOT/'tosctl/src/validator-auth-native',crate,ignore=shutil.ignore_patterns('target'))
   for path in (ROOT/'tosctl/src').iterdir():
    if path.is_dir() and path.name not in ('target','validator-auth-native'):(src/path.name).symlink_to(path,target_is_directory=True)
   manifest=crate/'Cargo.toml';manifest.write_text(manifest.read_text()+'\n[workspace]\n')
   shutil.copy2(ROOT/'tosctl/src/Cargo.lock',crate/'Cargo.lock')
   mutations(crate/'src/registry_view.rs',['cargo','build','--offline','--manifest-path',str(manifest),'--bin','registry-view-conformance'],[str(crate/'target/debug/registry-view-conformance'),str(args.fixtures.resolve())],RUST,args.out)
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--language',choices=['cpp','rust'],required=True);p.add_argument('--build',type=Path);p.add_argument('--fixtures',type=Path);p.add_argument('--out',type=Path,required=True);main(p.parse_args())
