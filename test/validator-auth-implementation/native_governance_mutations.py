"""Compile native lookup error-provenance guards in current governance."""
import argparse,json,shutil,subprocess,tempfile
from pathlib import Path
from context_mutations import checked,mutate,ROOT
CPP=[
 ('native-missing-identity','governance-missing-current-identity','if (found.error().code == "unknown-entry") return std::optional<Identity>{};',''),
 ('native-resource-provenance','governance-native-resource','return found.error();','return std::optional<Identity>{};'),
]
RUST=[
 ('native-missing-identity','governance-missing-current-identity','Err(Error("unknown-entry")) => Ok(None),',''),
 ('native-resource-provenance','governance-native-resource','Err(e) => Err(e),','Err(e) => Ok(None),'),
]
def main(a):
 if a.language=='cpp':
  folder=a.build.resolve()/'test/validator-auth-implementation'
  def run():
   checked(['cmake','--build',str(a.build.resolve()),'--target','test-p0-native-governance-mutant','-j2'])
   with tempfile.TemporaryDirectory(prefix='p0-config-context-cases-') as tmp:
    return subprocess.run([str(folder/'test-p0-native-governance-mutant'),str(Path(tmp)/'cases')],capture_output=True,text=True)
  report=mutate(folder/'native-registry-mutated.cpp',CPP,run)
 else:
  with tempfile.TemporaryDirectory(prefix='p0-native-governance-mutations-') as tmp:
   root=Path(tmp)
   for part in ('validator-auth-native','validator-auth'):shutil.copytree(ROOT/'tosctl/src'/part,root/part)
   for part in (ROOT/'tosctl/src').iterdir():
    if part.is_dir() and part.name not in ('target','validator-auth-native','validator-auth'):(root/part.name).symlink_to(part,target_is_directory=True)
   crate=root/'validator-auth-native';manifest=crate/'Cargo.toml';manifest.write_text(manifest.read_text()+'\n[workspace]\n');shutil.copy2(ROOT/'tosctl/src/Cargo.lock',crate/'Cargo.lock')
   def run():
    checked(['cargo','build','--offline','--manifest-path',str(manifest),'--bin','governance-conformance'])
    return subprocess.run([str(crate/'target/debug/governance-conformance'),'--native',str(a.fixtures.resolve())],capture_output=True,text=True)
   report=mutate(crate/'src/native_registry.rs',RUST,run)
 a.out.write_text(json.dumps(dict(language=a.language,native_governance_mutations=report,restored_baselines=True),indent=2)+'\n')
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--language',choices=['cpp','rust'],required=True)
 for n in ('build','inputs','fixtures','out'):p.add_argument('--'+n,type=Path,required=n=='out')
 main(p.parse_args())
