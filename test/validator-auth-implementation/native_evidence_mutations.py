"""Remove compiled native evidence admission guards and require named failures."""
import argparse,json,shutil,subprocess,tempfile
from pathlib import Path
from context_mutations import checked,mutate,ROOT
CPP=[
 ('evidence-tag','evidence-tag','s.fetch_ulong(32) == native_evidence_tag','(s.fetch_ulong(32), true)'),
 ('evidence-version','evidence-version','s.fetch_ulong(16) == 1, "evidence-version"','(s.fetch_ulong(16), true), "evidence-version"'),
 ('evidence-shape','evidence-trailing','s.size() == 49 &&',''),
 ('evidence-refcount','evidence-reference-count','need(s.size_refs() == 2 + unsigned(present), "evidence-shape");',''),
 ('evidence-header','evidence-unused-header','need(!h.is_special() && h.size() == 0 && h.size_refs() == 0, "evidence-unused-header");',''),
 ('evidence-byte-bound','evidence-authorization-bound','&& n <= limit',''),
 ('evidence-first-charge','evidence-first-charge','need(take(charge(bytes)), "evidence-charge");',''),
 ('evidence-second-charge','evidence-second-charge','need(take(charge(67108864 - remaining)), "evidence-charge");',''),
 ('evidence-leaf-shape','evidence-chunk-leaf','value->size() == 0 &&',''),
 ('evidence-chunk-size','evidence-chunk-declared-size','need(declared(cell, chunk_bytes) == it->second, "evidence-chunk-length");',''),
 ('evidence-manifest','evidence-conflicting-manifest','need(inserted || it->second == ref, "evidence-manifest-conflict");',''),
 ('evidence-dictionary','evidence-nonminimal-dictionary','need(supplied_root.is_null() == canonical_root.is_null() && (supplied_root.is_null() || supplied_root->get_hash() == canonical_root->get_hash()), "evidence-dictionary");',''),
 ('evidence-content','evidence-chunk-digest','take(reader.resolve(*v, kind));','(void)v;'),
 ('evidence-owner-anchor','evidence-anchor-file','if (actual.value() != expected) return Error{"evidence-owner-anchor"};',''),
 # Admission requires every declared chunk before anything reads one, and it
 # says so as a missing chunk. Calling that a malformed proof instead would
 # report storage the sender never supplied as input the sender got wrong.
 ('evidence-missing-chunk-provenance','evidence-missing-chunk','need(cells.size() == expected.size(), "evidence-missing-chunk");','need(cells.size() == expected.size(), "proof-boc");'),
]
RUST=[
 ('evidence-tag','evidence-tag','native(s.get_next_u32())? == NATIVE_EVIDENCE_TAG','{ native(s.get_next_u32())?; true }'),
 ('evidence-version','evidence-version','&& native(s.get_next_u16())? == 1, "evidence-version"','&& { native(s.get_next_u16())?; true }, "evidence-version"'),
 ('evidence-shape','evidence-trailing','&& root.bit_length() == 49',''),
 ('evidence-refcount','evidence-reference-count','need(s.remaining_references() == 2 + usize::from(present), "evidence-shape")?;',''),
 ('evidence-header','evidence-unused-header','need(header.cell_type() == CellType::Ordinary && header.bit_length() == 0 && header.references_count() == 0, "evidence-unused-header",)?;',''),
 ('evidence-byte-bound','evidence-authorization-bound','&& n <= limit',''),
 ('evidence-first-charge','evidence-empty','charge(declared(auth.clone(), NATIVE_AUTHORIZATIONS_LIMIT)?)?;','declared(auth.clone(), NATIVE_AUTHORIZATIONS_LIMIT)?;'),
 ('evidence-second-charge','evidence-empty','charge(67_108_864_usize.checked_sub(remaining).ok_or(Error("attachment-budget"))?)?;',''),
 ('evidence-leaf-shape','evidence-chunk-leaf','&& v.remaining_bits() == 0',''),
 ('evidence-chunk-size','evidence-chunk-declared-size','need(declared(cell.clone(), CHUNK_BYTES)? == *n, "evidence-chunk-length")?;',''),
 ('evidence-manifest','evidence-conflicting-manifest','need(old == r, "evidence-manifest-conflict")?;',''),
 ('evidence-dictionary','evidence-nonminimal-dictionary','need(supplied.data().map(Cell::repr_hash) == canonical.data().map(Cell::repr_hash), "evidence-dictionary",)?;',''),
 ('evidence-content','evidence-chunk-digest','reader.resolve(v, kind)?;',''),
 ('evidence-owner-anchor','evidence-anchor-file','need(&actual == expected, "evidence-owner-anchor")?;',''),
]
def main(a):
 if a.language=='cpp':
  folder=a.build.resolve()/'test/validator-auth-implementation'
  def run():
   checked(['cmake','--build',str(a.build.resolve()),'--target','test-p0-native-evidence-mutant','-j2'])
   with tempfile.TemporaryDirectory(prefix='p0-config-context-cases-') as tmp:
    return subprocess.run([str(folder/'test-p0-native-evidence-mutant'),str(a.inputs.resolve()),str(Path(tmp)/'cases')],capture_output=True,text=True)
  report=mutate(folder/'native-evidence-mutated.cpp',CPP,run)
 else:
  with tempfile.TemporaryDirectory(prefix='p0-native-evidence-mutations-') as tmp:
   root=Path(tmp)
   for part in ('validator-auth-native','validator-auth'):shutil.copytree(ROOT/'tosctl/src'/part,root/part)
   for part in (ROOT/'tosctl/src').iterdir():
    if part.is_dir() and part.name not in ('target','validator-auth-native','validator-auth'):(root/part.name).symlink_to(part,target_is_directory=True)
   crate=root/'validator-auth-native';manifest=crate/'Cargo.toml';manifest.write_text(manifest.read_text()+'\n[workspace]\n');shutil.copy2(ROOT/'tosctl/src/Cargo.lock',crate/'Cargo.lock')
   def run():
    checked(['cargo','build','--offline','--manifest-path',str(manifest),'--bin','native-evidence-conformance'])
    return subprocess.run([str(crate/'target/debug/native-evidence-conformance'),str(a.fixtures.resolve())],capture_output=True,text=True)
   report=mutate(crate/'src/native_evidence.rs',RUST,run)
 a.out.write_text(json.dumps(dict(language=a.language,native_evidence_mutations=report,restored_baselines=True),indent=2)+'\n')
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--language',choices=['cpp','rust'],required=True)
 for n in ('build','inputs','fixtures','out'):p.add_argument('--'+n,type=Path,required=n=='out')
 main(p.parse_args())
