"""Check proposed allocations and compile native TL; not a native TL-B/BOC test."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile
import zlib
import contract_artifacts

ROOT=Path(__file__).resolve().parents[2]
DOC=ROOT/'doc/validator-auth-p0'

def check_capability_inventory(types):
    enum = re.search(r'enum GlobalCapabilities\s*\{(.*?)\}', types, re.DOTALL)
    if not enum:
        raise ValueError('cannot inspect capability inventory')
    entries = re.findall(r'(\w+)\s*=\s*(\d+)\s*[,\n]', enum.group(1) + '\n')
    if len(entries) != enum.group(1).count('='):
        raise ValueError('unsupported capability declaration requires review')
    owners = [name for name, value in entries if int(value) == 1024]
    declared = [(name, int(value)) for name, value in entries if name == 'capValidatorAuth']
    if declared and declared != [('capValidatorAuth', 1024)]:
        raise ValueError('native validator-auth allocation drift')
    if owners and owners != ['capValidatorAuth']:
        raise ValueError('validator-auth capability collision')
    return bool(declared)

def check_validator_inventory(block, rust):
    declarations = re.findall(r'(?m)^(\w+)#([0-9a-f]+)[^;]*?=\s*ValidatorDescr;', block)
    owners = [name for name, tag in declarations if tag == 'b3']
    if owners != ['validator_auth']:
        raise ValueError('native validator descriptor allocation drift')
    expected = ('validator_auth#b3 public_key:SigPubKey weight:uint64 adnl_addr:bits256 '
                'binding:^ValidatorAuthBinding = ValidatorDescr;')
    if expected not in ' '.join(block.split()):
        raise ValueError('native validator descriptor shape drift')
    if 'validator_auth_binding$_ identity:bits256 stake_id:bits256 = ValidatorAuthBinding;' not in ' '.join(block.split()):
        raise ValueError('native identity binding shape drift')
    tags = [tag for _, tag in declarations]
    if len(set(tags)) != len(tags) or any(len(tag) != 2 for tag in tags):
        raise ValueError('native descriptor tag collision')
    if not re.search(r'const VALIDATOR_DESC_AUTH_TAG: u8 = 0xb3;', rust):
        raise ValueError('Rust native descriptor allocation drift')
    if not re.search(r'const VALIDATOR_DESC_ADDR_SEQNO_TAG: u8 = 0x93;', rust):
        raise ValueError('historical Rust descriptor allocation drift')

def check_config_inventory(block, frozen):
    clean=lambda s: ' '.join(re.sub(r'//[^\n]*', '', s).split())
    source=clean(block)
    slots=re.findall(r'[^;]*?=\s*ConfigParam\s+46\s*;', source)
    if len(slots)!=1 or not slots[0].strip().endswith('_ ValidatorAuthConfig = ConfigParam 46;'):
        raise ValueError('native Config46 allocation drift')
    declarations=[part.strip()+';' for part in clean(frozen).split(';') if part.strip()]
    for declaration in declarations:
        if source.count(declaration)!=1:
            raise ValueError('native Config46 shape drift')
    constructors=r'(\w+)(#[a-f0-9]+|\$[01_]*)([^;]*?)=\s*(AuthBytes|AuthByteNode|AuthControl|ValidatorAuthConfig);'
    native=re.findall(constructors,source)
    expected=re.findall(constructors,clean(frozen))
    if sorted(native)!=sorted(expected):
        raise ValueError('native authentication constructor collision')
    for name,_,_,_ in expected:
        if len(re.findall(r'\b'+re.escape(name)+r'[#\$]',source))!=1:
            raise ValueError('native authentication constructor name collision')

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--tl-parser',type=Path,required=True)
    p.add_argument('--out',type=Path,required=True)
    args=p.parse_args();parser=args.tl_parser.resolve()
    contract_artifacts.main()
    profile=json.loads((DOC/'profile.json').read_text());schema=(DOC/'wire.tl').read_text()
    declarations=re.findall(r'^(validatorAuth\.\w+)#([0-9a-f]{8}) (.*?) = (.*?);$',schema,re.MULTILINE)
    if len(declarations)!=6:raise ValueError('six constructors required')
    seen=set()
    for name,tag,fields,result in declarations:
        if int(tag,16)!=zlib.crc32(f'{name} {fields} = {result}'.encode()):
            raise ValueError('constructor CRC drift: '+name)
        if tag in seen:raise ValueError('duplicate proposed ID')
        seen.add(tag)
    if seen!=set(profile['tl_constructors'].values()):raise ValueError('manifest/schema drift')
    block=(ROOT/'crypto/block/block.tlb').read_text()
    frozen=(DOC/'wire.tlb').read_text()
    check_config_inventory(block,frozen)
    types=(ROOT/'tos/tos-types.h').read_text()
    installed=check_capability_inventory(types)
    # Permit only the inventoried native allocation, never an unrelated owner.
    fixture='enum GlobalCapabilities { capValidatorAuth = 1024, };'
    assert check_capability_inventory(fixture)
    for bad in (fixture.replace('capValidatorAuth', 'capOther'),
                fixture.replace('1024', '2048'),
                fixture.replace('};', 'capOther = 1024, };')):
        try:
            check_capability_inventory(bad)
        except ValueError:
            pass
        else:
            raise ValueError('capability allocation negative control survived')
    checks=['native-capability-registered' if installed else 'native-capability-unoccupied', 'capability-collision-controls']
    for bad in (block.replace('_ ValidatorAuthConfig = ConfigParam 46;', '_ OtherConfig = ConfigParam 46;'),
                block.replace('auth_config_v1#76617131', 'auth_config_v1#76617132'),
                block+'\n_ uint32 = ConfigParam 46;',
                block+'\nother_auth_bytes#76616231 x:uint32 = AuthBytes;'):
        try:
            check_config_inventory(bad,frozen)
        except ValueError:
            pass
        else:
            raise ValueError('native Config46 collision control survived')
    checks.extend(['native-config46-registered','native-config46-collision-controls'])
    if 'validator_auth#' in block:
        rust=(ROOT/'tosctl/src/block/src/validators.rs').read_text()
        check_validator_inventory(block, rust)
        for bad in (block.replace('validator_auth#b3','validator_other#b3'),
                    block.replace('validator_auth#b3','validator_auth#93'),
                    block+'\nvalidator_other#b3 weight:uint64 = ValidatorDescr;'):
            try:
                check_validator_inventory(bad,rust)
            except ValueError:
                pass
            else:
                raise ValueError('native descriptor collision control survived')
        checks.extend(['native-descriptor-registered','native-descriptor-collision-controls'])
    with tempfile.TemporaryDirectory() as directory:
        d=Path(directory)
        for base in ('tos_api','lite_api'):
            combined=(ROOT/f'tl/generate/scheme/{base}.tl').read_text()+'\n---types---\n'+schema
            source=d/(base+'.tl');out=d/(base+'.tlo');source.write_text(combined)
            result=subprocess.run([str(parser),'-e',str(out),str(source)],capture_output=True,text=True,timeout=30)
            if result.returncode or not out.exists() or not out.stat().st_size:
                raise ValueError('native TL failed: '+base+'\n'+result.stderr)
            checks.append(base+'-combined-schema')
        source=d/'invalid.tl';source.write_text(combined+'\nvalidatorAuth.invalidV1 data:NeverDeclared = validatorAuth.Invalid;\n')
        bad=subprocess.run([str(parser),'-e',str(d/'bad.tlo'),str(source)],capture_output=True,text=True,timeout=30)
        if bad.returncode==0:raise ValueError('native parser negative control accepted an undefined type')
        checks.append('native-undefined-type-rejected')
    hashes={str(f.relative_to(ROOT)):hashlib.sha256(f.read_bytes()).hexdigest()
            for directory in (DOC,ROOT/'test/validator-auth-p0') for f in sorted(directory.iterdir()) if f.is_file()}
    args.out.parent.mkdir(parents=True,exist_ok=True)
    args.out.write_text(json.dumps(dict(success=True,checks=checks,source_sha256=hashes,
                                      scope='allocation and native TL only; no native TL-B/BOC or activation'),indent=2,sort_keys=True)+'\n')
    print('PASS:',', '.join(checks))

if __name__=='__main__':main()
