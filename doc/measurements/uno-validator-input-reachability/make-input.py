import hashlib, json, re, struct, sys, types
from pathlib import Path
R=Path('/tmp/uno-a2-registry-jqOjoDbi')
P=Path(__file__).resolve().parent
base=R/'source/test/tostester/src/pytosiq_core'
# Load only the repository's BOC implementation, not unrelated client modules.
for name,path in [('pytosiq_core',base),('pytosiq_core.boc',base/'boc'),('pytosiq_core.crypto',base/'crypto')]:
    m=types.ModuleType(name);m.__path__=[str(path)];sys.modules[name]=m
from pytosiq_core.boc.cell import Cell
from bitarray.util import int2ba
raw=(R/'singleton-input/idle1.candidate').read_bytes()
assert len(raw)>120
def tlbytes(data,offset):
    n=data[offset];head=1
    if n==254:n=int.from_bytes(data[offset+1:offset+4],'little');head=4
    end=offset+head+n
    return data[offset+head:end],end+(-(head+n)%4)
def encode(data):
    h=bytes([len(data)]) if len(data)<254 else b'\xfe'+len(data).to_bytes(3,'little')
    return h+data+b'\0'* (-(len(h)+len(data))%4)
data,nextoff=tlbytes(raw,120)
collated,end=tlbytes(raw,nextoff);assert end==len(raw)
block=Cell.one_from_boc(data);info=block.refs[0]
assert int(info.bits[:32].to01(),2)==0x9bc7a987
assert len(info.refs)==2
match=re.search(r'= \(-1,8000000000000000,1\):([0-9A-F]+):([0-9A-F]+) saved', (R/'fixture/bootstrap.log').read_text())
assert match
def replace_ref(original,seq,root,file):
    bits=original.bits.copy()
    assert len(bits)==608
    bits[64:96]=int2ba(seq,length=32)
    bits[96:352]=int2ba(int.from_bytes(root,'big'),length=256)
    bits[352:608]=int2ba(int.from_bytes(file,'big'),length=256)
    return Cell(bits,[])
master=replace_ref(info.refs[0],1,bytes.fromhex(match[1]),bytes.fromhex(match[2]))
previous=replace_ref(info.refs[1],0,(R/'fixture/counter-state.rhash').read_bytes(),(R/'fixture/counter-state.fhash').read_bytes())
newinfo=Cell(info.bits.copy(),[master,previous])
newblock=Cell(block.bits.copy(),[newinfo,*block.refs[1:]])
newdata=newblock.to_boc()
result=raw[:56]+newblock.hash+hashlib.sha256(newdata).digest()+encode(newdata)+encode(collated)
(P/'candidate.bin').write_bytes(result)
(P/'construction.json').write_text(json.dumps({'template':'singleton-input/idle1.candidate','changes':['BlockInfo master reference','BlockInfo previous reference','archive root/file hashes'],'scope':'Adversarial input for prefix reachability only. No claim that transaction/state-update contents are valid under target configuration. No gate changed.','candidate_sha256':hashlib.sha256(result).hexdigest(),'master_root':match[1],'master_file':match[2]},indent=2))
print(len(result),'bytes')
