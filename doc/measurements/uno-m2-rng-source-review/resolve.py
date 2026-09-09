# Static review worksheet; not an acceptance gate.
import pathlib
exec((pathlib.Path(__file__).resolve().parent/'extract.py').read_text().split('for f in out:')[0])
def canonical(r):
 r=r.lstrip('%')
 for full,aliases in {'rax':['eax','ax','al','ah'],'rbx':['ebx','bx','bl','bh'],'rcx':['ecx','cx','cl','ch'],'rdx':['edx','dx','dl','dh'],'rsi':['esi','si','sil'],'rdi':['edi','di','dil'],'rbp':['ebp','bp','bpl'],'rsp':['esp','sp','spl']}.items():
  if r==full or r in aliases:return full
 return re.sub(r'^(r\d+)[dwb]$',r'\1',r)
volatile={'rax','rcx','rdx','rsi','rdi','r8','r9','r10','r11'}
for f in out:
 raw=lines[int(f['function_address'],16)];ins=[]
 for l in raw:
  m=re.match(r'\s*([a-f0-9]+):\s+(?:[a-f0-9]{2} )+\s*([a-z][a-z0-9]*)\s*(.*)',l)
  if m:ins.append((int(m[1],16),m[2],m[3],l.strip()))
 indices={a:i for i,(a,*_) in enumerate(ins)};pred=collections.defaultdict(set)
 for i,(a,op,args,l) in enumerate(ins):
  if op not in ('jmp','ret','retq','ud2') and i+1<len(ins):pred[i+1].add(i)
  if op.startswith('j'):
   m=re.match(r'([a-f0-9]+) ',args)
   if m and int(m[1],16) in indices:pred[indices[int(m[1],16)]].add(i)
 def trace(i,r):
  todo=list(pred[i]);seen=set();defs={};unknown=[]
  if not todo:unknown.append('no predecessor')
  while todo:
   k=todo.pop()
   if k in seen:continue
   seen.add(k);a,op,args,l=ins[k];regs=[canonical(x) for x in re.findall(r'%([a-z0-9]+)',args.split('#')[0])]
   if op=='call' and r in volatile:unknown.append(hex(a)+': caller-saved clobber');continue
   # A deliberately conservative definition inventory. Unknown instructions
   # mentioning the tracked register stop review rather than being ignored.
   readonly=op.startswith(('j','cmp','test','nop')) or op in ('call','push','ret','data16','cs')
   argtext=args.split('#')[0].strip();dest=re.search(r',%([a-z0-9]+)$',argtext)
   write=not readonly and ((dest and canonical(dest[1])==r) or (len(regs)==1 and regs[0]==r and '(' not in argtext))
   if write:
    target=None;g=re.search(r'# ([a-f0-9]+)',args)
    if op=='lea' and g and '%rip' in args:target=int(g[1],16)
    if op=='mov' and g and '%rip' in args:
     slot=int(g[1],16);target=rel.get(slot)
     if slot in imports:target='import:'+imports[slot]
    defs[hex(a)]={'instruction':l,'target':target};continue
   if r in regs and not readonly and not dest and op not in ('push',):unknown.append(hex(a)+': unhandled register use');continue
   if op in ('mul','imul','div','idiv','cpuid','xgetbv') and r in ('rax','rdx','rbx','rcx'):unknown.append(hex(a)+': implicit clobber');continue
   if not pred[k]:unknown.append(hex(a)+': entry/landing predecessor unknown')
   todo.extend(pred[k])
  return list(defs.values()),sorted(set(unknown))
 for s in f['sites']:
  if s['import']:s['kind']='named-import';s['target']='import:'+s['import'];continue
  m=re.search(r'\b(?:call|jmp)\s+\*%([a-z0-9]+)\s*$',s['instruction'])
  if not m:s['kind']='memory-dispatch';continue
  ds,unknown=trace(indices[int(s['address'],16)],canonical(m[1]));s['definitions']=ds;s['unknown_predecessors']=unknown
  ts={d['target'] for d in ds}
  if not unknown and len(ts)==1 and None not in ts:
   t=next(iter(ts));s['kind']='constant-register';s['target']=names.get(t,hex(t)) if isinstance(t,int) else t
  else:s['kind']='unresolved-register'
(base/'resolved.json').write_text(json.dumps(out,indent=2)+'\n')
c=collections.Counter();tc=collections.Counter()
for f in out:
 if 'uno_crypto_verify_v2' not in f['roots']:continue
 for s in f['sites']:c[s['kind']]+=1;tc[s.get('target',s['kind'])]+=1
print(c)
for t,n in tc.most_common():print(n,t[:200])
