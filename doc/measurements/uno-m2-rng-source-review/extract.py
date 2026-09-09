# Static review worksheet; not an acceptance gate.
import re,collections,json,pathlib
base=pathlib.Path(__file__).resolve().parent
rel={};imports={}
for l in (base/'relocations.txt').read_text().splitlines():
 f=l.split()
 if len(f)>3 and f[2]=='R_X86_64_RELATIVE':rel[int(f[0],16)]=int(f[3],16)
 elif len(f)>4 and f[2] in ('R_X86_64_GLOB_DAT','R_X86_64_JUMP_SLOT'):imports[int(f[0],16)]=f[4]
names={};edges=collections.defaultdict(set);sites=collections.defaultdict(list);lines=collections.defaultdict(list);cur=None
for l in (base/'disassembly.txt').read_text().splitlines():
 label=re.match(r'^([0-9a-f]+) <(.*)>:',l)
 if label:cur=int(label[1],16);names[cur]=label[2];continue
 if cur is None:continue
 lines[cur].append(l)
 d=re.search(r'\b(?:callq?|jmpq?|j[a-z]+|bl|b)\s+([0-9a-f]+)\s+<',l)
 if d:edges[cur].add(int(d[1],16))
 if re.search(r'\b(?:call|jmp)\s+\*|\b(?:blr|br)\s+',l):
  g=re.search(r'# ([0-9a-f]+)',l)
  if g and int(g[1],16) in rel:edges[cur].add(rel[int(g[1],16)])
  else:sites[cur].append({'address':l.split(':')[0].strip(),'instruction':l.strip(),'import':imports.get(int(g[1],16)) if g else None})
roots={}
for name in ('uno_crypto_verify_v2','uno_crypto_system_encrypt_v1','uno_crypto_system_verify_v1'):
 root=next(a for a,n in names.items() if n==name);seen={root};todo=[root]
 while todo:
  for a in edges[todo.pop()]:
   if a not in seen:seen.add(a);todo.append(a)
 roots[name]=seen
out=[]
for a in sorted(set.union(*roots.values())):
 if sites[a]:out.append({'function_address':hex(a),'function':names[a],'roots':[n for n,s in roots.items() if a in s],'sites':sites[a]})
(base/'functions.json').write_text(json.dumps(out,indent=2)+'\n')
for f in out:
 if 'uno_crypto_verify_v2' not in f['roots']:continue
 operands=collections.Counter(re.search(r'\b(call|jmp)\s+(.*)',s['instruction'])[2].split('#')[0].strip() for s in f['sites'] if not s['import'])
 print(f['function_address'],len(f['sites']),sum(bool(s['import']) for s in f['sites']), f['function'][:160],dict(operands))
(base/'function-lines.json').write_text(json.dumps({hex(a):ls for a,ls in lines.items()}))
