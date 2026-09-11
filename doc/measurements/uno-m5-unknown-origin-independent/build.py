from pathlib import Path
import subprocess,shlex,re
r=Path('/tmp/b-unknown-review');src=Path('/tmp/b-unknown-source');build=Path('/tmp/uno-merge-6ea2fbf80-tL5Uih')
cmds=subprocess.check_output(['ninja','-C',str(build),'-t','commands','test-m3-live'],text=True).splitlines()
def compile(match,out):
 args=shlex.split(next(c for c in cmds if ' -c ' in c and match in c))
 args=[re.sub(r'/home/tomi/tos/(?!build(?:/|$))',str(src)+'/',a) for a in args]
 args=[a.replace(str(src)+'/tl/generate','/home/tomi/tos/tl/generate') for a in args]
 for flag,val in [('-o',str(r/out)),('-MF',str(r/out)+'.d')]:args[args.index(flag)+1]=val
 subprocess.run(args,cwd=build,check=True,stdout=subprocess.DEVNULL,stderr=open(r/'build.log','a'))
 print('compiled',out,flush=True)
def link(name,obj):
 args=shlex.split(cmds[-1].split('&&')[1].strip())
 if args[-1]==':':args=args[:-2]
 args[args.index('-o')+1]=str(r/name)
 args=[str(r/'driver.o') if a=='CMakeFiles/test-m3-live.dir/test/test-m3-live.cpp.o' else a for a in args]
 idx=args.index('validator/impl/libtos_validator.a');args.insert(idx,str(r/obj))
 subprocess.run(args,cwd=build,check=True,stdout=subprocess.DEVNULL,stderr=open(r/'build.log','a'))
 print('linked',name,flush=True)
compile('test/test-m3-live.cpp','driver.o')
header=src/'crypto/block/workchain-unknown-origin.h';original=header.read_text()
for name in ['normal','no-count']:
 s=original
 if name=='no-count':
  start=s.index('  auto previous = unknown_origin_detail::count.load')
  end=s.index('  // Saturate',start)
  s=s[:start]+'  // Isolated mutation: retain classification/logging; omit only increment.\n'+s[end:]
 header.write_text(s)
 compile('validator/impl/collator.cpp',name+'.o');link(name,name+'.o')
header.write_text(original)
