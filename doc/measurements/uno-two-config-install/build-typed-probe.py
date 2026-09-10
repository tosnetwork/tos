import subprocess,pathlib,shlex,json,shutil
b=pathlib.Path('/tmp/uno-publication-build');d=pathlib.Path('/tmp/uno-d40-postzero');a=json.loads((d/'typed-debug-compile.command.json').read_text());a[a.index('-o')+1]=str(d/'manager-disk.cpp.o');a[a.index('-MF')+1]=str(d/'manager-disk.cpp.o.d')
def run(label,args):
 (d/(label+'.command.json')).write_text(json.dumps(args));p=subprocess.run(args,cwd=b,stdout=(d/(label+'.stdout.log')).open('wb'),stderr=(d/(label+'.stderr.log')).open('wb'));print(label,p.returncode,flush=True);assert p.returncode==0
run('typed-copy-compile',a)
shutil.copyfile(b/'validator/libvalidator-disk.a',d/'libvalidator-disk.a')
run('typed-copy-archive',['ar','r',str(d/'libvalidator-disk.a'),str(d/'manager-disk.cpp.o')])
s=subprocess.check_output(['ninja','-C',str(b),'-t','commands','test-tos-collator']).decode().splitlines()[-1];a=shlex.split(s.split(' && ')[1]);a[a.index('-o')+1]=str(d/'test-tos-collator-typed');a=[str(d/'libvalidator-disk.a') if x=='validator/libvalidator-disk.a' else x for x in a];run('typed-copy-link',a)
