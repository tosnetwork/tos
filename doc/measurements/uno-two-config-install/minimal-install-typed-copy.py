import pathlib,subprocess,os,time,json,hashlib,base64,tempfile
r=pathlib.Path('/home/tomi/tos-m2'); b=pathlib.Path('/tmp/uno-publication-build'); d=pathlib.Path(tempfile.mkdtemp(prefix='uno-two-config-')); print(d,flush=True)
(d/'db/static').mkdir(parents=True); env=dict(os.environ,SOURCE_DATE_EPOCH=str(int(time.time())))
inc=f'{r}/crypto/fift/lib:{b}/crypto/smartcont:{r}/crypto/smartcont'
def run(label,args):
 p=subprocess.run(list(map(str,args)),cwd=d,env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=90)
 (d/(label+'.stdout.log')).write_bytes(p.stdout);(d/(label+'.stderr.log')).write_bytes(p.stderr)
 (d/(label+'.command.json')).write_text(json.dumps({'argv':list(map(str,args)),'exit_status':p.returncode,'cwd':str(d)},indent=2))
 print(label,p.returncode,flush=True)
 if p.returncode: raise SystemExit('Stopped: '+str(d/label))
 return p
master=(r/'test/counter-masterchain-genesis.fif').read_text(); start=master.index('{ <b x{a6}'); end=master.index('config.workchains!',start); master=master[:start]+master[end:]
start=master.index('variable native-ingress-dict');end=master.index('<b globalid@',start);master=master[:start]+master[end:]
master=master.replace('<b configdict ref, 0 32 u, 0 256 u, dictnew dict, b>','<b configdict ref, 0 32 u, "config-master.pk" load-generate-keypair drop B, dictnew dict, b>')
master=master.replace('empty_cell 0 0 1 config_addr 6 register_smc\ndup set_config_smc drop','empty_cell 1000000000000 0 1 config_addr 6 register_smc\ndup set_config_smc\nMasterchain swap "config-master.addr" save-address-verbose')
(d/'master.fif').write_text(master)
run('shard',[b/'crypto/create-state','-I',inc,r/'test/counter-shard-genesis.fif'])
run('master',[b/'crypto/create-state','-I',inc,d/'master.fif'])
run('proposal',[b/'crypto/counter-install-config',d/'zerostate.boc',d/'counter-state.boc',d/'install',2])
for name in ['zerostate','basestate0','counter-state']:
 data=(d/(name+'.boc')).read_bytes();(d/'db/static'/hashlib.sha256(data).hexdigest().upper()).write_bytes(data)
zero={'workchain':-1,'shard':-9223372036854775808,'seqno':0,'root_hash':base64.b64encode((d/'zerostate.rhash').read_bytes()).decode(),'file_hash':base64.b64encode((d/'zerostate.fhash').read_bytes()).decode()}
(d/'global.json').write_text(json.dumps({'@type':'config.global','dht':{'@type':'dht.config.global','k':6,'a':3,'static_nodes':{'@type':'dht.nodes','nodes':[]}},'validator':{'@type':'validator.config.global','zero_state':zero,'hardforks':[]}}))
for seq,param,suffix in [(0,12,'12.closed'),(1,84,'84')]:
 run('sign-'+str(param),[b/'crypto/fift','-I',inc,'-s',r/'crypto/smartcont/update-config.fif',d/'config-master',seq,param,d/('install.'+suffix+'.boc'),d/('message-'+str(param))])
run('install',['gdb','-q','-batch','-x','/tmp/uno-d40-postzero/typed-install.gdb','--args',pathlib.Path('/tmp/uno-d40-postzero/test-tos-collator-typed'),'-C',d/'global.json','-D',d/'db','--query-result',d/'install.result','-w',-1,'-m',d/'message-12.boc','-m',d/'message-84.boc'])
print((d/'install.result').read_text(),flush=True)
