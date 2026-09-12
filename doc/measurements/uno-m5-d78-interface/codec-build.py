import sys,pathlib,re
sys.path.insert(0,'/tmp');import b_d75_helpers as h
h.root=pathlib.Path('/tmp/b-d78-new');h.repo=pathlib.Path('/home/tomi/tos-m2')
h.cmds=[re.sub(r'/home/tomi/tos/(?!build(?:/|\s))','/home/tomi/tos-m2/',c) if ' -c ' in c else c for c in h.cmds]
h.cmds[-1]=h.cmds[-1].replace('uno/crypto/cargo-target/release/libtos_uno_crypto_prototype.a','/tmp/uno-merge-6ea2fbf80-tL5Uih/uno/crypto/cargo-target/release/libtos_uno_crypto_prototype.a')
h.compile(h.repo/'crypto/block/block-auto.cpp','block-auto.cpp',h.root/'block-auto.o')
h.compile(h.repo/'crypto/test/test-workchain-withdrawal-codec.cpp','test-workchain-block.cpp',h.root/'test.o')
h.link(h.root/'test.o',h.root/'test',h.root/'block-auto.o')
p=h.run(h.root/'test','WithdrawalCodec','codec');assert p.returncode==0
