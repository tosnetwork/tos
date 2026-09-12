exec(open('/tmp/b-shortfall-review/build.py').read().split("for mode in")[0])
s=(r/'probe.cpp').read_text()
s=s.replace('vm::AugmentedDictionary blocks(','''gen::ValueFlow::Record_value_flow flow;
 if (::tlb::unpack_cell(blk.value_flow,flow)) {CurrencyCollection f;CHECK(f.unpack(flow.fees_collected));std::cout<<"BLOCK_FEES_COLLECTED="<<f.tomis<<"\\n";}
 else {gen::ValueFlow::Record_value_flow_v2 flow2;CHECK(::tlb::unpack_cell(blk.value_flow,flow2));CurrencyCollection f;CHECK(f.unpack(flow2.fees_collected));std::cout<<"BLOCK_FEES_COLLECTED="<<f.tomis<<"\\n";}
 vm::AugmentedDictionary blocks(''')
s=s.replace('CHECK(native.fees);','CHECK(native.fees); vm::Dictionary transfers(native.transfers,32); CHECK(transfers.is_empty()); std::cout<<"NATIVE_EXPLICIT_TRANSFERS=0\\n";')
s=s.replace('for(unsigned variant=0;variant<4;++variant)','for(unsigned variant=0;variant<7;++variant)')
s=s.replace('uint64_t expected_g,expected_h;', '''if(variant==4)varied.base_compute=UINT64_MAX;
      if(variant==5)varied.slot_fee=UINT64_MAX;
      if(variant==6){varied.slot_fee=10996071;varied.base_compute=0;}
      if(variant>=4){auto v=WorkchainProofTestAccess::create(100);
        auto bad=prepare_workchain_failed_funded({inboxes,0},a0.data,co0.data,varied,policy.domain,
          {dom.global_id,dom.genesis_hash,dom.instance_id},*ingress.custody_address,ingress.executor_address,now.seq_no,v);
        CHECK(bad.is_error()); CHECK(bad.error().message()=="Failed no-issuance or arithmetic branch unsupported");
        std::cout<<"ARITHMETIC_REFUSAL variant="<<variant<<" stage="<<bad.error().message().str()<<"\\n";continue;}
      uint64_t expected_g,expected_h;''')
(r/'extra.cpp').write_text(s)
h.compile(r/'extra.cpp','test-workchain-block.cpp',r/'extra.o');h.link(r/'extra.o',r/'extra',pathlib.Path('/tmp/b-fee-admission/backend.o'))
p=h.run(r/'extra','FailedActualComponents','extra');assert p.returncode==0
