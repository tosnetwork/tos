// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later
// Differential driver. Every input is public test data; no networking or signing.
#include "vm/boc.h"
#include "vm/vm.h"
#include "td/utils/logging.h"
#include <fstream>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <vector>
#include <string>

std::string unhex(const std::string& s) {
  if (s.size() % 2 || s.size() > 100000) throw std::runtime_error("invalid hex length");
  std::string out;
  auto n = [](char c) { if(c>='0' && c<='9')return c-'0'; if(c>='a'&&c<='f')return c-'a'+10;
    throw std::runtime_error("invalid hex"); };
  for (std::size_t i=0;i<s.size();i+=2)out.push_back(char(n(s[i])*16+n(s[i+1])));
  return out;
}
int main(int argc,char** argv) {
  try {
    if(argc!=2)throw std::runtime_error("usage: pq-parity scenarios.tsv");
    vm::init_vm().ensure(); SET_VERBOSITY_LEVEL(0);
    std::ifstream file(argv[1]); if(!file)throw std::runtime_error("missing scenarios");
    unsigned count=0;
    for(std::string line;std::getline(file,line);) {
      std::vector<std::string> f; std::istringstream row(line);
      for(std::string x;std::getline(row,x,'\t');)f.push_back(x);
      if(f.size()!=10)throw std::runtime_error("invalid scenario");
      int version=std::stoi(f[1]), repeats=std::stoi(f[4]); long long budget=std::stoll(f[2]);
      if(repeats<1||repeats>11||budget<0)throw std::runtime_error("invalid limits");
      td::Ref<vm::Stack> stack{true};
      for(int j=0;j<repeats;++j)for(int i=6;i<10;++i) {
        if(f[i]=="skip")continue;
        if(f[i]=="int"){stack.write().push_smallint(1);continue;}
        auto bytes=unhex(f[i]); auto c=vm::std_boc_deserialize(td::Slice(bytes));
        if(c.is_error())throw std::runtime_error("invalid cell BOC");
        stack.write().push_cell(c.move_as_ok());
      }
      vm::CellBuilder code;
      for(int j=0;j<repeats;++j){code.store_long(0xf93100,24);if(j+1<repeats)code.store_long(0x30,8);}
      vm::VmState st{vm::load_cell_slice_ref(code.finalize()),version,std::move(stack),vm::GasLimits{budget,budget}};
      st.set_chksig_always_succeed(f[3]=="1");
      int exit=~st.run(); auto gas=st.gas_consumed(); long long value=99;
      if(exit==0){if(st.get_stack().depth()!=1)throw std::runtime_error("unexpected stack");value=st.get_stack().pop_int_finite()->to_long();}
      const auto& cs=st.get_committed_state();
      std::cout<<f[0]<<'\t'<<exit<<'\t'<<gas<<'\t'<<value<<'\t'<<st.committed()<<'\t'
        <<(cs.c4.not_null()?cs.c4->get_hash().to_hex():"-")<<'\t'
        <<(cs.c5.not_null()?cs.c5->get_hash().to_hex():"-")<<'\n';
      ++count;
    }
    if(file.bad()||count<20)throw std::runtime_error("incomplete scenario set");
    return 0;
  }catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 1;}
}
