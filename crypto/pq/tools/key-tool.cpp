// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later
// Unix key-file adapter. Production keystores may implement the SDK signer interface instead.
#include "mldsa_native.h"
#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <array>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <iostream>
#include <stdexcept>
#include <string>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>

template<std::size_t N> struct Secret {
  std::array<uint8_t,N> data{};
  Secret() = default; Secret(const Secret&) = delete; Secret& operator=(const Secret&) = delete;
  ~Secret(){OPENSSL_cleanse(data.data(),N);}
};
struct File { int fd; explicit File(int value):fd(value){if(fd<0)throw std::runtime_error("cannot open key file");}
  ~File(){close(fd);} File(const File&)=delete; };
std::vector<uint8_t> unhex(const char* text,std::size_t limit){
  std::string s(text);if(s.size()%2||s.size()/2>limit)throw std::runtime_error("bad public input length");
  auto n=[](char c){if(c>='0'&&c<='9')return c-'0';if(c>='a'&&c<='f')return c-'a'+10;throw std::runtime_error("bad hex");};
  std::vector<uint8_t> out;for(std::size_t i=0;i<s.size();i+=2)out.push_back(uint8_t(n(s[i])*16+n(s[i+1])));return out;
}
template<std::size_t N> void print_hex(const std::array<uint8_t,N>& bytes){
  static const char h[]="0123456789abcdef";for(auto c:bytes)std::cout<<h[c>>4]<<h[c&15];std::cout<<'\n';
}
void read_seed(const char* path, Secret<MLDSA_SEEDBYTES>& seed){
  File f(open(path,O_RDONLY|O_CLOEXEC|O_NOFOLLOW));struct stat st{};
  if(fstat(f.fd,&st)!=0||!S_ISREG(st.st_mode)||st.st_uid!=geteuid()||(st.st_mode&077)!=0||st.st_size!=MLDSA_SEEDBYTES)
    throw std::runtime_error("key must be an owner-only regular 32-byte seed file");
  std::size_t pos=0;while(pos<seed.data.size()){auto n=read(f.fd,seed.data.data()+pos,seed.data.size()-pos);
    if(n<0&&errno==EINTR)continue;if(n<=0)throw std::runtime_error("key read failed");pos+=std::size_t(n);}
}
int main(int argc,char** argv){
  try{
    if(argc<3)throw std::runtime_error("usage: tos-pq-key keygen|public KEYFILE; sign KEYFILE MESSAGE_HEX CONTEXT_HEX");
    std::string command(argv[1]);
    if((command=="sign"&&argc!=5)||(command!="sign"&&argc!=3))throw std::runtime_error("unexpected arguments");
    if(command!="keygen"&&command!="public"&&command!="sign")throw std::runtime_error("unknown command");
    Secret<MLDSA_SEEDBYTES> seed;Secret<MLDSA44_SECRETKEYBYTES> sk;
    std::array<uint8_t,MLDSA44_PUBLICKEYBYTES> pk{};
    if(command=="keygen"){
      if(RAND_priv_bytes(seed.data.data(),seed.data.size())!=1)throw std::runtime_error("secure random source failed");
    }else read_seed(argv[2],seed);
    if(tos_pq_tool_keypair_internal(pk.data(),sk.data.data(),seed.data.data())!=0)throw std::runtime_error("key derivation failed");
    if(command=="keygen"){
      File f(open(argv[2],O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC|O_NOFOLLOW,0600));
      std::size_t pos=0;while(pos<seed.data.size()){auto n=write(f.fd,seed.data.data()+pos,seed.data.size()-pos);
        if(n<0&&errno==EINTR)continue;if(n<=0)throw std::runtime_error("key write failed; remove incomplete file");pos+=std::size_t(n);}
      if(fsync(f.fd)!=0)throw std::runtime_error("key fsync failed");
      print_hex(pk);return 0;
    }
    if(command=="public"){print_hex(pk);return 0;}
    auto message=unhex(argv[3],8192),ctx=unhex(argv[4],255);
    std::vector<uint8_t> prefix{0,uint8_t(ctx.size())};prefix.insert(prefix.end(),ctx.begin(),ctx.end());
    Secret<MLDSA_RNDBYTES> random;
    if(RAND_priv_bytes(random.data.data(),random.data.size())!=1)throw std::runtime_error("secure random source failed");
    std::array<uint8_t,MLDSA44_BYTES> sig{};
    if(tos_pq_tool_signature_internal(sig.data(),message.data(),message.size(),prefix.data(),prefix.size(),
        random.data.data(),sk.data.data(),0)!=0 ||
       tos_pq_tool_verify(sig.data(),message.data(),message.size(),ctx.data(),ctx.size(),pk.data())!=0)
      throw std::runtime_error("sign/verify self-check failed");
    print_hex(sig);return 0;
  }catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 1;}
}
