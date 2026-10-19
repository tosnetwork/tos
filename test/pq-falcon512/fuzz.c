/* PUBLIC TEST DATA; bounded decoder stress and sensitive positive controls. */
#include "falcon512-native.h"
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
static uint32_t state=0x12345678;
static uint32_t next(void) { state ^= state<<13; state ^= state>>17; state ^= state<<5; return state; }
static int read_file(const char *path, uint8_t *out, size_t length) {
  FILE *f=fopen(path,"rb");
  if (!f) return 0;
  int ok=fread(out,1,length,f)==length && fgetc(f)==EOF;
  fclose(f);return ok;
}
int main(int argc,char **argv) {
  uint8_t key[898],signature[667],message[8193],k[898],s[667];
  if(argc!=4 || !read_file(argv[1],key,897) || !read_file(argv[2],signature,666) || !read_file(argv[3],message,97)) return 2;
  if(tos_falcon512_padded_verify(message,97,signature,666,key,897)!=1) return 3;
  message[96]^=1;
  if(tos_falcon512_padded_verify(message,97,signature,666,key,897)!=0) return 4;
  message[96]^=1;
  for(int i=0;i<20000;i++) {
    size_t ml=next()%8194,kl=(i%4==0)?897:next()%899,sl=(i%4==0)?666:next()%668;
    memcpy(k,key,897);memcpy(s,signature,666);k[897]=s[666]=0;
    if(i%3==0)k[next()%898]^=(uint8_t)(next()|1);
    else s[next()%667]^=(uint8_t)(next()|1);
    for(size_t j=0;j<ml;j++)message[j]=(uint8_t)next();
    int status=tos_falcon512_padded_verify(message,ml,s,sl,k,kl);
    if(ml>8192 || kl!=897 || sl!=666) { if(status!=-1)return 5; }
    else if(status!=0 && status!=1) return 6;
  }
  puts("PASS: positive, negative and 20000 bounded fuzz inputs");return 0;
}
