#include "tos_v5r2_kdf.h"
#include <stdio.h>
#include <string.h>
#define CHECK(x) do { if (!(x)) { fprintf(stderr,"failed line %d\n",__LINE__); return 1; } } while (0)
int main(void) {
  {
    unsigned char master[] = {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31};
    unsigned char network[] = {32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51,52,53,54,55,56,57,58,59,60,61,62,63};
    unsigned char expected[] = {126,129,138,197,7,171,240,201,45,152,187,31,225,205,229,154,246,176,80,254,60,122,68,84,64,132,196,133,43,130,212,85};
    unsigned char out[32], zero[32] = {0};
    CHECK(tos_v5r2_derive_and_wipe(1,master,32,network,-239,0u,0u,NULL,out,sizeof out)==0);
    CHECK(memcmp(out,expected,sizeof out)==0);
    CHECK(memcmp(master,zero,32)==0);
  }
  {
    unsigned char master[] = {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31};
    unsigned char network[] = {32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51,52,53,54,55,56,57,58,59,60,61,62,63};
    unsigned char expected[] = {106,114,44,237,107,182,163,39,219,112,229,196,238,53,242,203,95,203,83,221,96,251,245,111,199,36,89,92,101,100,166,202,125,158,99,69,122,192,186,212,173,176,238,68,151,126,68,44};
    unsigned char out[48], zero[32] = {0};
    CHECK(tos_v5r2_derive_and_wipe(2,master,32,network,-239,0u,0u,NULL,out,sizeof out)==0);
    CHECK(memcmp(out,expected,sizeof out)==0);
    CHECK(memcmp(master,zero,32)==0);
  }
  {
    unsigned char master[] = {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31};
    unsigned char network[] = {32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51,52,53,54,55,56,57,58,59,60,61,62,63};
    unsigned char expected[] = {166,232,139,195,83,43,41,204,180,205,46,230,180,187,202,31,171,51,68,5,24,118,243,79,144,228,229,157,223,153,161,109};
    unsigned char out[32], zero[32] = {0};
    CHECK(tos_v5r2_derive_and_wipe(1,master,32,network,-239,1u,1u,NULL,out,sizeof out)==0);
    CHECK(memcmp(out,expected,sizeof out)==0);
    CHECK(memcmp(master,zero,32)==0);
  }
  {
    unsigned char master[] = {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31};
    unsigned char network[] = {32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51,52,53,54,55,56,57,58,59,60,61,62,63};
    unsigned char expected[] = {102,69,183,238,99,64,237,62,254,83,146,168,56,141,252,189,162,5,20,73,116,73,71,30,255,129,144,31,191,35,224,29,106,46,2,144,156,78,28,246,16,99,103,241,234,201,70,145};
    unsigned char out[48], zero[32] = {0};
    CHECK(tos_v5r2_derive_and_wipe(2,master,32,network,-239,1u,1u,NULL,out,sizeof out)==0);
    CHECK(memcmp(out,expected,sizeof out)==0);
    CHECK(memcmp(master,zero,32)==0);
  }
  {
    unsigned char master[] = {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31};
    unsigned char network[] = {32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51,52,53,54,55,56,57,58,59,60,61,62,63};
    unsigned char expected[] = {81,105,207,220,109,172,59,239,225,91,50,4,217,140,91,198,178,100,88,255,16,211,66,137,14,165,203,253,75,239,206,223,41,129,96,120,169,189,255,237,244,3,110,5,88,195,198,135};
    unsigned char tree[] = {165,165,165,165,165,165,165,165,165,165,165,165,165,165,165,165,165,165,165,165,165,165,165,165,165,165,165,165,165,165,165,165};
    unsigned char out[48], zero[32] = {0};
    CHECK(tos_v5r2_derive_and_wipe(3,master,32,network,-239,0u,0u,tree,out,sizeof out)==0);
    CHECK(memcmp(out,expected,sizeof out)==0);
    CHECK(memcmp(master,zero,32)==0);
  }
  {
    unsigned char master[] = {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31};
    unsigned char network[] = {32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51,52,53,54,55,56,57,58,59,60,61,62,63};
    unsigned char expected[] = {172,153,159,165,94,196,67,65,94,23,245,224,22,251,107,110,79,11,14,162,91,138,184,151,104,227,121,241,171,9,198,13,112,206,205,178,132,131,94,184,104,57,86,140,157,226,240,38};
    unsigned char tree[] = {166,166,166,166,166,166,166,166,166,166,166,166,166,166,166,166,166,166,166,166,166,166,166,166,166,166,166,166,166,166,166,166};
    unsigned char out[48], zero[32] = {0};
    CHECK(tos_v5r2_derive_and_wipe(3,master,32,network,-239,0u,0u,tree,out,sizeof out)==0);
    CHECK(memcmp(out,expected,sizeof out)==0);
    CHECK(memcmp(master,zero,32)==0);
  }
  {
    unsigned char master[] = {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31};
    unsigned char network[] = {32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51,52,53,54,55,56,57,58,59,60,61,62,63};
    unsigned char expected[] = {102,6,71,127,193,132,97,9,43,147,238,212,191,188,103,225,73,32,144,98,216,212,121,170,118,10,122,132,229,125,59,172,143,120,201,59,231,12,181,107,68,106,130,180,54,101,222,32};
    unsigned char tree[] = {165,165,165,165,165,165,165,165,165,165,165,165,165,165,165,165,165,165,165,165,165,165,165,165,165,165,165,165,165,165,165,165};
    unsigned char out[48], zero[32] = {0};
    CHECK(tos_v5r2_derive_and_wipe(3,master,32,network,-239,1u,1u,tree,out,sizeof out)==0);
    CHECK(memcmp(out,expected,sizeof out)==0);
    CHECK(memcmp(master,zero,32)==0);
  }
  { unsigned char master[32], out[48], network[32]={0}, zero[48]={0};
    memset(master, 9, sizeof master); memset(out,9,sizeof out);
    CHECK(tos_v5r2_derive_and_wipe(99,master,32,network,0,0,0,NULL,out,48)==-1);
    CHECK(memcmp(out,zero,48)==0); CHECK(memcmp(master,zero,32)==0);
  }
  return 0;
}
