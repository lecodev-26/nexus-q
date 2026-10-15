#include <stdint.h>
#include <stdio.h>
#include <valgrind/memcheck.h>
static volatile int sink;
int main(void){ uint8_t sk[32]={1}; VALGRIND_MAKE_MEM_UNDEFINED(sk,32); if (sk[3] & 1) sink=1; static int tbl[256]; sink += tbl[sk[7]]; puts("neg done"); return 0; }
