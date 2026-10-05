#define _POSIX_C_SOURCE 200809L
#include <openssl/evp.h>
#include <openssl/core_names.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <sys/utsname.h>

#define ITERATIONS 20
#define WARMUPS 3
#define OPENSSL_VERSION_ARENA "3.5.9"
#define MESSAGE "nexusq-pqc-arena-v1"

static double elapsed_ns(struct timespec a, struct timespec b) {
    return (double)(b.tv_sec-a.tv_sec)*1e9 + (double)(b.tv_nsec-a.tv_nsec);
}
static const char *env_or(const char *n,const char *f){const char *v=getenv(n);return v&&*v?v:f;}
static void env_meta(char *target,size_t tl,char *os,size_t ol,char *cpu,size_t cl){
    struct utsname u;
    const char *t=getenv("ARENA_TARGET"),*o=getenv("ARENA_OS"),*c=getenv("ARENA_CPU");
    if(t&&*t&&o&&*o&&c&&*c){snprintf(target,tl,"%s",t);snprintf(os,ol,"%s",o);snprintf(cpu,cl,"%s",c);return;}
    if(uname(&u)==0){snprintf(target,tl,"%s-%s",u.machine,u.sysname);snprintf(os,ol,"%s",u.sysname);snprintf(cpu,cl,"%s",u.machine);return;}
    snprintf(target,tl,"unknown");snprintf(os,ol,"unknown");snprintf(cpu,cl,"unknown");
}
static void emit(const char *alg,const char *param,const char *op,double latency,size_t pk,size_t sk,size_t ct,size_t sig,int hasct,int hassig){
    char target[128],os[64],cpu[128],ct_json[32],sig_json[32]; struct timespec ts;
    env_meta(target,sizeof(target),os,sizeof(os),cpu,sizeof(cpu)); clock_gettime(CLOCK_REALTIME,&ts);
    snprintf(ct_json,sizeof(ct_json),hasct ? "%zu" : "null",ct);
    snprintf(sig_json,sizeof(sig_json),hassig ? "%zu" : "null",sig);
    unsigned long long stamp=(unsigned long long)ts.tv_sec*1000000000ULL+(unsigned long long)ts.tv_nsec;
    printf("{\"schema_version\":1,\"run_id\":\"openssl-%s-%s-%s\",\"implementation\":{\"id\":\"openssl\",\"version\":\"%s\",\"commit\":null},\"algorithm\":{\"id\":\"%s\",\"parameter_set\":\"%s\"},\"operation\":\"%s\",\"environment\":{\"target\":\"%s\",\"os\":\"%s\",\"cpu\":\"%s\",\"cpu_features\":[],\"compiler\":\"cc\",\"compiler_version\":\"%s\",\"optimization\":\"%s\",\"harness_version\":\"arena-v1\"},\"measurement\":{\"iterations\":%d,\"warmups\":%d,\"measurement_timestamp_unix_ns\":%llu,\"latency_ns\":%.3f,\"throughput_ops_s\":%.6f,\"memory_bytes\":null,\"measurement_method\":\"clock_gettime(CLOCK_MONOTONIC) mean wall-clock latency\"},\"sizes\":{\"public_key_bytes\":%zu,\"secret_key_bytes\":%zu,\"ciphertext_bytes\":%s,\"signature_bytes\":%s}}\n",alg,param,op,OPENSSL_VERSION_ARENA,alg,param,op,target,os,cpu,__VERSION__,env_or("ARENA_OPT","release"),ITERATIONS,WARMUPS,stamp,latency,1e9/latency,pk,sk,ct_json,sig_json);
}
static int kem(void){
    EVP_PKEY *key=NULL; EVP_PKEY_CTX *ctx=NULL; unsigned char *ct=NULL,*ss=NULL; size_t ctl=0,ssl=0; struct timespec a,b;
    for(int w=0;w<WARMUPS;w++){ctx=EVP_PKEY_CTX_new_from_name(NULL,"ML-KEM-768",NULL);if(!ctx||!EVP_PKEY_keygen_init(ctx)||!EVP_PKEY_generate(ctx,&key))return 1;EVP_PKEY_CTX_free(ctx);ctx=NULL;EVP_PKEY_free(key);key=NULL;}
    clock_gettime(CLOCK_MONOTONIC,&a);for(int i=0;i<ITERATIONS;i++){ctx=EVP_PKEY_CTX_new_from_name(NULL,"ML-KEM-768",NULL);if(!ctx||!EVP_PKEY_keygen_init(ctx)||!EVP_PKEY_generate(ctx,&key))return 2;EVP_PKEY_CTX_free(ctx);ctx=NULL;EVP_PKEY_free(key);key=NULL;}clock_gettime(CLOCK_MONOTONIC,&b);
    emit("ml-kem","768","keygen",elapsed_ns(a,b)/ITERATIONS,1184,2400,1088,0,1,0);
    ctx=EVP_PKEY_CTX_new_from_name(NULL,"ML-KEM-768",NULL);if(!ctx||!EVP_PKEY_keygen_init(ctx)||!EVP_PKEY_generate(ctx,&key))return 3;EVP_PKEY_CTX_free(ctx);ctx=NULL;
    ctx=EVP_PKEY_CTX_new_from_pkey(NULL,key,NULL);if(!ctx||!EVP_PKEY_encapsulate_init(ctx,NULL)||!EVP_PKEY_encapsulate(ctx,NULL,&ctl,NULL,&ssl))return 4;ct=OPENSSL_malloc(ctl);ss=OPENSSL_malloc(ssl);if(!ct||!ss)return 5;EVP_PKEY_CTX_free(ctx);ctx=NULL;
    for(int w=0;w<WARMUPS;w++){ctx=EVP_PKEY_CTX_new_from_pkey(NULL,key,NULL);if(!ctx||!EVP_PKEY_encapsulate_init(ctx,NULL)||!EVP_PKEY_encapsulate(ctx,ct,&ctl,ss,&ssl))return 6;EVP_PKEY_CTX_free(ctx);ctx=NULL;}
    clock_gettime(CLOCK_MONOTONIC,&a);for(int i=0;i<ITERATIONS;i++){ctx=EVP_PKEY_CTX_new_from_pkey(NULL,key,NULL);if(!ctx||!EVP_PKEY_encapsulate_init(ctx,NULL)||!EVP_PKEY_encapsulate(ctx,ct,&ctl,ss,&ssl))return 7;EVP_PKEY_CTX_free(ctx);ctx=NULL;}clock_gettime(CLOCK_MONOTONIC,&b);emit("ml-kem","768","encaps",elapsed_ns(a,b)/ITERATIONS,1184,2400,1088,0,1,0);
    for(int w=0;w<WARMUPS;w++){ctx=EVP_PKEY_CTX_new_from_pkey(NULL,key,NULL);if(!ctx||!EVP_PKEY_decapsulate_init(ctx,NULL)||!EVP_PKEY_decapsulate(ctx,ss,&ssl,ct,ctl))return 8;EVP_PKEY_CTX_free(ctx);ctx=NULL;}
    clock_gettime(CLOCK_MONOTONIC,&a);for(int i=0;i<ITERATIONS;i++){ctx=EVP_PKEY_CTX_new_from_pkey(NULL,key,NULL);if(!ctx||!EVP_PKEY_decapsulate_init(ctx,NULL)||!EVP_PKEY_decapsulate(ctx,ss,&ssl,ct,ctl))return 9;EVP_PKEY_CTX_free(ctx);ctx=NULL;}clock_gettime(CLOCK_MONOTONIC,&b);emit("ml-kem","768","decaps",elapsed_ns(a,b)/ITERATIONS,1184,2400,1088,0,1,0);
    OPENSSL_free(ct);OPENSSL_free(ss);EVP_PKEY_free(key);return 0;
}
static int sign_scheme(const char *name,const char *param,const char *alg,size_t pk,size_t sk,size_t sigsz){
    EVP_PKEY *key=NULL; EVP_PKEY_CTX *kctx=NULL,*sctx=NULL,*vctx=NULL; EVP_SIGNATURE *sigalg=NULL; unsigned char *sig=NULL; size_t sl=0; const unsigned char msg[] = MESSAGE; struct timespec a,b;
    for(int w=0;w<WARMUPS;w++){kctx=EVP_PKEY_CTX_new_from_name(NULL,name,NULL);if(!kctx||!EVP_PKEY_keygen_init(kctx)||!EVP_PKEY_generate(kctx,&key))return 1;EVP_PKEY_CTX_free(kctx);kctx=NULL;EVP_PKEY_free(key);key=NULL;}
    clock_gettime(CLOCK_MONOTONIC,&a);for(int i=0;i<ITERATIONS;i++){kctx=EVP_PKEY_CTX_new_from_name(NULL,name,NULL);if(!kctx||!EVP_PKEY_keygen_init(kctx)||!EVP_PKEY_generate(kctx,&key))return 2;EVP_PKEY_CTX_free(kctx);kctx=NULL;EVP_PKEY_free(key);key=NULL;}clock_gettime(CLOCK_MONOTONIC,&b);emit(alg,param,"keygen",elapsed_ns(a,b)/ITERATIONS,pk,sk,0,sigsz,0,1);
    kctx=EVP_PKEY_CTX_new_from_name(NULL,name,NULL);if(!kctx||!EVP_PKEY_keygen_init(kctx)||!EVP_PKEY_generate(kctx,&key))return 3;EVP_PKEY_CTX_free(kctx);kctx=NULL;
    sigalg=EVP_SIGNATURE_fetch(NULL,name,NULL);if(!sigalg)return 4;
    sctx=EVP_PKEY_CTX_new_from_pkey(NULL,key,NULL);if(!sctx||!EVP_PKEY_sign_message_init(sctx,sigalg,NULL)||!EVP_PKEY_sign(sctx,NULL,&sl,msg,sizeof(msg)-1))return 5;sig=OPENSSL_malloc(sl);if(!sig)return 6;
    for(int w=0;w<WARMUPS;w++){size_t n=sl;if(!EVP_PKEY_sign(sctx,sig,&n,msg,sizeof(msg)-1))return 7;}
    clock_gettime(CLOCK_MONOTONIC,&a);for(int i=0;i<ITERATIONS;i++){size_t n=sl;if(!EVP_PKEY_sign(sctx,sig,&n,msg,sizeof(msg)-1))return 8;}clock_gettime(CLOCK_MONOTONIC,&b);emit(alg,param,"sign",elapsed_ns(a,b)/ITERATIONS,pk,sk,0,sl,0,1);
    vctx=EVP_PKEY_CTX_new_from_pkey(NULL,key,NULL);if(!vctx||!EVP_PKEY_verify_message_init(vctx,sigalg,NULL))return 9;
    for(int w=0;w<WARMUPS;w++){if(!EVP_PKEY_verify(vctx,sig,sl,msg,sizeof(msg)-1))return 10;}
    clock_gettime(CLOCK_MONOTONIC,&a);for(int i=0;i<ITERATIONS;i++){if(!EVP_PKEY_verify(vctx,sig,sl,msg,sizeof(msg)-1))return 11;}clock_gettime(CLOCK_MONOTONIC,&b);emit(alg,param,"verify",elapsed_ns(a,b)/ITERATIONS,pk,sk,0,sl,0,1);
    OPENSSL_free(sig);EVP_PKEY_CTX_free(kctx);EVP_PKEY_CTX_free(sctx);EVP_PKEY_CTX_free(vctx);EVP_SIGNATURE_free(sigalg);EVP_PKEY_free(key);return 0;
}
int main(void){if(kem()!=0)return 1;if(sign_scheme("ML-DSA-65","65","ml-dsa",1952,4032,3309)!=0)return 2;if(sign_scheme("SLH-DSA-SHAKE-128f","SHAKE-128f","slh-dsa",32,64,17088)!=0)return 3;return 0;}
