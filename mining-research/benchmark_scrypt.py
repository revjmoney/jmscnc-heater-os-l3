"""Offline correctness/host benchmark for a one-line scratch-zeroing patch.
Requires Windows MSVC cl.exe on PATH; never runs or changes a miner.
"""
import ctypes, difflib, hashlib, json, random, statistics, subprocess, time
from pathlib import Path

HERE=Path(__file__).resolve().parent
def prepare(source):
    original=Path(source).read_text(encoding='utf-8')
    needle='char scratchbuf[SCRATCHBUF_SIZE] = "";'
    if original.count(needle)!=1:raise ValueError('Unexpected upstream source')
    modified=original.replace(needle,'char scratchbuf[SCRATCHBUF_SIZE];')
    (HERE/'scrypt-original.c').write_text(original,encoding='utf-8')
    (HERE/'scrypt-scratch.patch').write_text(''.join(difflib.unified_diff(original.splitlines(True),modified.splitlines(True),'a/scrypt.c','b/scrypt.c')),encoding='utf-8')
    algorithm=original.split('void scrypt_regenhash')[0].replace('#include "config.h"','').replace('#include "miner.h"','')
    prefix='#include <intrin.h>\n#define htobe32(x) _byteswap_ulong(x)\n#define ROTR 0\n'
    wrapper='''
__declspec(dllexport) void hash80(const unsigned char *raw,unsigned char *out,int mode) {
    uint32_t input[20],result[8];
    char scratch[SCRATCHBUF_SIZE];
    memcpy(input,raw,80);
    if (mode == 0) memset(scratch,0,sizeof(scratch));
    if (mode == 1) memset(scratch,0xa5,sizeof(scratch));
    scrypt_1024_1_1_256_sp(input,scratch,result);
    for(int i=0;i<8;i++) {out[i*4]=(unsigned char)(result[i]>>24);out[i*4+1]=(unsigned char)(result[i]>>16);out[i*4+2]=(unsigned char)(result[i]>>8);out[i*4+3]=(unsigned char)result[i];}
}
'''
    (HERE/'scrypt-harness.c').write_text(prefix+algorithm+wrapper,encoding='utf-8')

def verify():
    lib=ctypes.CDLL(str(HERE/'scrypt-harness.dll'));fn=lib.hash80;fn.argtypes=[ctypes.c_void_p,ctypes.c_void_p,ctypes.c_int];fn.restype=None
    def hash80(raw,mode):
        output=ctypes.create_string_buffer(32);fn(ctypes.create_string_buffer(raw),output,mode);return output.raw
    rng=random.Random(4910);vectors=[bytes(80),bytes([255])*80,bytes(range(80))]+[rng.randbytes(80) for _ in range(64)]
    for raw in vectors:
        expected=hashlib.scrypt(raw,salt=raw,n=1024,r=1,p=1,dklen=32)
        for mode in (0,1,2):
            actual=hash80(raw,mode)
            if actual!=expected:raise AssertionError('Scrypt reference mismatch')
    raw=vectors[-1];samples={0:[],2:[]}
    for _ in range(7):
        for mode in (0,2):
            start=time.perf_counter()
            for _ in range(1000):hash80(raw,mode)
            samples[mode].append(time.perf_counter()-start)
    clean,uninitialized=statistics.median(samples[0]),statistics.median(samples[2])
    result=dict(reference='Python hashlib.scrypt / OpenSSL',vectors=len(vectors),comparisons=len(vectors)*3,result='All outputs match; zero, poisoned and uninitialized scratch',platform='Windows x64 MSVC /O2; controller ARM performance unmeasured',zeroed_seconds_per_1000=clean,uninitialized_seconds_per_1000=uninitialized,host_time_ratio=clean/uninitialized,asic_hashrate_gain='Not measured; this is share-validation CPU work, not ASIC mining',firmware_inclusion='Not included; stock CGMiner retained')
    (HERE/'benchmark-results.json').write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8');print(json.dumps(result,indent=2))

if __name__=='__main__':
    import argparse
    p=argparse.ArgumentParser();p.add_argument('--source');p.add_argument('--verify',action='store_true');args=p.parse_args()
    if args.source:prepare(args.source)
    if args.verify:verify()
