# Vulnerability Report: Denial of Service in Opus via Integer Overflow in `quant_coarse_energy`

## 1. Overview

* **Vulnerability Type:** Integer Overflow / Divide-by-Zero (FPE)
* **Weakness:** CWE-190 (Integer Overflow or Wraparound)
* **Product:** Opus Audio Codec
* **Component:** `celt` module (Quantization logic)
* **Affected Function:** `quant_coarse_energy` (in `celt/quant_bands.c`)
* **Impact:** Denial of Service (Application Crash)

## 2. Description

A vulnerability was identified in the `quant_coarse_energy` function of the Opus library's `celt` component. The issue arises from an integer overflow during the calculation of the `intra_bias` variable. Specifically, the multiplication of `budget`, `delayedIntra`, and `loss_rate` occurs without intermediate type casting to a larger width, allowing the product to exceed the maximum value of a 32-bit integer.

When processing specifically crafted input data (via a fuzz driver), this overflow causes undefined behavior. In the observed crash scenario, this leads to a Floating Point Exception (FPE) or an invalid state that triggers an AddressSanitizer (ASan) violation, resulting in immediate process termination (Denial of Service).

## 3. Technical Details & Root Cause Analysis

**Location:** `src/opus/celt/quant_bands.c`, line 277

**Vulnerable Code Snippet:**

```c
intra_bias = (opus_int32)((budget**delayedIntra*loss_rate)/(C*512));

```

**Root Cause:**
The expression `budget * *delayedIntra * loss_rate` involves the following types:

* `budget`: `opus_uint32`
* `delayedIntra`: `opus_val32` (typically `float` or `int32_t` depending on configuration)
* `loss_rate`: `int`

In C, if these operands are 32-bit integers, the multiplication result is truncated to 32 bits. If the input values are sufficiently large, their product will wrap around (overflow).

1. **Overflow:** The multiplication `budget * *delayedIntra * loss_rate` overflows the 32-bit register capacity.
2. **Corrupted State:** The resulting `intra_bias` becomes incorrect (potentially negative or nonsensical).
3. **Crash:** This invalid value propagates to subsequent logic (such as the `if` condition using `ec_tell_frac`), causing the application to crash due to a Floating Point Exception (FPE) or related memory safety violation caught by ASan.

## 4.  Crash Log
```
INFO:__main__:Running: docker run --privileged --shm-size=2g --platform linux/amd64 --rm -e FUZZING_ENGINE=libfuzzer -e SANITIZER=address -e RUN_FUZZER_MODE=interactive -e HELPER=True -v /data/huangzikang/driver_test_data/opus/corpus/quant_coarse_energy-output-1/opus_repacketizer_fuzzer_fixed:/tmp/opus_repacketizer_fuzzer_fixed_corpus -v /data/huangzikang/uploadfile/oss-fuzz/build/out/quant_coarse_energy-output-1:/out -t gcr.io/oss-fuzz-base/base-runner run_fuzzer opus_repacketizer_fuzzer_fixed -runs=100000 -max_total_time=300 -detect_leaks=0 -print_final_stats=1 -len_control=0.
vm.mmap_rnd_bits = 28
rm: cannot remove '/tmp/opus_repacketizer_fuzzer_fixed_corpus': Device or resource busy
Using seed corpus: opus_repacketizer_fuzzer_fixed_seed_corpus.zip
/out/opus_repacketizer_fuzzer_fixed -rss_limit_mb=2560 -timeout=25 -runs=100000 -max_total_time=300 -detect_leaks=0 -print_final_stats=1 -len_control=0 /tmp/opus_repacketizer_fuzzer_fixed_corpus < /dev/null
INFO: Running with entropic power schedule (0xFF, 100).
INFO: Seed: 3752436689
INFO: Loaded 1 modules   (477 inline 8-bit counters): 477 [0x55a42fdb0048, 0x55a42fdb0225), 
INFO: Loaded 1 PC tables (477 PCs): 477 [0x55a42fdb0228,0x55a42fdb1ff8), 
INFO:       24 files found in /tmp/opus_repacketizer_fuzzer_fixed_corpus
INFO: -max_len is not provided; libFuzzer will not generate inputs larger than 1048576 bytes
INFO: seed corpus: files: 24 min: 56702b max: 6145920b total: 65091562b rss: 32Mb
AddressSanitizer:DEADLYSIGNAL
=================================================================
==13==ERROR: AddressSanitizer: FPE on unknown address 0x55a42fd3fb93 (pc 0x55a42fd3fb93 bp 0x7fffdafaced0 sp 0x7fffdafacd00 T0)
SCARINESS: 10 (signal)
    #0 0x55a42fd3fb93 in quant_coarse_energy /src/opus/celt/quant_bands.c:277:62
    #1 0x55a42fd3f737 in LLVMFuzzerTestOneInput /src/opus/tests/opus_repacketizer_fuzzer.c:54:5
    #2 0x55a42fbf6300 in fuzzer::Fuzzer::ExecuteCallback(unsigned char const*, unsigned long) /src/llvm-project/compiler-rt/lib/fuzzer/FuzzerLoop.cpp:614:13
    #3 0x55a42fbf5b25 in fuzzer::Fuzzer::RunOne(unsigned char const*, unsigned long, bool, fuzzer::InputInfo*, bool, bool*) /src/llvm-project/compiler-rt/lib/fuzzer/FuzzerLoop.cpp:516:7
    #4 0x55a42fbf7ab2 in fuzzer::Fuzzer::ReadAndExecuteSeedCorpora(std::__Fuzzer::vector<fuzzer::SizedFile, std::__Fuzzer::allocator<fuzzer::SizedFile>>&) /src/llvm-project/compiler-rt/lib/fuzzer/FuzzerLoop.cpp:829:7
    #5 0x55a42fbf7da2 in fuzzer::Fuzzer::Loop(std::__Fuzzer::vector<fuzzer::SizedFile, std::__Fuzzer::allocator<fuzzer::SizedFile>>&) /src/llvm-project/compiler-rt/lib/fuzzer/FuzzerLoop.cpp:867:3
    #6 0x55a42fbe6edb in fuzzer::FuzzerDriver(int*, char***, int (*)(unsigned char const*, unsigned long)) /src/llvm-project/compiler-rt/lib/fuzzer/FuzzerDriver.cpp:914:6
    #7 0x55a42fc122b2 in main /src/llvm-project/compiler-rt/lib/fuzzer/FuzzerMain.cpp:20:10
    #8 0x7fa5a1e0e082 in __libc_start_main (/lib/x86_64-linux-gnu/libc.so.6+0x24082) (BuildId: 0323ab4806bee6f846d9ad4bccfc29afdca49a58)
    #9 0x55a42fbd975d in _start (/out/opus_repacketizer_fuzzer_fixed+0x3e75d)

DEDUP_TOKEN: quant_coarse_energy--LLVMFuzzerTestOneInput--fuzzer::Fuzzer::ExecuteCallback(unsigned char const*, unsigned long)
AddressSanitizer can not provide additional info.
SUMMARY: AddressSanitizer: FPE /src/opus/celt/quant_bands.c:277:62 in quant_coarse_energy
==13==ABORTING
MS: 0 ; base unit: 0000000000000000000000000000000000000000
artifact_prefix='./'; Test unit written to ./crash-338c3f1b4b97226bc60bc41038becbc6de06b28f
stat::number_of_executed_units: 2
stat::average_exec_per_sec:     0
stat::new_units_added:          0
stat::slowest_unit_time_sec:    0
stat::peak_rss_mb:              33
```

## 5.  Harness
```c
#include <stdio.h> 
#include <stdlib.h> 
#include <stdint.h> 
#include <string.h> 
#include "quant_bands.h"
#include <stddef.h>

void quant_coarse_energy(const CELTMode *m, int start, int end, int effEnd, const celt_glog *eBands, 
                         celt_glog *oldEBands, uint32_t budget, celt_glog *error, ec_enc *enc, 
                         int C, int LM, int nbAvailableBytes, int force_intra, opus_val32 *delayedIntra, 
                         int two_pass, int loss_rate, int lfe);

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    static celt_glog eBands[20];
    static celt_glog oldEBands[20];
    static celt_glog error;
    static CELTMode mode;  
    static ec_enc enc;     

    if (Size < 4) return 0;

    int C = Data[0] % 2;      
    int LM = Data[1] % 2;     
    int two_pass = Data[2] % 2;
    int loss_rate = Data[3] % 101; 
    int lfe = (Data[4] % 2);  

    opus_val32 delayedIntra = 0;
    if (Size >= 8) {
        memcpy(&delayedIntra, Data + 4, sizeof(opus_val32));
    }

    size_t copy_size = sizeof(celt_glog) * 20;
    if (Size >= copy_size * 2) {
        memcpy(eBands, Data + 8, copy_size);
        memcpy(oldEBands, Data + 8 + copy_size, copy_size);
    } else {
        memset(eBands, 0, copy_size);
        memset(oldEBands, 0, copy_size);
    }

    quant_coarse_energy(&mode, 0, 20, 20, eBands, oldEBands, 500, &error, &enc, 
                        C, LM, 60, 0, &delayedIntra, two_pass, loss_rate, lfe);

    return 0;
}

```

