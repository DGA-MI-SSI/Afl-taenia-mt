/*
 american fuzzy lop++ - high-performance binary-only instrumentation
 -------------------------------------------------------------------

 Originally written by Andrew Griffiths <agriffiths@google.com> and
 Michal Zalewski <lcamtuf@google.com>

 TCG instrumentation and block chaining support by Andrea Biondo
 <andrea.biondo965@gmail.com>

 QEMU 3.1.1 port, TCG thread-safety, CompareCoverage and NeverZero
 counters by Andrea Fioraldi <andreafioraldi@gmail.com>

 Copyright 2015, 2016, 2017 Google Inc. All rights reserved.
 Copyright 2019 AFLplusplus Project. All rights reserved.

 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at:

 http://www.apache.org/licenses/LICENSE-2.0

 This code is a shim patched into the separately-distributed source
 code of QEMU 3.1.0. It leverages the built-in QEMU tracing functionality
 to implement AFL-style instrumentation and to take care of the remaining
 parts of the AFL fork server logic.

 The resulting QEMU binary is essentially a standalone instrumentation
 tool; for an example of how to leverage it for other purposes, you can
 have a look at afl-showmap.c.

 */
#ifndef AFL_EMU_COMMON_H_
#define AFL_EMU_COMMON_H_

#include <stdint.h>

#include "../../include/config.h"
#include "../../include/taenia_config.h"

#ifndef CPU_NB_REGS
#define AFL_REGS_NUM 1000
#else
#define AFL_REGS_NUM CPU_NB_REGS
#endif

/* NeverZero */

#if (defined(__x86_64__) || defined(__i386__)) && defined(AFL_QEMU_NOT_ZERO)
#define INC_AFL_AREA(loc)           \
  asm volatile(                     \
      "incb (%0, %1, 1)\n"          \
      "adcb $0, (%0, %1, 1)\n"      \
      : /* no out */                \
      : "r"(afl_area_ptr), "r"(loc) \
      : "memory", "eax")
#else
#define INC_AFL_AREA(loc) afl_area_ptr[loc]++
#endif

/* Declared in afl-qemu-cpu-inl.h */

extern unsigned char *afl_area_ptr;
extern unsigned int afl_inst_rms;
extern abi_ulong afl_start_code, afl_end_code;
extern u8 afl_compcov_level;
extern unsigned char afl_fork_child;

extern __thread abi_ulong afl_prev_loc;

typedef struct
{
    /*
     * Beware: we cannot use pointer or other arch-dependent types as this structure
     * is shared with libtaenia that may be of an other arch.
     * Moreover, we need to sync ints. for instance address and thread ids are long int, we need to make sure long int (as taenia sees them) are used on both sides.
     */
    volatile uint8_t libtaenia_ready_flag;
    volatile uint8_t libtaenia_answer_flag;
    volatile uint8_t taenia_qemu_ready_flag;

#ifdef TAENIA_AMD64
    volatile int64_t libtaenia_thread_id;
#elif defined(TAENIA_X86)
    volatile int32_t libtaenia_thread_id;
#endif

#ifdef TAENIA_THREAD_TRACKING
#ifdef TAENIA_AMD64
    volatile int64_t tracked_thread_ids[MAX_THREADS];
#elif defined(TAENIA_X86)
    volatile int32_t tracked_thread_ids[MAX_THREADS];
#endif

#ifdef TAENIA_THREAD_LOGS
    /*
     * This is a flatten version of the following struct:
     *      uint32_t id;
     *      uint32_t read_count;
     *      uint32_t write_count;
     *      uint32_t block_count;
     */
    volatile uint32_t encountered_threads_id[MAX_THREADS];
    volatile uint32_t encountered_threads_read_count[MAX_THREADS];
    volatile uint32_t encountered_threads_write_count[MAX_THREADS];
    volatile uint32_t encountered_threads_block_count[MAX_THREADS];

#endif  // TAENIA_THREAD_LOGS
#endif  // TAENIA_THREAD_TRACKING
    volatile uint32_t libtaenia_tracked_libs_number;
    volatile int8_t libtaenia_tracked_libs_names[MAX_TRACKED_LIBS][MAX_LIB_NAME_SIZE];

#ifdef TAENIA_AMD64
    volatile uint64_t libtaenia_tracked_libs_start_addresses[MAX_TRACKED_LIBS];
    volatile uint64_t libtaenia_tracked_libs_end_addresses[MAX_TRACKED_LIBS];
#elif defined(TAENIA_X86)
    volatile uint32_t libtaenia_tracked_libs_start_addresses[MAX_TRACKED_LIBS];
    volatile uint32_t libtaenia_tracked_libs_end_addresses[MAX_TRACKED_LIBS];
#endif
} taenia_shm_t;

extern volatile taenia_shm_t *pshm;
extern uint8_t calibration;
extern abi_ulong afl_entry_point;

void afl_debug_dump_saved_regs(void);

void tcg_gen_afl_call0(void *func);
void tcg_gen_afl_compcov_log_call(void *func, target_ulong cur_loc, TCGv_i64 arg1, TCGv_i64 arg2);

void tcg_gen_afl_maybe_log_call(target_ulong cur_loc);

#endif
