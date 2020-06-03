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

#include <syscall.h>

#include "tcg-op.h"

#include "afl-qemu-common.h"
#include "afl-qemu-taenia-log.h"

void afl_maybe_log(target_ulong cur_loc);
static void afl_gen_trace(target_ulong cur_loc);
static int is_in_tracked_code(target_ulong cur_loc);

#if defined(TAENIA_THREAD_TRACKING) && defined(TAENIA_THREAD_LOGS)
static inline int encounter_thread(int thid);
#endif

void afl_maybe_log(target_ulong cur_loc)
{

    if (!afl_area_ptr)
        return;

#ifdef TAENIA_AMD64
    int64_t thid = (int64_t)gettid();
#elif defined(TAENIA_X86)
    /*
     * This is the dangerous bit, we cast a unsigned long of a 64-bit qemu into a 32-bit.
     * We may lose some information. However, we are forced to, because the target runs in 32-bit.
     * So its thread id is 32-bit.
     */
    int32_t thid = (int32_t)gettid();
#endif
#if defined(TAENIA_MY_THREAD_ONLY) || defined(TAENIA_THREAD_TRACKING)

    if (pshm->libtaenia_thread_id)
    {
        // Libtaenia is initialized.
        if (pshm->libtaenia_thread_id == thid)
        {
            // With TAENIA_MY_THREAD_ONLY, we follow our own thread (libtaenia's thread).
            // Same for TAENIA_THREAD_TRACKING, because it is this thread that provides the original input.

            if (!calibration)
            {
                /*
                 * We follow the main thread only if we are not in the calibration phase.
                 * Calibration happens at the start of afl.
                 */
                return;
            }
        }
#ifdef TAENIA_THREAD_TRACKING
        else
        {
            // In an other thread.
            // We check that it is one of the threads we tracked.
            uint8_t findit = 0;
            for (uint32_t i = 0; i < MAX_THREADS; i++)
            {
                // Thread id 0 cannot be used as the target is launched in qemu.
                if (pshm->tracked_thread_ids[i] != 0 && pshm->tracked_thread_ids[i] == thid)
                {
                    findit = 1;
                    break;
                }
            }
            if (!findit)
            {
               return;
            }
        }

#ifdef TAENIA_THREAD_LOGS
        encounter_thread(thid);
#endif
#else   // TAENIA_THREAD_TRACKING
        else
        {
            // We do not track other threads, so we drop.
            return;
        }
#endif  // TAENIA_THREAD_TRACKING
    }
    else
    {
        // libtaenia not initialized.
        return;
    }
#endif  // TAENIA_MY_THREAD_ONLY

    register uintptr_t afl_idx = cur_loc ^ afl_prev_loc;

    LOG_PATH("Exe|%lx, %lx", cur_loc, (abi_ulong)afl_idx);

    INC_AFL_AREA(afl_idx);

    afl_prev_loc = cur_loc >> 1;

}

/* Generates TCG code for AFL's tracing instrumentation. */
static void afl_gen_trace(target_ulong cur_loc)
{

    /* Optimize for cur_loc > afl_end_code, which is the most likely case on
     Linux systems. */

    if (!is_in_tracked_code(cur_loc))
    {
        return;
    }

#ifdef TAENIA_DEBUG_PATH
    abi_ulong real_loc = cur_loc;
#endif


    /* Looks like QEMU always maps to fixed locations, so ASLR is not a
     concern. Phew. But instruction addresses may be aligned. Let's mangle
     the value to get something quasi-uniform. */

    cur_loc = (cur_loc >> 4) ^ (cur_loc << 8);
    cur_loc &= MAP_SIZE - 1;

    /* Implement probabilistic instrumentation by looking at scrambled block
     address. This keeps the instrumented locations stable across runs. */

    LOG_PATH("Gen|%lx, %lx", real_loc, cur_loc);

    if (cur_loc >= afl_inst_rms)
        return;

    tcg_gen_afl_maybe_log_call(cur_loc);

}

#if defined(TAENIA_THREAD_TRACKING) && defined(TAENIA_THREAD_LOGS)
/*
 * Log function for traking at a macro level the tracked threads.
 */
static inline int encounter_thread(int thid)
{
    LOG_DEBUG("encounter_thread");
    for (uint16_t i = 0; i < MAX_TOTAL_THREADS; i++)
    {
        if (pshm->encountered_threads_id[i] == thid)
        {
            pshm->encountered_threads_block_count[i]++;
            return 1;
        }
    }
    for (uint16_t i = 0; i < MAX_TOTAL_THREADS; i++)
    {
        // New thread
        if (!pshm->encountered_threads_id[i])
        {
            pshm->encountered_threads_id[i] = thid;
            pshm->encountered_threads_read_count[i] = 0;
            pshm->encountered_threads_write_count[i] = 0;
            pshm->encountered_threads_block_count[i] = 1;
            return 1;
        }
    }
    LOG_ERROR("Not enough space in the encountered thread table (used for log).");
    return 0;
}
#endif

static int is_in_tracked_code(target_ulong cur_loc)
{
    if (cur_loc < afl_end_code && cur_loc > afl_start_code)
    {
        return 1;
    }

    if(pshm != NULL)
    {
        uint32_t i;
        
        for(i = 0; i < pshm->libtaenia_tracked_libs_number; i++)
        {

            if (cur_loc < pshm->libtaenia_tracked_libs_end_addresses[i] && cur_loc > pshm->libtaenia_tracked_libs_start_addresses[i])
            {
                return 1;
            }
        }
    }
    return 0;
}
