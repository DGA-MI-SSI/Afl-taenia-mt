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

#include "afl-qemu-common.h"
#include "tcg.h"
#include "tcg-op.h"

static void afl_compcov_log_16(target_ulong cur_loc, target_ulong arg1, target_ulong arg2)
{

    register uintptr_t idx = cur_loc;

    if ((arg1 & 0xff00) == (arg2 & 0xff00))
    {
        INC_AFL_AREA(idx);
    }

}

static void afl_compcov_log_32(target_ulong cur_loc, target_ulong arg1, target_ulong arg2)
{

    register uintptr_t idx = cur_loc;

    if ((arg1 & 0xff000000) == (arg2 & 0xff000000))
    {

        INC_AFL_AREA(idx + 2);
        if ((arg1 & 0xff0000) == (arg2 & 0xff0000))
        {

            INC_AFL_AREA(idx + 1);
            if ((arg1 & 0xff00) == (arg2 & 0xff00))
            {
                INC_AFL_AREA(idx);
            }

        }

    }

}

static void afl_compcov_log_64(target_ulong cur_loc, target_ulong arg1, target_ulong arg2)
{

    register uintptr_t idx = cur_loc;

    if ((arg1 & 0xff00000000000000) == (arg2 & 0xff00000000000000))
    {

        INC_AFL_AREA(idx + 6);
        if ((arg1 & 0xff000000000000) == (arg2 & 0xff000000000000))
        {

            INC_AFL_AREA(idx + 5);
            if ((arg1 & 0xff0000000000) == (arg2 & 0xff0000000000))
            {

                INC_AFL_AREA(idx + 4);
                if ((arg1 & 0xff00000000) == (arg2 & 0xff00000000))
                {

                    INC_AFL_AREA(idx + 3);
                    if ((arg1 & 0xff000000) == (arg2 & 0xff000000))
                    {

                        INC_AFL_AREA(idx + 2);
                        if ((arg1 & 0xff0000) == (arg2 & 0xff0000))
                        {

                            INC_AFL_AREA(idx + 1);
                            if ((arg1 & 0xff00) == (arg2 & 0xff00))
                            {
                                INC_AFL_AREA(idx);
                            }

                        }

                    }

                }

            }

        }

    }

}

static void afl_gen_compcov(target_ulong cur_loc, TCGv_i64 arg1, TCGv_i64 arg2, TCGMemOp ot, int is_imm)
{

    void *func;

    if (!afl_compcov_level || cur_loc > afl_end_code || cur_loc < afl_start_code)
        return;

    if (!is_imm && afl_compcov_level < 2)
        return;

    switch (ot)
    {

        case MO_64:
            func = &afl_compcov_log_64;
            break;
        case MO_32:
            func = &afl_compcov_log_32;
            break;
        case MO_16:
            func = &afl_compcov_log_16;
            break;
        default:
            return;

    }

    cur_loc = (cur_loc >> 4) ^ (cur_loc << 8);
    cur_loc &= MAP_SIZE - 7;

    if (cur_loc >= afl_inst_rms)
        return;

    tcg_gen_afl_compcov_log_call(func, cur_loc, arg1, arg2);

}


