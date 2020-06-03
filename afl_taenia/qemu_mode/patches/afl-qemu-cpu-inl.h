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
 code of QEMU 3.1.1. It leverages the built-in QEMU tracing functionality
 to implement AFL-style instrumentation and to take care of the remaining
 parts of the AFL fork server logic.

 The resulting QEMU binary is essentially a standalone instrumentation
 tool; for an example of how to leverage it for other purposes, you can
 have a look at afl-showmap.c.

 */

#include "afl-qemu-common.h"
#include "afl-qemu-taenia-comm.h"
#include "afl-qemu-taenia-conf.h"
#include "afl-qemu-taenia-log.h"
#include "afl-qemu-taenia-replay.h"

#ifdef TAENIA_DEBUG_PATH
pthread_mutex_t debug_path_log_mutex = PTHREAD_MUTEX_INITIALIZER;
#endif

/***************************
 * VARIOUS AUXILIARY STUFF *
 ***************************/

/* This snippet kicks in when the instruction pointer is positioned at
 _start and does the usual forkserver stuff, not very different from
 regular instrumentation injected via afl-as.h. */

#define AFL_QEMU_CPU_SNIPPET2         \
  do {                                \
                                      \
    if (itb->pc == afl_entry_point) { \
        if(taenia_replay_mode)        \
        {                             \
            replay_setup();           \
            replay_forkserver();      \
        }                             \
        else                          \
        {                             \
            afl_setup();              \
            afl_forkserver(cpu);      \
        }                             \
    }                                 \
                                      \
  } while (0)

/* We use one additional file descriptor to relay "needs translation"
 messages between the child and the fork server. */

#define TSL_FD (FORKSRV_FD - 1)

/* This is equivalent to afl-as.h: */

unsigned char *afl_area_ptr = NULL; /* Exported for afl_gen_trace */
unsigned int afl_forksrv_pid = 0;
abi_ulong afl_entry_point = NULL;

/* Exported variables populated by the code patched into elfload.c: */

abi_ulong afl_start_code, /* .text start pointer      */
afl_end_code;             /* .text end pointer        */

u8 afl_compcov_level;

__thread abi_ulong afl_prev_loc;

/* Set in the child process in forkserver mode: */

static int forkserver_installed = 0;
unsigned char afl_fork_child;

/* Instrumentation ratio: */

unsigned int afl_inst_rms = MAP_SIZE; /* Exported for afl_gen_trace */


volatile taenia_shm_t *pshm = NULL;
uint8_t calibration;

/* Function declarations. */

static void afl_setup(void);
static void afl_forkserver(CPUState *);

static void afl_wait_tsl(CPUState *, int);
static void afl_request_tsl(target_ulong, target_ulong, uint32_t, uint32_t, TranslationBlock *, int);

/* Data structures passed around by the translate handlers: */

struct afl_tb
{

    target_ulong pc;
    target_ulong cs_base;
    uint32_t flags;
    uint32_t cf_mask;

};

struct afl_tsl
{

    struct afl_tb tb;
    char is_chain;

};

struct afl_chain
{

    struct afl_tb last_tb;
    uint32_t cf_mask;
    int tb_exit;

};

/* Some forward decls: */

TranslationBlock *tb_htable_lookup(CPUState *, target_ulong, target_ulong, uint32_t, uint32_t);
static inline TranslationBlock *tb_find(CPUState *, TranslationBlock *, int, uint32_t);
static inline void tb_add_jump(TranslationBlock *tb, int n, TranslationBlock *tb_next);

/*************************
 * ACTUAL IMPLEMENTATION *
 *************************/


/* Set up SHM region and initialize other stuff. */

static void afl_setup(void)
{

    LOG_INFO("Afl_setup.");

    LOG_DEBUG("In debug mode.");
    LOG_DEBUG("afl_forkserver is at %p", &afl_forkserver);
    LOG_DEBUG("Afl entry point 0x%lx", (uint64_t) afl_entry_point);

#ifdef TAENIA_THREAD_TRACKING
    LOG_INFO("Tracking threads.");
#endif
#ifdef TAENIA_THREAD_LOGS
    LOG_INFO("Thread tracking macro logs enabled.");
#endif

    if (!load_configuration())
    {
        LOG_ERROR("Loading configuration failed.");
        exit(1);
    }

    /* All right, let's await orders... */

    if ((pshm = make_shm()) == NULL)
    {
        LOG_ERROR("Shared mem not initialized.");
        exit(1);
    }
    calibration = 1;
    char *id_str = getenv(SHM_ENV_VAR), *inst_r = getenv("AFL_INST_RATIO");

    int shm_id;

   if (inst_r)
    {

        unsigned int r;

        r = atoi(inst_r);

        if (r > 100)
            r = 100;
        if (!r)
            r = 1;

        afl_inst_rms = MAP_SIZE * r / 100;

    }

    if (id_str)
    {

        shm_id = atoi(id_str);
        afl_area_ptr = shmat(shm_id, NULL, 0);

        if (afl_area_ptr == (void *) -1)
            exit(1);

        /* With AFL_INST_RATIO set to a low value, we want to touch the bitmap
         so that the parent doesn't give up on us. */

        if (inst_r)
            afl_area_ptr[0] = 1;

        LOG_DEBUG("Afl_area_ptr is ready");
    }

    if (getenv("AFL_INST_LIBS"))
    {

        afl_start_code = 0;
        afl_end_code = (abi_ulong) -1;

    }

    /* pthread_atfork() seems somewhat broken in util/rcu.c, and I'm
     not entirely sure what is the cause. This disables that
     behaviour, and seems to work alright? */

    rcu_disable_atfork();
}

static void print_mappings(void)
{

    u8 buf[MAX_LINE];
    FILE *f = fopen("/proc/self/maps", "r");

    if (!f)
        return;

    while (fgets(buf, MAX_LINE, f))
        printf("%s", buf);

    fclose(f);

}

/* Fork server logic, invoked once we hit _start. */

static void afl_forkserver(CPUState *cpu)
{

    if (forkserver_installed == 1)
        return;
    forkserver_installed = 1;

    if (getenv("AFL_QEMU_DEBUG_MAPS"))
        print_mappings();

    int status, t_fd[2];
    int ret = 0;
    pid_t child_pid;
    static unsigned char tmp[4];
    uint32_t session_id = 0, iteration = 0;
    uint8_t process_alive = 0;

    LOG_INFO("Afl_forkserver");

    /* Tell the parent that we're alive. If the parent doesn't want
     to talk, assume that we're not running in forkserver mode. */

    if (write(FORKSRV_FD + 1, tmp, 4) != 4)
    {
        LOG_ERROR("The parent does not want to talk. Assume we are not running in forkserver mode.");
        return;
    }

    afl_forksrv_pid = getpid();

    /* All right, let's await orders... */

    while (1)
    {
        LOG_INFO("Restarting program: session %d.", session_id++);

        clean_shm(pshm);

        /* Whoops, parent dead? */

        wait_afl_command();

        child_pid = fork();
        if (child_pid < 0)
        {
            LOG_ERROR("Fork error: %s (%d).", strerror(errno), errno);
            exit(4);
        }

        if (!child_pid)
        {

            /* Child process. Close descriptors and run free. */

            afl_fork_child = 1;
            close(FORKSRV_FD);
            close(FORKSRV_FD + 1);
            close(t_fd[0]);
            LOG_INFO("Child continue.");

            return;

        }

        /* Parent. */
        LOG_DEBUG("Parent continue.");
        close(TSL_FD);

#ifdef TAENIA_DEBUG
        ret = wait_for_taenia_ready(pshm, 3000); // To have time to use gdb.
#else
        ret = wait_for_taenia_ready(pshm, libtaenia_init_timeout);
#endif

        if (ret < 0)
        {
            LOG_ERROR("Libtaenia is not alive, I quit.");
            process_alive = 0;
        }
        else
        {
            LOG_INFO("Libtaenia is ready.");
            process_alive = 1;
        }

        if (libtaenia_stateful_mode)
        {
            create_archive();
            if(track_process_mode)
            {
                proc_snapshot * tmp_snap = take_proc_snapshot();
                processes_snapshot = filter_proc_snapshot(tmp_snap, tracked_procs);
                destroy_proc_snapshot(tmp_snap);
            }
        }

        /* main loop, exit only on a crash */

        while (process_alive)
        {
            status = 0;
            iteration++;
            LOG_DEBUG("Main loop, iteration %d.", iteration);
            if (calibration && iteration > 40)
            {
                // The first 40 iterations are used for calibration. 
                calibration = 0;
                LOG_DEBUG("End of calibration.");
            }

            /* Synchro AFL master */
            if (write(FORKSRV_FD + 1, &child_pid, 4) != 4)
            {
                LOG_ERROR("Error writing to afl master.");
                exit(5);
            }
            // I am ready.
            pshm->taenia_qemu_ready_flag = 1;

            // Waiting for libtaenia answer.
            process_alive = wait_for_taenia_answer(child_pid, &status, pshm);
            pshm->libtaenia_answer_flag = 0;

            if (libtaenia_stateful_mode)
            {
                int ret = do_archive(process_alive, status);
                if (ret == 2)
                {
                    // Told to kill program
                    process_alive = kill_program(child_pid, pshm);
                }
                else if(ret == 3)
                {
                    process_alive = kill_program(child_pid, pshm);
                    LOG_INFO("Some tracked process were found dead.");
                    if(stop_on_process_crash)
                    {
                        status = SIGSTOP;
                    }
                    
                }
            }

            if (write(FORKSRV_FD + 1, &status, 4) != 4)
            {
                LOG_ERROR("Write error to AFL server.");
                exit(7);
            }

            if (process_alive)
            {
                wait_afl_command();
            }
        }
        afl_wait_tsl(cpu, t_fd[0]);
    }
}

/* This code is invoked whenever QEMU decides that it doesn't have a
 translation of a particular block and needs to compute it, or when it
 decides to chain two TBs together. When this happens, we tell the parent to
 mirror the operation, so that the next fork() has a cached copy. */

static void afl_request_tsl(target_ulong pc, target_ulong cb, uint32_t flags, uint32_t cf_mask, TranslationBlock *last_tb, int tb_exit)
{

    struct afl_tsl t;
    struct afl_chain c;

    if (!afl_fork_child)
        return;

    t.tb.pc = pc;
    t.tb.cs_base = cb;
    t.tb.flags = flags;
    t.tb.cf_mask = cf_mask;
    t.is_chain = (last_tb != NULL);

    if (write(TSL_FD, &t, sizeof(struct afl_tsl)) != sizeof(struct afl_tsl))
        return;

    if (t.is_chain)
    {

        c.last_tb.pc = last_tb->pc;
        c.last_tb.cs_base = last_tb->cs_base;
        c.last_tb.flags = last_tb->flags;
        c.cf_mask = cf_mask;
        c.tb_exit = tb_exit;

        if (write(TSL_FD, &c, sizeof(struct afl_chain)) != sizeof(struct afl_chain))
            return;

    }

}

/* Check if an address is valid in the current mapping */

static inline int is_valid_addr(target_ulong addr)
{

    int l, flags;
    target_ulong page;

    page = addr & TARGET_PAGE_MASK;
    l = (page + TARGET_PAGE_SIZE) - addr;

    flags = page_get_flags(page);
    if (!(flags & PAGE_VALID) || !(flags & PAGE_READ))
        return 0;

    return 1;

}

/* This is the other side of the same channel. Since timeouts are handled by
 afl-fuzz simply killing the child, we can just wait until the pipe breaks. */

static void afl_wait_tsl(CPUState *cpu, int fd)
{

    struct afl_tsl t;
    struct afl_chain c;
    TranslationBlock *tb, *last_tb;

    while (1)
    {

        u8 invalid_pc = 0;

        /* Broken pipe means it's time to return to the fork server routine. */

        if (read(fd, &t, sizeof(struct afl_tsl)) != sizeof(struct afl_tsl))
            break;

        /* Exit command for persistent */

        if (t.tb.pc == (target_ulong) (-1))
            return;

        tb = tb_htable_lookup(cpu, t.tb.pc, t.tb.cs_base, t.tb.flags, t.tb.cf_mask);

        if (!tb)
        {

            /* The child may request to transate a block of memory that is not
             mapped in the parent (e.g. jitted code or dlopened code).
             This causes a SIGSEV in gen_intermediate_code() and associated
             subroutines. We simply avoid caching of such blocks. */

            if (is_valid_addr(t.tb.pc))
            {

                mmap_lock();
                tb = tb_gen_code(cpu, t.tb.pc, t.tb.cs_base, t.tb.flags, t.tb.cf_mask);
                mmap_unlock();

            }
            else
            {

                invalid_pc = 1;

            }

        }

        if (t.is_chain)
        {

            if (read(fd, &c, sizeof(struct afl_chain)) != sizeof(struct afl_chain))
                break;

            if (!invalid_pc)
            {

                last_tb = tb_htable_lookup(cpu, c.last_tb.pc, c.last_tb.cs_base, c.last_tb.flags, c.cf_mask);
                if (last_tb)
                {
                    tb_add_jump(last_tb, c.tb_exit, tb);
                }

            }

        }

    }

    close(fd);

}

