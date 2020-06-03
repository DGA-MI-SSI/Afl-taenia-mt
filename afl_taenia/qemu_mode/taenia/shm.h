/*
 * shm.h
 */

#ifndef AFL_TAENIA_QEMU_MODE_TAENIA_SHM_H_
#define AFL_TAENIA_QEMU_MODE_TAENIA_SHM_H_

#include <stdint.h>

#include "taenia_config.h"


#if defined(THREAD_TRACKING) && defined(THREAD_LOGS)
typedef struct
{
    int id;
    uint32_t read_count;
    uint32_t write_count;
    uint32_t block_count;
} encountered_thread_t;
#endif

typedef struct
{
    volatile uint8_t libtaenia_ready_flag;
    volatile uint8_t libtaenia_answer_flag;
    volatile uint8_t taenia_qemu_ready_flag;

#ifdef __amd64__
    volatile int64_t libtaenia_thread_id;
#elif defined(__i386__)
    volatile int32_t libtaenia_thread_id;
#endif

#ifdef THREAD_TRACKING

#ifdef __amd64__
    volatile int64_t tracked_thread_ids[MAX_THREADS];
#elif defined(__i386__)
    volatile int32_t tracked_thread_ids[MAX_THREADS];
#endif
#ifdef THREAD_LOGS
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
#endif  // THREAD_LOGS
#endif  // THREAD_TRACKING
    volatile uint32_t libtaenia_tracked_libs_number;
    volatile int8_t libtaenia_tracked_libs_names[MAX_TRACKED_LIBS][MAX_LIB_NAME_SIZE];
#ifdef __amd64__
    volatile uint64_t libtaenia_tracked_libs_start_addresses[MAX_TRACKED_LIBS];
    volatile uint64_t libtaenia_tracked_libs_end_addresses[MAX_TRACKED_LIBS];
#elif defined(__i386__)
    volatile uint32_t libtaenia_tracked_libs_start_addresses[MAX_TRACKED_LIBS];
    volatile uint32_t libtaenia_tracked_libs_end_addresses[MAX_TRACKED_LIBS];
#endif
} taenia_shm_t;

volatile taenia_shm_t* pshm;
volatile taenia_shm_t* get_shm();

#endif /* AFL_TAENIA_QEMU_MODE_TAENIA_SHM_H_ */
