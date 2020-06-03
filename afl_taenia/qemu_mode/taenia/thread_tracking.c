/*
 * thread_tracking.c
 */

#define _GNU_SOURCE     // for syscall
#include <unistd.h>
#include <sys/syscall.h>    // for SYS_...

#include <dlfcn.h>
#include <stdlib.h>
#include <string.h>

#include "elf_hook.h"
#include "taenia_log.h"
#include "hooks.h"
#include "shm.h"
#include "taenia_config.h"
#include "thread_tracking.h"


/*
 * Simpler version, do not work to find a symbol in the targeted binary (as this function is executed from libtaenia).
 */
void* get_imported_function_address_by_name(char const *modulePath, char const *funcName)
{
    void *hlib = dlopen(modulePath, RTLD_NOW);
    void *funcPtr = dlsym(hlib, funcName);
    dlclose(hlib);
    return funcPtr;
}


/*
 * More general case.
 * Get the address of the given function.
 */
void* get_function_address_by_name(char const *modulePath, char const *funcName)
{
#if !defined(__amd64__) && !defined(__i386__)
        LOG_ERROR("This architecture is not supported.");
        exit(-1);
#endif

    void *handle = 0;
    void *base = 0;
    void *funcPtr = 0;


    LOG_DEBUG("Searching %s in %s.", funcName, modulePath);

    handle = dlopen(modulePath, RTLD_LAZY);
    if (!handle)
    {
        LOG_ERROR("Module %s not found.", modulePath);
        return 0;
    }

    funcPtr = get_function_address(modulePath, base, funcName);
    dlclose(handle);

    if (!funcPtr)
    {
        LOG_ERROR("Function %s not found.", funcName);

    }
    // Add the global offset used by qemu.
#ifdef __amd64__
    funcPtr += 0x4000000000;
#endif
#ifdef __i386__
    funcPtr += 0xffffa000;
#endif


    LOG_DEBUG("%s found at %p.", funcName, funcPtr);
    return funcPtr;
}


#ifdef THREAD_TRACKING

static long int gettid() {
    return syscall(SYS_gettid);
}

#ifdef THREAD_LOGS
#define MODE_READ 0
#define MODE_WRITE 1
static int encounter_thread(int thid, uint8_t mode);
static void print_encountered_threads();
#endif  // THREAD_LOGS

/* ----------------------------------------------------------------------------
 * Inputs and threads logging.
 * ------------------------------------------------------------------------- */
#ifdef DEBUG

static void log_tracked_inputs()
{
    for (uint32_t i = 0; i < MAX_INPUTS; i++)
    {
        if (tracked_inputs[i] != NULL)
        {
            LOG_DEBUG("Input %d: %s", i, tracked_inputs[i]);
        }
    }
}
static void log_tracked_threads()
{
    for (uint32_t i = 0; i < MAX_THREADS; i++)
    {
        if (pshm->tracked_thread_ids[i] != 0)
        {
            LOG_DEBUG("Thread %d: %ld", i, pshm->tracked_thread_ids[i]);
        }
    }
}

#endif // DEBUG


/* ----------------------------------------------------------------------------
 * Inputs tracking.
 * ------------------------------------------------------------------------- */
uint8_t **make_tracked_inputs()
{
    uint8_t **tracked_inputs = malloc(MAX_INPUTS * sizeof(void*));
    memset(tracked_inputs, 0, MAX_INPUTS * sizeof(void*));
    return tracked_inputs;
}


/*
 * Add the input to the list.
 * Inputs can be in double in the list.
 */
int track_input(uint8_t *input)
{
    LOG_DEBUG("Track input: %s", input);

    for (uint32_t i = 0; i < MAX_INPUTS; i++)
    {
        if (tracked_inputs[i] == NULL)
        {
            // Empty slot
            tracked_inputs[i] = malloc(max_input_size);
            memcpy(tracked_inputs[i], input, max_input_size);
            tracked_inputs_number++;
#ifdef DEBUG
            LOG_DEBUG("Tracked inputs number: %d", tracked_inputs_number);
            log_tracked_inputs();
#endif
#ifdef THREAD_LOGS
            encounter_thread(gettid(), MODE_WRITE);
#endif
            return 1;
        }
    }
    LOG_ERROR("Not enough space in the tracking input table. An input cannot be tracked.");
    return 0;
}

/*
 * If the input is tracked, remove it.
 */
int untrack_input(uint8_t *input)
{
    LOG_DEBUG("Untrack input: %s", input);
    uint8_t findit = 0;
    for (uint32_t i = 0; i < MAX_INPUTS; i++)
    {
        if (tracked_inputs[i] != NULL && memcmp(tracked_inputs[i], input, max_input_size) == 0)
        {
            findit = 1;
            memset(tracked_inputs[i], 0, max_input_size);
            free(tracked_inputs[i]);
            tracked_inputs[i] = NULL;
            break;
        }
    }

    long int thid = gettid();

    if (findit)
    {
#ifdef DEBUG
        LOG_DEBUG("Tracked inputs number: %d", tracked_inputs_number);
        log_tracked_inputs();
#endif
#ifdef THREAD_LOGS
        encounter_thread(thid, MODE_READ);
#endif
        tracked_inputs_number--;

        // If the thread received an input we tracked, he is interesting.
        track_thread(thid);
    }
    else
    {
        // Else, he is parsing data we have not provided, so we untrack him.
        untrack_thread(thid);
    }

    return findit;
}


/* ----------------------------------------------------------------------------
 * Threads tracking.
 * ------------------------------------------------------------------------- */

/*
 * If the thread is already tracked, do nothing.
 * Else, add it to the tracking table.
 * This no-arg function exists to simplify the hooks.
 */
int track_thread(long int thid)
{
    LOG_DEBUG("Track thread: %ld", thid);
    for (uint16_t i = 0; i < MAX_THREADS; i++)
    {
        if (pshm->tracked_thread_ids[i] == thid)
        {
            // Thread already tracked.
#ifdef DEBUG
            log_tracked_threads();
#endif
            return 1;
        }
    }
    for (uint16_t i = 0; i < MAX_THREADS; i++)
    {
        /*
         *  We use 0 to identify empty slots because it won't be used as the binary is launched in qemu, and so is not the main thread.
         * Only afl will ahve a thread with id 0..
         */
        if (pshm->tracked_thread_ids[i] == 0)
        {
            // Empty slot
            pshm->tracked_thread_ids[i] = thid;
            tracked_threads_number++;
#ifdef DEBUG
            LOG_DEBUG("Tracked threads number: %d", tracked_threads_number);
            log_tracked_threads();
#endif

            return 1;
        }
    }
    LOG_ERROR("Not enough space in the tracking thread table. A thread cannot be tracked.");
    return 0;
}


/*
 * If the thread is tracked, remove the thread.
 * This no-arg function exists to simplify the hooks.
 */
int untrack_thread_short()
{
    long int thid = gettid();
    return untrack_thread(thid);
}

int untrack_thread(long int thid)
{
    LOG_DEBUG("Untrack thread: %d", thid);
    for (uint16_t i = 0; i < MAX_THREADS; i++)
    {
        if (pshm->tracked_thread_ids[i] == thid)
        {
            pshm->tracked_thread_ids[i] = 0;
            tracked_threads_number--;
#ifdef DEBUG
            LOG_DEBUG("Tracked threads number: %d", tracked_threads_number);
            log_tracked_threads();
#endif
            return 1;
        }
    }
    return 0;
}


int clean_inputs() {
    tracked_inputs_number = 0;
    if (tracked_inputs)
    {
        for (uint32_t i = 0; i < MAX_INPUTS; i++)
        {
            if (tracked_inputs[i])
            {
                memset(tracked_inputs[i], 0, max_input_size);
                free(tracked_inputs[i]);
                tracked_inputs[i] = NULL;
            }
        }
    }
    return 1;
}

int clean_threads() {
    tracked_threads_number = 0;
    for (uint16_t i = 0; i < MAX_THREADS; i++)
    {
        pshm->tracked_thread_ids[i] = 0;
    }
    return 1;
}


/* ----------------------------------------------------------------------------
 * Thread macroscopic logging.
 * ------------------------------------------------------------------------- */
#ifdef THREAD_LOGS
uint32_t et_count = 1;
static int encounter_thread(int thid, uint8_t mode) {
    LOG_DEBUG("Encounter_thread.");
    for (uint16_t i = 0; i < MAX_TOTAL_THREADS; i++)
    {
        if (pshm->encountered_threads_id[i] == thid)
        {
            if (mode == MODE_READ)
            {
                pshm->encountered_threads_read_count[i]++;
            }
            else if (mode == MODE_WRITE)
            {
                pshm->encountered_threads_write_count[i]++;
            }
            if ((et_count++ % 200000) == 0)
                print_encountered_threads();
            return 1;
        }
    }
    for (uint16_t i = 0; i < MAX_TOTAL_THREADS; i++)
    {
        // New thread
        if (!pshm->encountered_threads_id[i])
        {
            pshm->encountered_threads_id[i] = thid;
            if (mode == MODE_READ)
            {
                pshm->encountered_threads_read_count[i]  = 1;
                pshm->encountered_threads_write_count[i] = 0;
                pshm->encountered_threads_block_count[i] = 0;
            }
            else if (mode == MODE_WRITE)
            {
                pshm->encountered_threads_read_count[i]  = 0;
                pshm->encountered_threads_write_count[i] = 1;
                pshm->encountered_threads_block_count[i] = 0;
            }
            if ((et_count++ % 200000) == 0)
                print_encountered_threads();
            return 1;
        }
    }

    LOG_ERROR("Not enough space in the encountered thread table (used for log).");
    return 0;
}

static void print_encountered_threads()
{
    char msg[LOG_SIZE] = "";
    raw_log("--------------------------------------------------------------------------------");
    for (uint16_t i = 0; i < MAX_TOTAL_THREADS; i++)
    {
        if (pshm->encountered_threads_id[i])
        {
            snprintf(msg, LOG_SIZE, "Thread %d: \n\t\twrites\t: %d \n\t\treads\t: %d \n\t\tblocks\t: %d", pshm->encountered_threads_id[i], pshm->encountered_threads_write_count[i],
                    pshm->encountered_threads_read_count[i], pshm->encountered_threads_block_count[i]);
            raw_log(msg);
        }
    }
}
#endif // THREAD_LOGS
#endif // THREAD_TRACKING

