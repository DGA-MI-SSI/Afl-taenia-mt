/*
 * hooks_with_calls.c
 */


#define __USE_GNU   // For RTLD_NEXT
#define _GNU_SOURCE

#include <dlfcn.h>
#include <errno.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/param.h>
#include <sys/types.h>
#include <unistd.h>

#include "hooks.h"
#include "taenia.h"
#include "taenia_config.h"
#include "taenia_log.h"
#include "thread_tracking.h"


#if defined(THREAD_TRACKING) || defined(EXECUTION_MODE_INDIRECT_CALL)
static int overwrite_call_to(void *overwritten_addr, void* called_addr);
#endif


/* ============================================================================
 *    User expected modifications
 */

static int (*original_pthread_create)(pthread_t *thread, const pthread_attr_t *attr, void *(*start_routine)(void *), void *arg) = NULL;

/*
 * The code called in place of the hooked function.
 * Else a good hook function is the root recv() function.
 * It is also possible to start it at the library load, however the target won't be ready at that point and an accurate sleep would be required.
 */
int pthread_create(pthread_t *thread, const pthread_attr_t *attr, void *(*start_routine)(void *), void *arg)
{
    // First time, we remember what was the original function to call it later on.
    if (original_pthread_create == NULL)
    {
        LOG_INFO("Pthread hook taken.");
        original_pthread_create = dlsym(RTLD_NEXT, "pthread_create");
        if (original_pthread_create == NULL)
        {
            LOG_ERROR("Error dlsym:%s\n", dlerror());
            exit(-1);
        }

        // Start the caller thread. Only once every lib loading.
        init_taenia();
    }
    LOG_DEBUG("pthread_create called.");
    return original_pthread_create(thread, attr, start_routine, arg);
}



#ifdef EXECUTION_MODE_INDIRECT_CALL

uint8_t indirect_mode_first_take = 0;
uint8_t *indirect_mode_target_input = 0;
pthread_mutex_t indirect_mutex_need_input = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t indirect_mutex_need_execution = PTHREAD_MUTEX_INITIALIZER;


/*
 * Replace the functions we target in indirect hook.
 */
static ssize_t fake_recv(int sockfd, void *buf, size_t len, int flags)
{
    UNUSED(sockfd);
    UNUSED(flags);
    LOG_DEBUG("fake_recv");
    pthread_mutex_lock(&indirect_mutex_need_input);
    LOG_DEBUG("indirect_mutex_need_input unlocked");

    size_t real_len = MIN(len, max_input_size);

    if (!memcpy(buf, indirect_mode_target_input, real_len))
    {
        LOG_DEBUG("memcpy error: %d", errno);
        return EFAULT;
    }

    LOG_DEBUG("Data given: %s", (char*)buf);

    // Call done, waiting for the next input.
    //indirect_mode_status = WAITING_INPUT;
    pthread_mutex_unlock(&indirect_mutex_need_execution);

    // The first call has a special status.
    if (!indirect_mode_first_take)
    {
        indirect_mode_first_take = 1;
    }

    return (ssize_t)real_len;
}


/*
 * Hook functions that will take our inputs.
 * In indirect mode, the targeted function is not directly called, it is a common function which is hooked to replace its output by ours.
 */
int add_indirect_call_hooks(char *targeted_lib)
{
    LOG_DEBUG("add_indirect_call_hooks");
    void* smart_broker_task_addr = get_function_address_by_name(targeted_lib, "smart_broker_task");

    // Set both mutex to locked.
    pthread_mutex_lock(&indirect_mutex_need_input);
    pthread_mutex_lock(&indirect_mutex_need_execution);

#ifdef __amd64__
#ifdef DEBUG
    uint32_t recv_offset = 725;
#else
    uint32_t recv_offset = 618;
#endif

#elif defined(__i386__)
#ifdef DEBUG
    uint32_t recv_offset = 678;
#else
    uint32_t recv_offset = 617;
#endif
#else
    uint32_t recv_offset = 0;
    LOG_ERROR("Unsupported arch.")
    exit(1);
#endif
    LOG_DEBUG("Write fake_recv (%p) at smart_broker_task (%p) + %d.", &fake_recv, smart_broker_task_addr, recv_offset);

    overwrite_call_to(smart_broker_task_addr + recv_offset, &fake_recv);

    return 0;
}

#endif         // EXECUTION_MODE_INDIRECT_CALL


#if defined(THREAD_TRACKING)


static int (*fifo_write)(uint8_t *arg);
static int (*fifo_read)(uint8_t *arg);

int fake_fifo_write_with_calls(uint8_t *arg)
{
    LOG_DEBUG("fake_fifo_write_with_calls");
    // Execute the function we want.
    track_input(arg);

    // Execute the function we replaced.
    return fifo_write(arg);
}

int fake_fifo_read_with_calls(uint8_t *arg)
{
    LOG_DEBUG("fake_fifo_read_with_calls");
    // Back at the beginning of the function: a loop has been done, we untrack the thread.
    untrack_thread_short();

    // Wait for a new input
    int ret = fifo_read(arg);   // May be blocking.

    // untrack it (if we find it).
    untrack_input(arg);

    // The order is inverse because arg is populated at the end of fifo_read.
    return ret;
}


/*
 * Hook the functions we need to track threads.
 * This is very specific to the functions used by the binary and should probably be rewritten for each test case.
 */
int add_call_hooks(char *targeted_lib)
{

    LOG_DEBUG("Add call-hooks");
    /*
     *
     * Replaced functions
     */
    fifo_write = get_function_address_by_name(targeted_lib, "fifo_write");
    fifo_read = get_function_address_by_name(targeted_lib, "fifo_read");


    // The function call offset depends on the architecture and the DEBUG flag (because of the call to LOG_DEBUG).
#ifdef __amd64__
#ifdef DEBUG
    uint32_t hwrite_call_offset = 41;
    uint32_t hread_call_offset  = 64;
#else
    uint32_t hwrite_call_offset = 19;
    uint32_t hread_call_offset  = 46;
#endif

#elif defined(__i386__)
#ifdef DEBUG
    uint32_t hwrite_call_offset = 48;
    uint32_t hread_call_offset  = 65;
#else
    uint32_t hwrite_call_offset = 22;
    uint32_t hread_call_offset  = 82;
#endif

#endif         // __amd64__, __i386__


    /*
     * First, we need to hook the write function in order to track interesting inputs.
     *
     * Fifo_write() is called in smart_broke().
     */
    void *smart_broke_addr = get_function_address_by_name(targeted_lib, "smart_broke");
    LOG_DEBUG("Write fake_fifo_write_with_calls (%p) at smart_broke (%p) + %d", &fake_fifo_read_with_calls, smart_broke_addr, hwrite_call_offset);
    overwrite_call_to(smart_broke_addr + hwrite_call_offset, (uint8_t*)(&fake_fifo_write_with_calls));

    /*
     * Then, we need to hook the read function in order to untrack interesting inputs, once they are read.
     * So we need to hook a place where the input is avaiblable.
     *
     * Fifo_read() is called in smart_parser_task()
     */
    void *smart_parser_task_addr = get_function_address_by_name(targeted_lib, "smart_parser_task");
    LOG_DEBUG("Write fake_fifo_read_with_calls (%p) at smart_parser_task (%p) + %d", &fake_fifo_read_with_calls, smart_parser_task_addr, hread_call_offset);
    overwrite_call_to(smart_parser_task_addr + hread_call_offset, (uint8_t*)(&fake_fifo_read_with_calls));

    /*
     * Finally, we need to hook the end of read (or the beginning if it loops) in order to identify when the treatment of an input
     * is terminated.
     *
     * However we have already hooked this function previously, so we did both (see code of fake_fifo_read) in one hook.
     */


    /* Here the parser_task is already in a read, that was not hooked. So we send a dumb message in order to get out of it.
     * It is not important that we "lose" one smart_parse execution.
     */

    uint8_t useless_first_input[STANDARD_INPUT_SIZE] = "DUMB";
    uint8_t *first_read_buf = malloc(max_input_size);
    memcpy(first_read_buf, useless_first_input, max_input_size);
    LOG_DEBUG("Provoke a dumb fifo_write.");
    fifo_write(first_read_buf);
    free(first_read_buf);

    return 1;
}

#endif         // THREAD_TRACKING


int add_hooks(char *targeted_lib)
{
    LOG_DEBUG("add_hooks");
#ifdef EXECUTION_MODE_INDIRECT_CALL
    add_indirect_call_hooks(targeted_lib);
#endif

#if defined(THREAD_TRACKING)
    add_call_hooks(targeted_lib);
#endif

#if !defined(THREAD_TRACKING) && !defined(EXECUTION_MODE_INDIRECT_CALL)
    (void)targeted_lib;
#endif

    return 0;
}

// ============================================================================


#if defined(THREAD_TRACKING) || defined(EXECUTION_MODE_INDIRECT_CALL)

/*
 * Overwrite a call at the given overwritten_addr that leads to the called_addr.
 */
static int overwrite_call_to(void *overwritten_addr, void* called_addr)
{
    LOG_DEBUG("overwrite_call_to");
#if !defined(__amd64__) && !defined(__i386__)
    LOG_ERROR("This architecture is not supported.");
    exit(1);
#endif

    uint8_t *caller_offset;
    unsigned long call_distance;
    ssize_t page_size;
    void* page_start;

    // Making the memory writable.
    if ((page_size = sysconf(_SC_PAGESIZE)) < 0)
    {
        LOG_ERROR("Sysconf failed.");
        exit(1);
    }

    // Allow write for the hooked function.
    page_start = (void*)(((size_t)overwritten_addr / (size_t)page_size) * (size_t)page_size);
    // mprotect must be given a page start.
    if (mprotect((void *)page_start, (size_t)page_size, PROT_READ | PROT_WRITE | PROT_EXEC) == -1)
    {
        LOG_ERROR("Mprotect failed for %p, error code: %d (%s).", overwritten_addr, errno, strerror(errno));
        exit(1);
    }
    LOG_DEBUG("page_start=%p, overwritten_addr=%p, next_page=%p", page_start, overwritten_addr, page_start + page_size);

    // Overwrite the given call with our targeted address function. +1 to overwrite the address and not the instruction.
    caller_offset = (uint8_t*)(overwritten_addr + 1);

    // Distance between the src and the dest of the call. -5 because it is implicitly added (size of the call).
    call_distance = ((unsigned long)called_addr - ((unsigned long)overwritten_addr) - 5);

    *caller_offset = (uint8_t)call_distance;
    *(caller_offset + 1) = (uint8_t)(call_distance >> 8);
    *(caller_offset + 2) = (uint8_t)(call_distance >> 16);
    *(caller_offset + 3) = (uint8_t)(call_distance >> 24);

    return 0;
}
#endif
