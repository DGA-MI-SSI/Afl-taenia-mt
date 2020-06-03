/*
 * taenia.c
 *
 * Injected in the targeted process in order to execute the targeted function.
 * Takes its input from shared mem.
 */

#include <fcntl.h>
#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>

#include "hooks.h"
#include "lib_tracking.h"
#include "taenia.h"
#include "taenia_config.h"
#include "taenia_log.h"
#include "thread_tracking.h"
#include "shm.h"

/* ----------------------------------------------------------------------------
 * Library loading
 * May be useful for injecting code in a fully static binary.
 * ------------------------------------------------------------------------- */
static int execute_target(uint8_t* input);

__attribute__((constructor)) static void __init__(void)
{
    LOG_INFO("Libtaenia loaded.");
    LOG_DEBUG("In debug mode.");

#ifdef THREAD_TRACKING
    LOG_INFO("Tracking threads.");
#endif
#ifdef THREAD_LOGS
    LOG_INFO("Thread tracking macro logs enabled.");
#endif
#ifdef EXECUTION_MODE_INDIRECT_CALL
    LOG_INFO("Indirect call execution mode!");
#endif

    LOG_DEBUG("execute_target is at %p", &execute_target);
    return;
}

__attribute__((destructor)) static void __destroy__(void)
{
    LOG_INFO("Libtaenia unloaded.");
    return;
}


static long int gettid() {
    return syscall(SYS_gettid);
}

/* ----------------------------------------------------------------------------
 * Configuration management
 * ------------------------------------------------------------------------- */

size_t max_input_size = 512;

lib_list *tracked_libs = NULL;
static char targeted_lib[CONF_ELEM_SIZE] = {0};

#ifndef EXECUTION_MODE_INDIRECT_CALL
static int (*targeted_func)(uint8_t *msg) = NULL;
static char targeted_func_str[CONF_ELEM_SIZE] = {0};

/*
 * Read a pointer from a string.
 */
static void *read_pointer(char* value)
{
    void * pointer = NULL;
    if (strstr(value, "0x") == value)
    {
        // Base 16
        pointer = (void*) strtoul(value + 2, 0, 16);
    }
    else
    {
        pointer = (void*) strtoul(value, 0, 10);
    }
    return pointer;
}
#endif


/*
 * Get every configuration elements taenia need.
 */
static void load_configuration(char *input_filename)
{
    LOG_DEBUG("Loading configuration.");

    FILE *fp;
    char *line, *env_conf, *equal;
    char cmd[CONF_ELEM_SIZE] =
    { 0 }, value[CONF_ELEM_ENUM_SIZE] =
    { 0 };
    size_t len, linelen, equal_offset;
    __ssize_t read;

    env_conf = getenv("LIBTAENIA_CONF");
    if ((env_conf == NULL))
    {
        LOG_ERROR("No configuration given.");
        exit(1);
    }

    fp = fopen(env_conf, "r");
    len = 0;
    while ((read = getline(&line, &len, fp)) != -1)
    {
        if (line == strstr(line, "#"))
        {
            // Comment.
            continue;
        }
        if ((equal = strstr(line, "=")) != NULL)
        {
            linelen = strlen(line);
            equal_offset = (size_t) (equal - line);

            if (linelen >= CONF_ELEM_ENUM_SIZE)
            {
                LOG_ERROR("Buffer overflow prevented.");
            }

            memset(cmd, 0, CONF_ELEM_SIZE);
            if (memcpy(cmd, line, equal_offset) != cmd)
            {
                LOG_ERROR("Memcpy error for cmd.");
            }

            memset(value, 0, CONF_ELEM_ENUM_SIZE);
            if (memcpy(value, equal + 1, linelen - equal_offset - 2) != value)
            {    // -2 to not get the \n at the end of the line.
                LOG_ERROR("Memcpy error for value.");
            }

            if (!strcmp(cmd, "targeted_lib"))
            {
                memcpy(targeted_lib, value, CONF_ELEM_SIZE);
                LOG_DEBUG("targeted_lib: %s", targeted_lib);
            }
#ifndef EXECUTION_MODE_INDIRECT_CALL
            // Targeted function --------------------------
            else if (!strcmp(cmd, "targeted_func_addr"))
            {
                targeted_func = read_pointer(value);
                LOG_DEBUG("targeted_func: %p", targeted_func);
            }
            else if (!strcmp(cmd, "targeted_func"))
            {
                memcpy(targeted_func_str, value, CONF_ELEM_SIZE);
                LOG_DEBUG("targeted_func: %s", targeted_func_str);
            }
#endif  // EXECUTION_MODE_INDIRECT_CALL
            else if (!strcmp(cmd, "max_input_size"))
            {
                max_input_size = strtoul(value, 0, 10);
                if (max_input_size <= 0)
                {
                    LOG_ERROR("Wrong max_input_size value, default to 512.");
                    max_input_size = 512;
                }
                LOG_DEBUG("max_input_size: %ld", max_input_size);

            // Input filename -----------------------------
            }
            else if (!strcmp(cmd, "afl_output_filename"))
            {
                strcpy(input_filename, value);
                if ((input_filename == NULL))
                {
                    LOG_INFO("No afl_output_filename, using /dev/shm/afl-input.");
                    strcpy(input_filename, "/dev/shm/afl-input");
                }
                LOG_DEBUG("input_filename: %s.", input_filename);
            }
            // Tracked libs --------------------------------
            else if (!strcmp(cmd, "afl_tracked_libs"))
            {
                parse_multivalue_line(value, tracked_libs);
                LOG_DEBUG("tracked_libs:");

#ifdef DEBUG
                uint32_t i;
                for(i = 0; i < tracked_libs->number; i++)
                {
                    raw_log(tracked_libs->libs[i]);
                }
#endif
            }
        }
    }
#ifndef EXECUTION_MODE_INDIRECT_CALL
    if (strnlen(targeted_func_str, CONF_ELEM_SIZE) > 0)
    {
        targeted_func = get_function_address_by_name(targeted_lib, targeted_func_str);
    }
    if (!targeted_func)
    {    // Mandatory
        LOG_ERROR("Cannot read targeted_func.");
        exit(0);

        LOG_DEBUG("targeted_func: %p", targeted_func);
    }
#endif // EXECUTION_MODE_INDIRECT_CALL
    if (input_filename == NULL)
    {    // Mandatory
        LOG_ERROR("Cannot read input_filename.");
        exit(0);
    }
}



/* ----------------------------------------------------------------------------
 * Execution
 * ------------------------------------------------------------------------- */
#ifdef EXECUTION_MODE_INDIRECT_CALL
/*
 * Indirect mode: prepare a buffer for when the function is legitimately called.
 * The legitimate call will take this buffer.
 */
static int execute_target(uint8_t* input)
{

    LOG_DEBUG("Indirect execution.");

    // We store the input.
    if(!memcpy(indirect_mode_target_input, input, max_input_size))
    {
        LOG_DEBUG("Memcpy error: %d", errno);

    return 0;
    }
    pthread_mutex_unlock(&indirect_mutex_need_input);


    // We wait for the target to take the very first input.
    if (!indirect_mode_first_take)
    {
        while (!indirect_mode_first_take)
        {
            // Waiting for someone to take the input we have provided.
            LOG_DEBUG("Awaiting first connection.");
            USLEEP_DEBUG;
            usleep(SLEEPTIME_STANDARD);
        }
    }
    // We want this function to end when the target has finished receiving an input and starts waiting for the next one.


    // We wait for a new take of the input, meaning the target has terminated receiving the previous one.
    pthread_mutex_lock(&indirect_mutex_need_execution);
    LOG_DEBUG("indirect_mutex_need_execution unlocked");

    return 0;
}

#else   // EXECUTION_MODE_INDIRECT_CALL
/*
 * We directly and simply execute the targeted function with the given input.
 */
static int execute_target(uint8_t* input)
{
    LOG_DEBUG("Executing function at %p.", targeted_func);
    targeted_func(input);

    return 0;
}

#endif  // EXECUTION_MODE_INDIRECT_CALL



/* ----------------------------------------------------------------------------
 * Main task
 * ------------------------------------------------------------------------- */
pthread_t caller_id = 0;
int taenia_started = 0;


/*
 * Libtaenia main task.
 * Collect inputs from afl and provide them to the fuzzed function.
 */
static void *libtaenia_task()
{
    LOG_INFO("libtaenia_task started.");

    uint8_t *input;
    __ssize_t input_size = 0;
    int finput;
    char *input_filename;

#ifdef DEBUG
    struct timeval tv_ori, tv_now;
    long int time_sec, time_usec;
    gettimeofday(&tv_ori, NULL);
    LOG_DEBUG("libtaenia_task is at %p", &libtaenia_task);
#endif  // DEBUG

    pshm = get_shm();
    if (pshm == NULL)
    {
        LOG_ERROR("Shared mem not created.");
        exit(1);
    }

    // --- Initialization ---
    pshm->libtaenia_tracked_libs_number = 0;
    tracked_libs = create_lib_list();

    input_filename = malloc(256 * sizeof(char));
    memset(input_filename, 0, 256);
    load_configuration(input_filename);

    input = malloc(max_input_size);
    memset(input, 0, max_input_size);


#ifdef EXECUTION_MODE_INDIRECT_CALL
    if(!(indirect_mode_target_input = calloc(1, max_input_size)))
    {
        LOG_ERROR("calloc error: %d", errno);
        exit(1);
    }
#endif

    unsigned int i;
    for(i = 0; i < tracked_libs->number; i++)
    {
        add_lib_to_tracked_libs(pshm, tracked_libs->libs[i]);
    }

    log_loaded_libs(tracked_libs);


#ifdef THREAD_TRACKING
    if (pshm->tracked_thread_ids == NULL)
    {
        LOG_ERROR("Tracked thread ids list not created.");
        exit(1);
    }

    if (tracked_inputs)
    {
        LOG_INFO("Cleaning inputs.");
        clean_inputs();
        free(tracked_inputs);
    }

    tracked_inputs = make_tracked_inputs();
    if (tracked_inputs == NULL)
    {
        LOG_ERROR("Input_list not initialized.");
        exit(1);
    }

    clean_threads();
    track_thread(gettid());    // Track myself
#endif

    add_hooks(targeted_lib);


#ifdef DEBUG
    gettimeofday(&tv_now, NULL);
    time_sec = tv_now.tv_sec - tv_ori.tv_sec;
    time_usec = tv_now.tv_usec - tv_ori.tv_usec;
    LOG_DEBUG("I am ready, time: %lu.%06lus", time_sec, time_usec);
#endif

    // I am ready.
    pshm->libtaenia_thread_id = gettid();
    pshm->libtaenia_ready_flag = 1;
    pshm->libtaenia_answer_flag = 0;


    // --- Execution ---
    while (1)
    {
#ifdef DEBUG
        gettimeofday(&tv_ori, NULL);
#endif
        while (!pshm->taenia_qemu_ready_flag)
        {
            pshm->libtaenia_ready_flag = 1; // I am ready !
            LOG_DEBUG("Wait wake-up, qemu: %d, taenia: %d, answer: %d", pshm->taenia_qemu_ready_flag, pshm->libtaenia_ready_flag, pshm->libtaenia_answer_flag);
            USLEEP_DEBUG;
            usleep(SLEEPTIME_STANDARD);
        }
        pshm->libtaenia_answer_flag = 0;

        memset(input, 0, max_input_size);
        finput = open(input_filename, O_RDONLY);
        if (finput < 0)
        {
            LOG_ERROR("Error %d while opening input file %s. UID: %d", finput, input_filename, getuid());
            pshm->libtaenia_ready_flag = 0;
            exit(-1);
        }
        input_size = read(finput, input, max_input_size);
        if (input_size == 0)
        {
            LOG_ERROR("No bytes read, continue.");
            pshm->libtaenia_ready_flag = 0;
            if (close(finput))
            {
                LOG_ERROR("Close failed.");
                exit(-3);
            }
            continue;
        }
        else if (input_size < 0)
        {
            LOG_ERROR("Error while reading input file.");
            pshm->libtaenia_ready_flag = 0;
            if (close(finput))
            {
                LOG_ERROR("Close failed.");
                exit(-3);
            }
            exit(-2);
        }
        LOG_DEBUG("Received input %s.", input);

        if (close(finput))
        {
            LOG_ERROR("Close failed.");
            exit(-3);
        }

        LOG_PATH("Inp|%s", input);

        // We have taken its input.
        pshm->taenia_qemu_ready_flag = 0;

        // Executing function.
        execute_target(input);


#ifdef THREAD_TRACKING
        LOG_DEBUG("Function executed, waiting for all inputs produced to be untracked.");
        // Wait for all sub-threads to have terminated.
        while(1) {
            if (tracked_inputs_number == 0 && tracked_threads_number == 1) {
                // All threads (except the main one) have terminated and all inputs have been dealt with.
                break;
            }
            usleep(SLEEPTIME_STANDARD);
        }
#endif



#ifdef DEBUG
        gettimeofday(&tv_now, NULL);
        time_sec = tv_now.tv_sec - tv_ori.tv_sec;
        time_usec = tv_now.tv_usec - tv_ori.tv_usec;
        LOG_DEBUG("Execution done, time: %ld.%06lds", time_sec, time_usec);
#endif

        pshm->libtaenia_answer_flag = 1;

    }

    // --- Conclusion ---
    free(input_filename);
    free(input);
#ifdef THREAD_TRACKING
    free(tracked_inputs);
#endif
    pshm->libtaenia_ready_flag = 0;
    return NULL;
}


/*
 * Initialize libtaenia.
 */
int init_taenia()
{
    int ret = 0;
    if(!taenia_started)
    {
        ret = pthread_create(&caller_id, NULL, &libtaenia_task, NULL);
        if (ret)
        {
            LOG_ERROR("Error in caller_task thread.");
            exit(-1);
        }
        taenia_started = 1;
    }
    return ret;
}


