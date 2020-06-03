/*
 * taenia_config.h
 *
 *  Contained all configurable defined elements of afl-taenia.
 */

#ifndef AFL_TAENIA_INCLUDE_TAENIA_CONFIG_H_
#define AFL_TAENIA_INCLUDE_TAENIA_CONFIG_H_

#include <pthread.h>

// The standard size of all inputs.
#define STANDARD_INPUT_SIZE 512

// The max size of an input.
extern size_t max_input_size;

// Shared mem name.
#define SHM_NAME "/taenia_shm.01"

// To have the time to follow while debugging
#define SLEEPTIME_DEBUG 1000000
#define SLEEPTIME_STANDARD 1
#if defined(DEBUG) || defined(TAENIA_DEBUG)
#define USLEEP_DEBUG usleep(SLEEPTIME_DEBUG)
#else
#define USLEEP_DEBUG
#endif

// For unused parameters
#define UNUSED(x) (void)(x)

// Max size of one log
#define LOG_SIZE 512
#define LOG_COLOR_ERROR 31
#define LOG_COLOR_INFO 0
#define LOG_COLOR_DEBUG 33
#define LOG_COLOR_RAW_DEBUG 32

//  Max size of a configuration element
#define CONF_ELEM_SIZE 512
#define CONF_ELEM_ENUM_SIZE 10000

#define MAX_TRACKED_LIBS 100
#define MAX_LIB_NAME_SIZE 128

#define MAX_TRACKED_PROCS 100

#if defined(THREAD_TRACKING) || defined(TAENIA_THREAD_TRACKING)

// Max number of threads we can track.
#define MAX_THREADS 100

// Max number of inputs we can track.
#define MAX_INPUTS 1000


#if defined(THREAD_LOGS) || defined(TAENIA_THREAD_LOGS)

// Total number of threads we can encounter and will log.
#define MAX_TOTAL_THREADS 100
#endif // THREAD_LOGS
#endif // THREAD_TRACKING

#ifdef TAENIA_DEBUG_PATH
extern pthread_mutex_t debug_path_log_mutex;
#endif


#endif /* AFL_TAENIA_INCLUDE_TAENIA_CONFIG_H_ */
