/*
 * Configuration parsing for all elements.
 */

#ifndef AFL_TAENIA_QEMU_MODE_PATCHES_AFL_QEMU_TAENIA_COMM_H_
#define AFL_TAENIA_QEMU_MODE_PATCHES_AFL_QEMU_TAENIA_COMM_H_

#include <stdint.h>
#include <sys/shm.h>

#include "afl-qemu-taenia-conf.h"

static volatile taenia_shm_t *make_shm(void);
static int clean_shm(volatile taenia_shm_t *shmptr);
static int wait_for_taenia_ready(volatile taenia_shm_t * shm_ptr, int timeouts);
static int wait_for_taenia_answer(pid_t child_pid, int *status, volatile taenia_shm_t *shmptr);
static void wait_afl_command(void);
static int kill_program(int child_pid, volatile taenia_shm_t *shmptr);

#if defined(TAENIA_THREAD_TRACKING) && defined(TAENIA_THREAD_LOGS)
static inline int clean_encountered_threads(volatile taenia_shm_t *shmptr);
#endif

/*
 * taenia-qemu is the first to use the shared mem, so he makes it.
 */
static volatile taenia_shm_t *make_shm(void)
{
    volatile taenia_shm_t *shmptr;
    int fd = 0;
    size_t size = sizeof(taenia_shm_t);

    LOG_DEBUG("Creating shared mem between taenia-qemu and libtaenia.");

    fd = shm_open(SHM_NAME, O_RDWR | O_CREAT, 0644);
    if (ftruncate(fd, size))
    {
        LOG_ERROR("Error ftruncate shm: %s (%d).", strerror(errno), errno);
        shmptr = NULL;
        exit(1);
    }

    if (fd <= 0)
    {
        LOG_ERROR("Error opening shm: %s (%d).", strerror(errno), errno);
        shmptr = NULL;
        exit(1);
    }
    shmptr = (taenia_shm_t *) mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);

    if (shmptr == NULL)
    {
        LOG_ERROR("Error mmap shm: %s (%d).", strerror(errno), errno);
        shmptr = NULL;
        exit(1);
    }

    clean_shm(shmptr);
    shmptr->libtaenia_tracked_libs_number = 0;
    return shmptr;
}

static int clean_shm(volatile taenia_shm_t *shmptr)
{
    shmptr->libtaenia_ready_flag = 0;
    shmptr->libtaenia_answer_flag = 0;
    shmptr->taenia_qemu_ready_flag = 0;
    shmptr->libtaenia_thread_id = 0;

#ifdef TAENIA_THREAD_TRACKING
    for (uint16_t i = 0; i < MAX_THREADS; i++)
    {
        shmptr->tracked_thread_ids[i] = 0;
    }
#ifdef TAENIA_THREAD_LOGS
    clean_encountered_threads(shmptr);
#endif  // TAENIA_THREAD_LOGS
#endif  // TAENIA_THREAD_TRACKING

    return 1;
}

static int wait_for_taenia_ready(volatile taenia_shm_t * shm_ptr, int timeouts)
{
    char timeout = 0;
    time_t start = time(NULL);

    LOG_INFO("Waiting for libtaenia to be ready.");

    while (!shm_ptr->libtaenia_ready_flag)
    {
        if ((time(NULL) - start) >= timeouts)
        {
            LOG_DEBUG("Timeout: %ld.", (time(NULL) - start));
            timeout = 1;
            break;
        }
        usleep(100);
    }

    if (!timeout)
    {
        LOG_DEBUG("Libtaenia ready, thread id: %ld.", shm_ptr->libtaenia_thread_id);
        return 0;
    }
    LOG_ERROR("Libtaenia not ready, process timeouts, something went wrong.");

    return -2;
}

static int kill_program(int child_pid, volatile taenia_shm_t *shmptr)
{
    int res;
    int status;
    time_t start = time(NULL);

    kill(child_pid, SIGKILL); // kill process
    while ((res = waitpid(child_pid, &status, WNOHANG)) == 0)
    {
        usleep(1);
        if (time(NULL) - start >= 3)
        {
            LOG_INFO("Child cannot be killed.");
            return 1;
        }
    }
    if (res < 0)
    {
        LOG_INFO("Child already dead.");
        return 0;
    }
    if (res > 0)
    {
        LOG_INFO("Child killed.");
        return 0;
    }
    return 1;
}

/*
 * Return if the processis is alive.
 */
static int wait_for_taenia_answer(pid_t child_pid, int *status, volatile taenia_shm_t *shmptr)
{
    time_t start = time(NULL);

    LOG_DEBUG("Waiting for libtaenia answer.");

    while (!shmptr->libtaenia_answer_flag)
    {
        // Trying to get a status in a non blocking way.
        waitpid(child_pid, status, WNOHANG);

        if (WIFSIGNALED(*status))
        {
            // If process was killed by a signal, it must be a crash.
            LOG_ERROR("Process was killed by signal %d, something went wrong.\n", WTERMSIG(*status));
            return 0;
        }

        if ((time(NULL) - start) >= libtaenia_hang_timeout)
        {
            // Hang detected by timeout
            *status = SIGKILL;
            LOG_ERROR("No answer received, process timeouts, something went wrong.");
            return kill_program(child_pid, shmptr);

        }
        LOG_DEBUG("Wait wake-up, qemu: %d, taenia: %d, answer: %d", shmptr->taenia_qemu_ready_flag, shmptr->libtaenia_ready_flag, shmptr->libtaenia_answer_flag);
        USLEEP_DEBUG;
        usleep(100);
    }

    /* Sync process status with afl */
    *status = 0;
    return 1;
}

static void wait_afl_command(void)
{
    static unsigned char tmp[4];

    LOG_DEBUG("Waiting for afl command.");
    int n = read(FORKSRV_FD, tmp, 4);
    if (n < 0)
    {
        LOG_ERROR("Read error from AFL server: %s (%d)", strerror(errno), errno);
        exit(2);
    }
    else if (n != 4)
    {
        LOG_ERROR("Read incomplete from AFL server: %d", n);
        exit(2);
    }
}

#if defined(TAENIA_THREAD_TRACKING) && defined(TAENIA_THREAD_LOGS)
static inline int clean_encountered_threads(volatile taenia_shm_t *shmptr)
{
    LOG_DEBUG("Cleaning encountered threads.");

    for (uint16_t i = 0; i < MAX_TOTAL_THREADS; i++)
    {
        shmptr->encountered_threads_id[i] = 0;
        shmptr->encountered_threads_read_count[i] = 0;
        shmptr->encountered_threads_write_count[i] = 0;
        shmptr->encountered_threads_block_count[i] = 0;
    }
    return 1;
}
#endif

#endif /* AFL_TAENIA_QEMU_MODE_PATCHES_AFL_QEMU_TAENIA_COMM_H_ */
