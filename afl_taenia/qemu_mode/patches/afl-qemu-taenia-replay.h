#ifndef REPLAY_H_
#define REPLAY_H_

#define _XOPEN_SOURCE 500 //for nftw

#include <ftw.h>

#include "afl-qemu-common.h"
#include "afl-qemu-taenia-comm.h"
#include "afl-qemu-taenia-conf.h"
#include "afl-qemu-taenia-archive.h"


static int get_replay_mode(const char* payload_path);
static void replay_setup(void);
static void replay_forkserver(void);

extern uint8_t taenia_replay_mode;
extern unsigned int afl_forksrv_pid;

static int multi_payload_mode = 0;
static char replay_payload_path[PATH_MAX];
static int last_payload_number = 1;

// Read from METADATA file, can be C (crash), H (hang), P (other process crash)
static char archive_reason;

/*
 * Identify is the payload is a single file or an archive containing multiple payloads.
 * Returns -1 on error
 */
static int get_replay_mode(const char* payload_path)
{

    int fd;
    struct stat st;

    fd = open(payload_path, O_RDONLY);
    if (fd == -1)
    {
        LOG_ERROR("Could not open file %s", payload_path);
        return -1;
    }

    if (fstat(fd, &st) != 0)
    {
        LOG_ERROR("Could not get stats from file %s", payload_path);
        return -1;
    }

    // Checking if payload_path is a regular file
    if (S_ISREG(st.st_mode))
    {
        LOG_DEBUG("Single payload mode");
        return 0;
    }

    //if not, checking if it's a valide archive
    if (S_ISDIR(st.st_mode))
    {
        char metadata_file[PATH_MAX];
        if (snprintf(metadata_file, PATH_MAX, "%s/METADATA", payload_path) == PATH_MAX)
        {
            LOG_ERROR("path was truncated");
            return -1;
        }

        if (access(metadata_file, F_OK) == 0)
        {
            LOG_DEBUG("Archive mode");
            return 1;
        }
    }
    return 0;
}

static void replay_setup()
{
    LOG_INFO("Replay setup");

    pshm = make_shm();
    if (pshm == NULL)
        exit(1);

    load_replay_configuration(replay_payload_path);

    multi_payload_mode = get_replay_mode(replay_payload_path);

    if (multi_payload_mode == -1)
    {
        LOG_ERROR("Payload source coud not be identified as valid");
        exit(1);
    }

    // If we're in archive mode, pull the payload count from METADATA file
    if (multi_payload_mode)
    {
        if(read_archive_metadata(replay_payload_path, &last_payload_number, &archive_reason) == -1)
        {
            LOG_ERROR("Error while reading METADATA file");
            exit(1);
        }
    }

    rcu_disable_atfork();
}

static void replay_forkserver()
{

    LOG_INFO("Replay forkserver");

    pid_t child_pid;
    int status, t_fd[2];
    int ret = 0;
    unsigned int session_id = 0, iteration = 0;
    uint8_t process_alive = 0;
    t_archive *archive;

    int current_payload_number;

    afl_forksrv_pid = getpid();

    while (1)
    {
        LOG_INFO("Restarting program: session %d.", session_id++);

        clean_shm(pshm);

        LOG_DEBUG("Fork");

        child_pid = fork();

        if (child_pid < 0)
        {
            LOG_ERROR("Fork error");
            exit(4);
        }

        if (!child_pid)
        {

            /* Child process. Close descriptors and run free. */

            afl_fork_child = 1;
            close(FORKSRV_FD);
            close(FORKSRV_FD + 1);
            close(t_fd[0]);

            LOG_DEBUG("Child runs.");

            return;

        }

        /* Parent. */
        LOG_DEBUG("Parent continue.");

        ret = wait_for_taenia_ready(pshm, libtaenia_init_timeout);

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

        current_payload_number = 1;

        /* main loop, exit only on a crash */

        while (process_alive)
        {
            status = 0;
            iteration++;
            LOG_DEBUG("Main loop, iteration %d.", iteration);

            if (!multi_payload_mode)
            {
                LOG_DEBUG("Payload source: %s", replay_payload_path);
                if(copy_file(replay_payload_path, afl_input_file) == -1)
                {
                    LOG_ERROR("Could not copy payload into Taenia's input file");
                    exit(1);
                }
            }
            else
            {
                // getting current payload in the archive
                char payload_file[PATH_MAX];
                if (snprintf(payload_file, PATH_MAX, "%s/%d.bin", replay_payload_path, current_payload_number) == PATH_MAX)
                {
                    LOG_ERROR("path was truncated");
                    exit(1);
                }
                LOG_DEBUG("Payload source: %s", payload_file);
                if(copy_file(payload_file, afl_input_file) == -1)
                {
                    LOG_ERROR("Could not copy payload into Taenia's input file");
                    exit(1);
                }
            }

            // I am ready
            pshm->taenia_qemu_ready_flag = 1;

            // Waiting for libtaenia answer.
            process_alive = wait_for_taenia_answer(child_pid, &status, pshm);
            pshm->libtaenia_answer_flag = 0;

            /* Get and relay exit status to parent. */
            if (!process_alive)
            {
                if (status == SIGKILL)
                {
                    printf("Program hung !\n");
                }
                else
                {
                    printf("Program crashed with signal %d !\n", WTERMSIG(status));
                }
            }

            if (current_payload_number == last_payload_number)
            {
                LOG_INFO("End of replay, see you later !");
                exit(0);
            }

            LOG_DEBUG("Child pid: %d, Waitpid ret: %d, status: %d.", child_pid, ret, status);
            current_payload_number++;
        }
    }
}

#endif // REPLAY_H_
