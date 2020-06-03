#ifndef ARCHIVE_H_
#define ARCHIVE_H_

#define _XOPEN_SOURCE 500 //for nftw

#include <ftw.h>
#include <libgen.h>
#include <errno.h>
#include <limits.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>        /* For mode constants */
#include <sys/wait.h>
#include <unistd.h>

#include "../../include/config.h"
#include "../../include/taenia_config.h"
#include "afl-qemu-taenia-log.h"
#include "afl-qemu-taenia-proc-monitor.h"

#define SAVE_CHAR 'S'
#define CRASH_CHAR 'C'
#define HANG_CHAR 'H'
#define PROCESS_CRASH_CHAR 'P'

/* ----------------------------------------------------------------------------
 * Stateful mode & timeouts
 * ------------------------------------------------------------------------- */

typedef struct
{
    int payload_counter;
    int was_saved;
    char *archive_path;
} t_archive;

static int copy_file(const char *source_path, const char *dest_path);
static int delete_file(const char *file_name, const struct stat *file_stats, int flag, struct FTW *extra_file_stats);
static int delete_directory(const char *dir_path);
static int init_stateful_mode(char *afl_output_dir, char *afl_input_path, uint32_t stateful_max_iterations);
static int destroy_archive(t_archive *archive);
static int add_current_payload(t_archive *archive, const char *afl_input_path);
static int save_archive(t_archive *archive, const char *new_path, const char reason);
static int create_archive(void);
static int do_archive(uint8_t process_alive, int status);
static int read_archive_metadata(const char* archive_path, int *payload_count, char *reason);
static int save_archive_crash_process(t_archive *archive, const char *new_path);

static int nb_crash = 0;
static int nb_hang = 0;
static int nb_proc_crash = 0;
static int previous_run_payload_number = 0;
static char stateful_output_path[PATH_MAX];
static char stateful_input_path[PATH_MAX];
static uint32_t libtaenia_stateful_max_iterations = 0;
static t_archive *archive;

/*
 * Copy a file content into another file
 * Returns -1 on error
 */
static int copy_file(const char *source_path, const char *dest_path)
{
    char *buffer;
    int fd;
    off_t data_size;
    struct stat st;

    // Opening source file
    fd = open(source_path, O_RDONLY);
    if (fd == -1)
    {
        LOG_ERROR("Could not open file %s", source_path);
        return -1;
    }

    FILE *source_file = fdopen(fd, "rb");
    if (source_file == NULL)
    {
        LOG_ERROR("Could not open file %s from file descriptor", source_path);
        return -1;
    }

    // Checking that we are dealing with a regular file
    if ((fstat(fd, &st) != 0) || (!S_ISREG(st.st_mode)))
    {
        LOG_ERROR("%s is not a regular file", source_path);
        return -1;
    }

    // Getting data size
    data_size = st.st_size;

    buffer = (char *) malloc(data_size);

    // Getting data
    fread(buffer, sizeof(char), data_size, source_file);
    fclose(source_file);

    // Saving data to destination file
    FILE *dest_file = fopen(dest_path, "wb+");
    if (dest_file == NULL)
    {
        LOG_ERROR("Could not open file %s.", dest_path);
        return -1;
    }

    fwrite(buffer, sizeof(char), data_size, dest_file);
    fclose(dest_file);

    free(buffer);

    return 0;
}

static int delete_file(const char *file_name, const struct stat *file_stats, int flag, struct FTW *extra_file_stats)
{
    return remove(file_name);
}

static int delete_directory(const char *dir_path)
{
    return nftw(dir_path, delete_file, 1, FTW_DEPTH | FTW_PHYS);
}

static int init_stateful_mode(char *afl_output_dir, char *afl_input_path, uint32_t stateful_max_iterations)
{
    LOG_DEBUG("Initializing stateful mode");

    snprintf(stateful_output_path, PATH_MAX, "%s/stateful", afl_output_dir);

    struct stat st = {0};
    if (stat(stateful_output_path, &st) == -1)
    {
        if (mkdir(stateful_output_path, 0700) == -1)
        {
            LOG_ERROR("Error creating '%s' directory", stateful_output_path);
            return 0;
        }
    }
    else
    {
        if (delete_directory(stateful_output_path) == -1)
        {
            LOG_ERROR("Could not delete directory");
            return 0;
        }
        if (mkdir(stateful_output_path, 0700) == -1)
        {
            LOG_ERROR("Error creating '%s' directory", stateful_output_path);
            return 0;
        }
    }

    if (!strncpy(stateful_input_path, afl_input_path, PATH_MAX))
    {
        LOG_ERROR("Could not copy afl input path.");
        return 0;
    }
    libtaenia_stateful_max_iterations = stateful_max_iterations;
    return 1;
}

/*
 * Destroys the specified archive from memory and disk
 */
static int destroy_archive(t_archive *archive)
{
    if (!archive->was_saved)
    {
        if (delete_directory(archive->archive_path) == -1)
        {
            LOG_ERROR("Could not delete directory");
            return -1;
        }
    }
    free(archive->archive_path);
    free(archive);

    LOG_DEBUG("Archive destroyed");

    return 0;
}

static int add_current_payload(t_archive *archive, const char *afl_input_path)
{
    // Building dest path
    char dest_file_path[PATH_MAX];
    if (snprintf(dest_file_path, PATH_MAX, "%s/%d.bin", archive->archive_path, archive->payload_counter) == PATH_MAX)
    {
        LOG_ERROR("Could not open file %s", afl_input_path);
        return -1;
    }

    if(copy_file(afl_input_path, dest_file_path) == -1)
    {
        LOG_ERROR("Could not open file %s from file descriptor", afl_input_path);
        return -1;
    }

    archive->payload_counter++;

    LOG_DEBUG("Payload saved");

    return 0;
}

static int save_archive_crash_process(t_archive *archive, const char *new_path)
{
    // Creating METADATA file
    char metadata_path[PATH_MAX];
    int len = snprintf(metadata_path, PATH_MAX, "%s/METADATA", archive->archive_path);

    if (len > 0)
    {
        if (len == PATH_MAX)
        {
            LOG_ERROR("METADATA path was truncated.");
            return -1;
        }
    }
    else
    {
        LOG_ERROR("Could not create METADATA path.");
        return -1;
    }

    LOG_INFO("Saving archive as %s", new_path);

    char metadata[100];
    // In case of a tracked process crash, we must provide the process names
    int payload_number = archive->payload_counter + previous_run_payload_number - 2;
    sprintf(metadata, "%d %c\n%s", payload_number, PROCESS_CRASH_CHAR, create_crash_proc_metadata(processes_snapshot));

    FILE *metadata_file = fopen(metadata_path, "w+");
    if (metadata_file == NULL)
    {
        LOG_ERROR("Could not open METADATA file.");
        return -1;
    }
    if (fputs(metadata, metadata_file) == EOF)
    {
        LOG_ERROR("Could not write to METADATA file.");
        return -1;
    }
    if (fclose(metadata_file) == EOF)
    {
        LOG_ERROR("Problem ecountered while closing METADATA file.");
        return -1;
    }

    // Renaming all payloads in preparation for merge
    int i;
    char old_path[PATH_MAX];
    char newer_path[PATH_MAX];

    for(i=1; i < libtaenia_stateful_max_iterations; i++)
    {
        int new_number = i + libtaenia_stateful_max_iterations - 1;
        snprintf(old_path, PATH_MAX, "%s/%d.bin", archive->archive_path, i);
        snprintf(newer_path, PATH_MAX, "%s/%d.bin", archive->archive_path, new_number);
        copy_file(old_path, newer_path);
    }

    //adding payloads from the previous run

    char previous_run_path[PATH_MAX];
    snprintf(previous_run_path, PATH_MAX, "%s/%s", stateful_output_path, "previous");
    for(i=1; i < libtaenia_stateful_max_iterations; i++)
    {
        snprintf(old_path, PATH_MAX, "%s/%d.bin", previous_run_path, i);
        snprintf(newer_path, PATH_MAX, "%s/%d.bin", archive->archive_path, i);
        copy_file(old_path, newer_path);
    }

    // Saving archive to new_path
    if (rename(archive->archive_path, new_path) == -1)
    {
        LOG_ERROR("Could not rename current archive.");
        return -1;
    }
    archive->was_saved = 1;

    LOG_DEBUG("Payload saved");

    return 0;
}

/*
 * Rename the "current" dir to save it for replay
 * new_path must be unique to avoid rename failure
 */
static int save_archive(t_archive *archive, const char *new_path, const char reason)
{
    // Creating METADATA file
    char metadata_path[PATH_MAX];
    int len = snprintf(metadata_path, PATH_MAX, "%s/METADATA", archive->archive_path);

    if (len > 0)
    {
        if (len == PATH_MAX)
        {
            LOG_ERROR("METADATA path was truncated.");
            return -1;
        }
    }
    else
    {
        LOG_ERROR("Could not create METADATA path.");
        return -1;
    }

    LOG_INFO("Saving archive as %s", new_path);

    char metadata[100];
    // In case of a tracked process crash, we must provide the process names
    if(reason == PROCESS_CRASH_CHAR)
    {
        sprintf(metadata, "%d %c\n%s", archive->payload_counter - 1, reason, create_crash_proc_metadata(processes_snapshot));
    }
    else
    {
        sprintf(metadata, "%d %c", archive->payload_counter - 1, reason);
    }
    FILE *metadata_file = fopen(metadata_path, "w+");
    if (metadata_file == NULL)
    {
        LOG_ERROR("Could not open METADATA file.");
        return -1;
    }
    if (fputs(metadata, metadata_file) == EOF)
    {
        LOG_ERROR("Could not write to METADATA file.");
        return -1;
    }
    if (fclose(metadata_file) == EOF)
    {
        LOG_ERROR("Problem ecountered while closing METADATA file.");
        return -1;
    }

    // Saving archive to new_path
    if (rename(archive->archive_path, new_path) == -1)
    {
        LOG_ERROR("Could not rename current archive.");
        return -1;
    }
    archive->was_saved = 1;

    LOG_DEBUG("Archive saved");

    return 0;
}

/*
 * Read and returns the number of payload contained in an archive
 * Returns -1 on error
 */
int read_archive_metadata(const char* archive_path, int *payload_count, char *reason)
 {
    char metadata_file_path[PATH_MAX];
    if (snprintf(metadata_file_path, PATH_MAX, "%s/METADATA", archive_path) == PATH_MAX)
    {
        LOG_ERROR("Path was truncated");
        return -1;
    }

    FILE *metadata_file = fopen(metadata_file_path, "r");
    if(metadata_file == NULL)
    {
        LOG_ERROR("Could not open metadata file");
        return -1;
    }

    if(fscanf(metadata_file, "%d %c", payload_count, reason) == EOF)
    {
        LOG_ERROR("Error reading metadata file");
        return -1;
    }

    if(*payload_count <= 0)
    {
        LOG_ERROR("Payload count is not a valid number");
        return -1;
    }

    if(*reason != CRASH_CHAR && *reason != HANG_CHAR && *reason != PROCESS_CRASH_CHAR && *reason != SAVE_CHAR)
    {
        LOG_ERROR("Reason is not valid, should be C, H, S or P");
        return -1;
    }

    LOG_INFO("payload_count: %d", *payload_count);
    LOG_INFO("reason: %c", *reason);

    return 0;
}

/*
 * Create an archive architecture inside the specified path
 */
static int create_archive()
{
    char archive_path[PATH_MAX];
    int len = snprintf(archive_path, PATH_MAX, "%s/current", stateful_output_path);

    if (len > 0)
    {
        if (len == PATH_MAX)
        {
            LOG_ERROR("Archive path was truncated.");
            return 0;
        }
    }
    else
    {
        LOG_ERROR("Could not create Archive path.");
        return 0;
    }

    archive = (t_archive *) malloc(sizeof(t_archive));
    memset(archive, 0, sizeof(t_archive));

    int path_size = strlen(archive_path) + 1;
    archive->archive_path = (char*) malloc(path_size * sizeof(char));
    memcpy(archive->archive_path, archive_path, path_size * sizeof(char));
    archive->payload_counter = 1;
    archive->was_saved = 0;

    LOG_DEBUG("Creating archive at path %s", archive->archive_path);

    struct stat st = {0};
    if (stat(archive->archive_path, &st) == -1)
    {
        if (mkdir(archive->archive_path, 0700) == -1)
        {
            LOG_ERROR("Error creating '%s' directory", archive->archive_path);
            return 0;
        }
    }
    else
    {
        if (delete_directory(archive->archive_path) == -1)
        {
            LOG_ERROR("Could not delete directory");
            return 0;
        }
        if (mkdir(archive->archive_path, 0700) == -1)
        {
            LOG_ERROR("Error creating '%s' directory", archive->archive_path);
            return 0;
        }
    }
    return 1;
}

/*
 * Returns 0 in case of error.
 *         1 in case of success.
 *         2 to kill child.
 *         3 for a tracked process death 
 */
static int do_archive(uint8_t process_alive, int status)
{
    LOG_DEBUG("Do archive.");

    if (process_alive)
    {
        // If we reached hard cap, we restart program
        if (archive->payload_counter >= libtaenia_stateful_max_iterations)
        {
            LOG_INFO("Stateful mode: restarting program.");
            process_alive = 0;

            if(track_process_mode)
            {
                int dead = update_proc_snapshot(processes_snapshot);
#ifdef TAENIA_DEBUG
                LOG_DEBUG("Tracked processes status :");
                print_debug_proc_snapshot(processes_snapshot);
#endif
                if(dead)
                {  
                    nb_proc_crash++;
                    char path[PATH_MAX];
                    int len = snprintf(path, PATH_MAX, "%s/process-crash-%d", stateful_output_path, nb_proc_crash);

                    if (len > 0)
                    {
                        if (len == PATH_MAX)
                        {
                            LOG_ERROR("Process crash path was truncated.");
                            return 0;
                        }
                    }
                    else
                    {
                        LOG_ERROR("Could not create process crash.");
                        return 0;
                    }
                    if (save_archive_crash_process(archive, path) == -1)
                    {
                        LOG_ERROR("Could not save archive");
                        return 0;
                    }
                    if (destroy_archive(archive) == -1)
                    {
                        LOG_ERROR("Could not destroy archive properly");
                        return 0;
                    }
                    char previous_run_path[PATH_MAX];
                    snprintf(previous_run_path, PATH_MAX, "%s/%s", stateful_output_path, "previous");
                    delete_directory(previous_run_path);
                    return 3;
                }
                else
                {
                    // Discarding last archive as nothing fun happened.
                    char previous_run_path[PATH_MAX];
                    snprintf(previous_run_path, PATH_MAX, "%s/%s", stateful_output_path, "previous");
                    delete_directory(previous_run_path);
                    save_archive(archive, previous_run_path, SAVE_CHAR);
                    previous_run_payload_number = archive->payload_counter;
                    LOG_INFO("All tracked processes are alive");
                }
                
            }
            destroy_archive(archive);

            // Order to silently kill child
            return 2;
        }
        else
        {
            // Saving payload
            if (add_current_payload(archive, stateful_input_path) == -1)
            {
                LOG_ERROR("Could not add payload to archive.");
                return 0;
            }
        }
    }
    else
    {
        // Saving payload
        if (add_current_payload(archive, stateful_input_path) == -1)
        {
            LOG_ERROR("Could not add payload to archive.");
            return 0;
        }

        // Saving archive
        if (status == SIGKILL)
        {
            // Saving archive as hang
            nb_hang++;
            char path[PATH_MAX];
            int len = snprintf(path, PATH_MAX, "%s/hang-%d", stateful_output_path, nb_hang);

            if (len > 0)
            {
                if (len == PATH_MAX)
                {
                    LOG_ERROR("Hang path was truncated.");
                    return 0;
                }
            }
            else
            {
                LOG_ERROR("Could not create hang path.");
                return 0;
            }
            if (save_archive(archive, path, HANG_CHAR) == -1)
            {
                LOG_ERROR("Could not save archive");
                return 0;
            }
            if (destroy_archive(archive) == -1)
            {
                LOG_ERROR("Could not destroy archive properly");
                return 0;
            }
        }
        else
        {
            // Saving archive as crash
            nb_crash++;
            char path[PATH_MAX];
            int len = snprintf(path, PATH_MAX, "%s/crash-%d", stateful_output_path, nb_crash);

            if (len > 0)
            {
                if (len == PATH_MAX)
                {
                    LOG_ERROR("Crash path was truncated.");
                    return 0;
                }
            }
            else
            {
                LOG_ERROR("Could not create crash path.");
                return 0;
            }
            if(save_archive(archive, path, CRASH_CHAR) == -1)
            {
                LOG_ERROR("Could not save archive");
                return 0;
            }
            if (destroy_archive(archive) == -1)
            {
                LOG_ERROR("Could not destroy archive properly");
                return 0;
            }
        }
    }
    return 1;
}


#endif // ARCHIVE_H_
