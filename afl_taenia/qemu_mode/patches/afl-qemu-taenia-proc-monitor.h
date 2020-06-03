#ifndef TAENIA_PROC_MONITOR_H_
#define TAENIA_PROC_MONITOR_H_

#define _GNU_SOURCE
#include <limits.h>
#include <sys/stat.h>
#include <dirent.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <time.h>

#define MAX_MULTILINE_VALUES 100
#define MAX_LINE 1000

typedef struct
{
    char **procs;
    int *pids;
    int *is_alive;
    int number;
    int max_number;
} proc_snapshot;

typedef struct
{
    char **procs;
    int number;
    int max_number;
} proc_list;

static proc_list *tracked_procs;
static proc_snapshot *processes_snapshot;
static int track_process_mode = 0;

static proc_list *create_proc_list(int max_proc_number);
static void destroy_proc_list(proc_list *list);

static proc_snapshot *create_proc_snapshot(int max_proc_number);
static void destroy_proc_snapshot(proc_snapshot *snapshot);
static proc_snapshot *take_proc_snapshot();
static proc_snapshot *filter_proc_snapshot(proc_snapshot *snapshot, proc_list *filter);
static int update_proc_snapshot(proc_snapshot *proc_snap);
static char *get_name_from_status_file(FILE *file);
static void print_debug_proc_snapshot(proc_snapshot *proc_snap);
static int is_process_alive(int pid, const char *proc_name);

proc_list *create_proc_list(int max_proc_number)
{
    proc_list *list = (proc_list *)malloc(sizeof(proc_list));
    list->procs = (char **) malloc(sizeof(char *) * max_proc_number);
    list->number = 0;
    list->max_number = max_proc_number;
    return list;
}

static void destroy_proc_list(proc_list *list)
{
    free(list->procs);
    free(list);
}

static int name_is_in_proc_list(char *name, proc_list *list)
{
    int i;
    for (i = 0; i < list->number; i++)
    {
        if (strcmp(name, list->procs[i]) == 0)
        {
            return 1;
        }
    }
    return 0;
}

static proc_snapshot *take_proc_snapshot()
{
    DIR *proc_dir;
    struct dirent *current_dir;
    char path[PATH_MAX];
    FILE *status_file;
    FILE *max_pid_file;
    int max_pid;

    /*
     Getting the max_pid system limit: might be overkill 
     but we wont take any chance at missing a process because
     we cheaped out on RAM.
    */
    max_pid_file = fopen("/proc/sys/kernel/pid_max", "r");

    if (max_pid_file == NULL)
    {
        LOG_ERROR("Can't open /proc/sys/kernel/pid_max");
        return NULL;
    }

    if (fscanf(max_pid_file, "%d", &max_pid) == EOF)
    {
        LOG_ERROR("Can't read /proc/sys/kernel/pid_max");
        return NULL;
    }

    fclose(max_pid_file);

    proc_snapshot *proc_snap = create_proc_snapshot(max_pid);

    proc_dir = opendir("/proc");
    if (proc_dir == NULL)
    {
        LOG_ERROR("Can't open /proc");
        return NULL;
    }

    current_dir = readdir(proc_dir);

    // Rolling through all files in /proc to find processes
    while (current_dir != NULL && proc_snap->number < proc_snap->max_number)
    {
        if (current_dir->d_type == DT_DIR && isdigit(current_dir->d_name[0]))
        {
            snprintf(path, PATH_MAX, "/proc/%s/status", current_dir->d_name);

            status_file = fopen(path, "r");
            // process might have died on us
            if (status_file == NULL)
            {
                current_dir = readdir(proc_dir);
                continue;
            }

            char *name = get_name_from_status_file(status_file);
            if (name != NULL)
            {
                proc_snap->procs[proc_snap->number] = name;
            }
            else
            {
                LOG_ERROR("Could not parse status file properly");
                return NULL;
            }

            fclose(status_file);

            proc_snap->pids[proc_snap->number] = atoi(current_dir->d_name);
            proc_snap->number++;
            proc_snap->is_alive[proc_snap->number] = 1;
        }

        current_dir = readdir(proc_dir);
    }
    closedir(proc_dir);
    return proc_snap;
}

static char *create_crash_proc_metadata(proc_snapshot *proc_snap)
{
    size_t metadata_len = 0;
    unsigned int i;

    for(i = 0; i < proc_snap->number; i++)
    {
        if(!proc_snap->is_alive[i])
        {
            metadata_len += strlen(proc_snap->procs[i]);
            //for comma sepration
            metadata_len += sizeof(char);
        }
    }

    char *metadata_line = (char *) malloc(sizeof(char) * (metadata_len));
    memset(metadata_line, 0, metadata_len);

    printf("%ld", metadata_len);

    for(i = 0; i < proc_snap->number; i++)
    {
        if(!proc_snap->is_alive[i])
        {
            int len = strlen(proc_snap->procs[i]);
            strncat(metadata_line, proc_snap->procs[i], len);
            strncat(metadata_line, ",", 1);
        }
    }
    metadata_line[metadata_len - 1] = '\0';
    return metadata_line;
}

static proc_snapshot *create_proc_snapshot(int max_proc_number)
{
    proc_snapshot *snapshot = (proc_snapshot *)malloc(sizeof(proc_snapshot));
    snapshot->procs = (char **) malloc(sizeof(char *) * max_proc_number);
    snapshot->pids = (int *) malloc(sizeof(int *) * max_proc_number);
    snapshot->is_alive = (int *) malloc(sizeof(int *) * max_proc_number);
    snapshot->number = 0;
    snapshot->max_number = max_proc_number;
    return snapshot;
}

static void destroy_proc_snapshot(proc_snapshot *snapshot)
{
    free(snapshot->procs);
    free(snapshot->pids);
    free(snapshot);
}

static proc_snapshot *filter_proc_snapshot(proc_snapshot *snapshot, proc_list *filter)
{
    //There will be at most snapshot->number values after filtering
    proc_snapshot *filtered_snapshot = create_proc_snapshot(snapshot->number);

    unsigned int i;
    for (i = 0; i < snapshot->number; i++)
    {
        if (name_is_in_proc_list(snapshot->procs[i], filter))
        {
            filtered_snapshot->procs[filtered_snapshot->number] = strdup(snapshot->procs[i]);
            filtered_snapshot->pids[filtered_snapshot->number] = snapshot->pids[i];
            filtered_snapshot->number++;
        }
    }
    return filtered_snapshot;
}

/*
 * Return 1 if at least one process is now dead, 0 otherwise
 */
static int update_proc_snapshot(proc_snapshot *proc_snap)
{
    int i;
    int ret = 0;
    for(i=0; i < proc_snap->number; i++)
    {
        if(!is_process_alive(proc_snap->pids[i], proc_snap->procs[i]))
        {
            ret = 1;
            proc_snap->is_alive[i] = 0;
        }
    }
    return ret;
}

static char *get_name_from_status_file(FILE *status_file)
{
    char line[MAX_LINE];
    char *p;

    while (fgets(line, MAX_LINE, status_file) != NULL)
    {
        if (strncmp(line, "Name:", 5) == 0)
        {
            // extracting name value
            for (p = line + 5; *p != '\0' && isspace(*p);)
                p++;

            int proc_name_len = strlen(p);

            // Remove \n with a null byte
            p[proc_name_len - 1] = '\0';

            return strdup(p);
        }
    }
    return NULL;
}

static void print_debug_proc_snapshot(proc_snapshot *proc_snap)
{
    unsigned int i;
    for(i = 0; i < proc_snap->number; i++)
    {
        if(proc_snap->is_alive[i])
        {
            LOG_DEBUG("%d\t%s\tAlive", proc_snap->pids[i], proc_snap->procs[i]);
        }
        else
        {
            LOG_DEBUG("%d\t%s\tDead", proc_snap->pids[i], proc_snap->procs[i]);
        }
    }
}

static int is_process_alive(int pid, const char *proc_name)
{
    char path[PATH_MAX];
    FILE *status_file;

    snprintf(path, PATH_MAX, "/proc/%d/status", pid);

    status_file = fopen(path, "r");
    if (status_file == NULL)
    {
        // if we can't open /proc/[pid]/status, the process is dead
        return 0;
    }

    // if we can, we check the name to ensure that it's (hopefully) the same
    char *extracted_name = get_name_from_status_file(status_file);
    fclose(status_file);
    if (strcmp(extracted_name, proc_name) == 0)
    {
        return 1;
    }
    else
    {
        return 0;
    }
}

#endif // TAENIA_PROC_MONITOR_H_
