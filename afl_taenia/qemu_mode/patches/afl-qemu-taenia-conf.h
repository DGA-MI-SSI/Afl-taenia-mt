/*
 * Communications between libtaenia and afl-qemu go through a shared mem managed here.
 *
 *
 */

#ifndef AFL_TAENIA_QEMU_MODE_PATCHES_AFL_QEMU_TAENIA_CONF_H_
#define AFL_TAENIA_QEMU_MODE_PATCHES_AFL_QEMU_TAENIA_CONF_H_

#include <stdint.h>

#include "afl-qemu-taenia-archive.h"
#include "afl-qemu-taenia-proc-monitor.h"
#include "afl-qemu-common.h"

static uint32_t libtaenia_init_timeout = 10;
static uint32_t libtaenia_hang_timeout = 3;
static uint8_t libtaenia_stateful_mode = 0;
static char afl_input_file[PATH_MAX];
static uint32_t minify_mode = 0;
static uint32_t stop_on_process_crash = 0;

static int parse_multivalue_line(const char* expected_cmd, const char* current_cmd, const char* current_value, proc_list *list);
static int parse_uint32_t(const char* expected_cmd, const char* current_cmd, const char* current_value, uint32_t *final_value);
static int parse_string(const char* expected_cmd, const char* current_cmd, const char* current_value, char *final_value);
static int load_replay_configuration(char *replay_payload_path);
static int load_configuration(void);

static int parse_multivalue_line(const char* expected_cmd, const char* current_cmd, const char* current_value, proc_list *list)
{
    if (!strcmp(current_cmd, expected_cmd))
    {
        char *delim = ", ";
        char *token = strtok((char *)current_value, delim);
        int i = 0;
        while (token != NULL && i < list->max_number)
        {
            list->procs[i] = strdup(token);
            token = strtok(NULL, delim);
            LOG_DEBUG("%s[%d]: %s", expected_cmd, i, list->procs[i]);
            i++;
        }
        list->number = i;
        return 1;
    }
    return 0;
}

static int parse_uint32_t(const char* expected_cmd, const char* current_cmd, const char* current_value, uint32_t *final_value)
{
    if (!strcmp(current_cmd, expected_cmd))
    {
        *final_value = strtol(current_value, 0, 10);
        LOG_DEBUG("%s: %d", expected_cmd, *final_value);
        return 1;
    }
    return 0;
}

static int parse_string(const char* expected_cmd, const char* current_cmd, const char* current_value, char *final_value)
{
    if (!strcmp(current_cmd, expected_cmd))
    {
        strcpy(final_value, current_value);
        LOG_DEBUG("%s: %s", expected_cmd, final_value);
        return 1;
    }
    return 0;
}



static int load_configuration(void)
{
    LOG_DEBUG("Loading configuration.");

    FILE *fp;
    char *line, *env_conf, *equal;
    char cmd[CONF_ELEM_SIZE] =
    { 0 }, value[CONF_ELEM_ENUM_SIZE] =
    { 0 };
    size_t read, len, linelen, equal_offset;
    uint32_t libtaenia_stateful_max_iterations = 0;
    char afl_output_dir[PATH_MAX];
    tracked_procs = create_proc_list(MAX_TRACKED_PROCS);

    env_conf = getenv("LIBTAENIA_CONF");
    if ((env_conf == NULL))
    {
        LOG_ERROR("No configuration given.");
        return 0;
    }

    fp = fopen(env_conf, "r");
    len = 0;
    while ((read = getline(&line, &len, fp)) != EOF)
    {
        if (line == strstr(line, "#"))
        {
            // Comment.
            continue;
        }
        if ((equal = strstr(line, "=")) != NULL)
        {
            // cmd=value pair
            linelen = strlen(line);
            equal_offset = (size_t) (equal - line);
            if(equal_offset == 0)
            {
                LOG_ERROR("Empty key detected in configuration");
                exit(0);
            }

            if(line[equal_offset + 1] == '\n' || line[equal_offset + 1] == '\0')
            {
                LOG_ERROR("Empty value detected in configuration");
                exit(0);
            }

            if (linelen >= CONF_ELEM_ENUM_SIZE)
            {
                LOG_ERROR("Line too long: %d chars", linelen);
                exit(0);
            }

            memset(cmd, 0, CONF_ELEM_SIZE);
            if (memcpy(cmd, line, equal_offset) != cmd)
            {
                LOG_ERROR("Memcpy error for cmd in configuration.");
                exit(0);
            }

            memset(value, 0, CONF_ELEM_ENUM_SIZE);
            if (memcpy(value, equal + 1, linelen - equal_offset - 2) != value)
            {    // -2 to not get the \n at the end of the line.
                LOG_ERROR("Memcpy error for value in configuration.");
                exit(0);
            }

            // Parsing -------------------------------
            if (parse_uint32_t("replay_minify_mode", cmd, value, &minify_mode))
            {
                continue;
            }
            if (parse_uint32_t("hang_timeout", cmd, value, &libtaenia_hang_timeout))
            {
                continue;
            }
            if (parse_uint32_t("init_timeout", cmd, value, &libtaenia_init_timeout))
            {
                continue;
            }
            if (parse_uint32_t("stateful_max_iterations", cmd, value, &libtaenia_stateful_max_iterations))
            {
                if (libtaenia_stateful_max_iterations)
                    libtaenia_stateful_mode = 1;
                continue;
            }
            if (parse_uint32_t("stop_on_process_crash", cmd, value, &stop_on_process_crash))
            {
                continue;
            }
            if (parse_string("afl_output_filename", cmd, value, afl_input_file))
            {
                continue;
            }
            if (parse_string("afl_output_directory", cmd, value, afl_output_dir))
            {
                continue;
            }
            if(parse_multivalue_line("tracked_processes", cmd, value, tracked_procs))
            {
                continue;
            }
        }
    }

    if (libtaenia_stateful_mode)
    {
        if(tracked_procs->number > 0)
        {
            track_process_mode = 1;
            LOG_INFO("Using stateful mode with process tracking.");
        }
        else
        {
            LOG_INFO("Using stateful mode.");
        }

        init_stateful_mode(afl_output_dir, afl_input_file, libtaenia_stateful_max_iterations);
        
    }
    return 1;
}

static int load_replay_configuration(char *replay_payload_path)
{
    LOG_DEBUG("Loading configuration.");

    FILE *fp;
    char *line, *env_conf, *equal;
    char cmd[CONF_ELEM_SIZE] =
    { 0 }, value[CONF_ELEM_SIZE] =
    { 0 };
    size_t read, len, linelen, equal_offset;

    env_conf = getenv("LIBTAENIA_CONF");
    if ((env_conf == NULL))
    {
        LOG_ERROR("No configuration given.");
        return 0;
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
            // cmd=value pair
            linelen = strlen(line);
            equal_offset = (size_t) (equal - line);

            if(equal_offset == 0)
            {
                LOG_ERROR("Empty key detected in configuration");
                exit(0);
            }

            if(line[equal_offset + 1] == '\n' || line[equal_offset + 1] == '\0')
            {
                LOG_ERROR("Empty value detected in configuration");
                exit(0);
            }
            if (linelen >= CONF_ELEM_ENUM_SIZE)
            {
                LOG_ERROR("Line too long: %d chars", linelen);
            }

            memset(cmd, 0, CONF_ELEM_SIZE);
            if (memcpy(cmd, line, equal_offset) != cmd)
            {
                LOG_ERROR("Memcpy error for cmd.");
            }

            memset(value, 0, CONF_ELEM_SIZE);
            if (memcpy(value, equal + 1, linelen - equal_offset - 2) != value)
            {    // -2 to not get the \n at the end of the line.
                LOG_ERROR("Memcpy error for value.");
            }

            // Parsing -------------------------------
            if (parse_uint32_t("hang_timeout", cmd, value, &libtaenia_hang_timeout))
            {
                continue;
            }
            if (parse_uint32_t("init_timeout", cmd, value, &libtaenia_init_timeout))
            {
                continue;
            }
            if (parse_string("afl_output_filename", cmd, value, afl_input_file))
            {
                continue;
            }
            if (parse_string("replay_payload_path", cmd, value, replay_payload_path))
            {
                continue;
            }
        }
    }
    return 1;
}

#endif /* AFL_TAENIA_QEMU_MODE_PATCHES_AFL_QEMU_TAENIA_CONF_H_ */
