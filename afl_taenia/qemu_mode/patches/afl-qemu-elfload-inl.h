
#include <stdio.h>
#include <stdlib.h>

#include "afl-qemu-taenia-replay.h"

/* ----------------------------------------------------------------------------
 * Configuration parsing
 * ------------------------------------------------------------------------- */

uint8_t taenia_replay_mode;
extern abi_ulong afl_entry_point;

static int parse_address(const char* expected_cmd, const char* current_cmd, const char* current_value, abi_ulong *final_value)
{
    if (!strcmp(current_cmd, expected_cmd))
    {

        *final_value = (abi_ulong) strtol(current_value + 2, NULL, 16);
        LOG_DEBUG("%s: 0x%lx", expected_cmd, *final_value);
        return 1;
    }
    return 0;
}

int conf_preload()
{
    LOG_DEBUG("Loading forkserver entrypoint.");

    FILE *fp;
    char *line, *env_conf, *equal;
    char cmd[CONF_ELEM_SIZE] =
    { 0 }, value[CONF_ELEM_ENUM_SIZE] =
    { 0 }, err[LOG_SIZE] =
    { 0 };
    size_t read, len, linelen, equal_offset;

    env_conf = getenv("LIBTAENIA_CONF");
    if ((env_conf == NULL))
    {
        LOG_ERROR("No configuration given.");
        return 0;
    }

    taenia_replay_mode = getenv("REPLAY_MODE");

    afl_entry_point = 0;
    
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

            if (linelen >= CONF_ELEM_ENUM_SIZE)
            {
                LOG_ERROR("Line too long: %d chars.", linelen);
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

            // Parsing -------------------------------
            if (parse_address("afl_forkserver_start_address", cmd, value, &afl_entry_point))
            {
                continue;
            }
        }
    }
    return 1;
}
