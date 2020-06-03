
#define _GNU_SOURCE

#include <link.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "lib_tracking.h"
#include "../../include/taenia_log.h"
#include "taenia_config.h"


static int log_libs_callback(struct dl_phdr_info *info, size_t size, void *data)
{
    UNUSED(size);
    lib_list *list = (lib_list *) data;

    if(strcmp(info->dlpi_name, ""))
    {
        if(lib_is_in_list(info->dlpi_name, list))
        {
            LOG_INFO("[T] %s", info->dlpi_name);
        }
        else
        {
            LOG_INFO("[ ] %s", info->dlpi_name);
        }
        
    }
    
    return 0;
}

static int get_lib_code_addresses_callback(struct dl_phdr_info *info, size_t size, void *data)
{
    UNUSED(size);
    unsigned int i;
    library *lib = data;

    lib->found = 0;
    
    for (i = 0; i < info->dlpi_phnum; i++)
    {
        if(!strcmp(info->dlpi_name, lib->lib_name))
        {
            /*
            PT_LOAD is a loadable program segment
            flag 5 means a R-X segment -> executable code
            */
            if (info->dlpi_phdr[i].p_type == PT_LOAD && info->dlpi_phdr[i].p_flags == 5)
            {
                lib->start_addr = (unsigned long int) (info->dlpi_addr + info->dlpi_phdr[i].p_vaddr);
                lib->end_addr = (unsigned long int) (info->dlpi_addr + info->dlpi_phdr[i].p_vaddr + info->dlpi_phdr[i].p_memsz);
                lib->found = 1;
                return 1;
            }
        }
        
    }

    return 0;
}

/*
 * Tries to find the start address and end address of the lib executable code
 * Return 0 on success, with start_addr and end_addr set to proper values
 * Return 1 on failure to find the lib, values of start_addr and end_addr are undefined
 */
int get_lib_code_addresses(char *lib_name, unsigned long int  *start_addr, unsigned long int  *end_addr)
{
    library lib;
    lib.lib_name = lib_name;

    dl_iterate_phdr((void*)&get_lib_code_addresses_callback, (void *) &lib);

    if(lib.found)
    {
        *start_addr = lib.start_addr;
        *end_addr = lib.end_addr;
        return 0;
    }
        
    return 1;
}

void log_loaded_libs(lib_list * list)
{
    LOG_INFO("Libraries tracking overview:");
    dl_iterate_phdr((void*)&log_libs_callback, list);
}

int add_lib_to_tracked_libs(volatile taenia_shm_t *shm, char *lib_name)
{
    unsigned long int start_addr, end_addr;
    uint32_t index = shm->libtaenia_tracked_libs_number;

    if(index < MAX_TRACKED_LIBS)
    {
        if(get_lib_code_addresses(lib_name, &start_addr, &end_addr) == 0)
        {
            strncpy((char*)(shm->libtaenia_tracked_libs_names[index]), lib_name, MAX_LIB_NAME_SIZE);
            shm->libtaenia_tracked_libs_start_addresses[index] = start_addr;
            shm->libtaenia_tracked_libs_end_addresses[index] = end_addr;
            shm->libtaenia_tracked_libs_number++;

            LOG_DEBUG("Tracking lib: %d | %s | %14p | %14p", index, lib_name, start_addr, end_addr);

            return 0;
        }
        else
        {
            LOG_ERROR("Could not find library %s", lib_name);
        }
    }
    else
    {
        LOG_ERROR("Maximum number of tracked libs reached");
    }

    return 1;
}

lib_list * create_lib_list()
{
    lib_list *list = (lib_list *) malloc(sizeof(lib_list));
    list->libs = malloc(sizeof(char *) * MAX_TRACKED_LIBS);
    list->number = 0;
    return list;
}

void parse_multivalue_line(char *line, lib_list *list)
{
    char *delim = ", ";
    char *token = strtok(line, delim);
    unsigned int i = 0;
    while(token != NULL && i < MAX_TRACKED_LIBS)
    {
        list->libs[i] = strdup(token);
        token = strtok(NULL, delim);
        i++;
    }
    list->number = i;
}

int lib_is_in_list(const char *lib_name, lib_list *list)
{
    unsigned int i;
    for(i = 0; i < list->number; i++)
    {
        if(!strcmp(list->libs[i], lib_name))
        {
            return 1;
        }
    }
    return 0;
}
