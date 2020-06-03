#ifndef AFL_TAENIA_QEMU_MODE_TAENIA_LIB_TRACKING_H_
#define AFL_TAENIA_QEMU_MODE_TAENIA_LIB_TRACKING_H_

#include "shm.h"

typedef struct 
{
    char* lib_name;
    unsigned long int  start_addr;
    unsigned long int   end_addr;
    int found;
} library;


typedef struct
{
    char **libs;
    unsigned int number;
} lib_list;

int get_lib_code_addresses(char *lib_name, unsigned long int  *start_addr, unsigned long int  *end_addr);
int add_lib_to_tracked_libs(volatile taenia_shm_t *shm, char *lib_name);
void log_loaded_libs(lib_list *list);
lib_list * create_lib_list();
void parse_multivalue_line(char *line, lib_list *list);
int lib_is_in_list(const char *lib_name, lib_list *list);

#endif /* AFL_TAENIA_QEMU_MODE_TAENIA_LIB_TRACKING_H_ */
