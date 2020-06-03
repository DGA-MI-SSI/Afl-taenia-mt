#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <unistd.h>

#include "proc_smart_sample.h"

#include "taenia_log.h"


void parse(const char *msg)
{
    LOG_INFO("Proc abort on %s.", msg);
    abort();
}

int main()
{
    char msg[7];
    while(1)
    {
        FILE *interprocess_channel = fopen("/tmp/interprocess_channel", "rb+");
        if(interprocess_channel == NULL)
        {
            LOG_DEBUG("interprocess_channel NULL");
        }
        else
        {
            fread(msg, 7, sizeof(char), interprocess_channel);
            fclose(interprocess_channel);
            parse(msg);
        }
        usleep(100000);
    }
    
    return 0;
}
