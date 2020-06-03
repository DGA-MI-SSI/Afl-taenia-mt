#include "smart_sample_lib.h"
#include "taenia_log.h"

void smart_parse_lib(char *msg)
{
    if(msg[6] == 'I' && msg[7] == 'B' && msg[8] == 'A')
    {
        LOG_INFO("LIB ABORT !");
        abort();
    }
}
