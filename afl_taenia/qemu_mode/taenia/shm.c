/*
 * shm.c
 *
 * Shared memories management module.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>        /* For mode constants */
#include <unistd.h>

#include "shm.h"
#include "taenia_log.h"

/*
 * Get the shared memory.
 */
volatile taenia_shm_t* get_shm()
{
    LOG_DEBUG("get_shm().");
    int fd = 0;
    size_t size = sizeof(taenia_shm_t);

    fd = shm_open(SHM_NAME, O_RDWR | O_CREAT, 0644);
    ftruncate(fd, (off_t)size);

    if (fd <= 0)
    {
        LOG_ERROR("Error opening shm errno: %s (%d).", strerror(errno), errno);
        return NULL;
    }
    volatile taenia_shm_t * shm_ptr = (taenia_shm_t *) mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (shm_ptr == NULL)
    {
        LOG_ERROR("Error mmap shm errno: %s (%d).", strerror(errno), errno);
        return NULL;
    }

    return shm_ptr;
}

