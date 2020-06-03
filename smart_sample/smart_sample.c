/*
 * smart_sample.c
 *
 *  Created on: Oct 14, 2019
 *      Author: user
 */


#include <arpa/inet.h>
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "smart_sample.h"
#include "taenia_log.h"

/* ----------------------------------------------------------------------------
 * Parser thread
 * --------------------------------------------------------------------------*/

static uint8_t first_step = 0;

void *smart_parser_task()
{
    LOG_DEBUG("Parser starting.");
    char buf[BUFFER_SIZE];
    while (1)
    {
        memset(buf, 0, BUFFER_SIZE);
        fifo_read(buf);
        smart_parse(buf);
#ifdef SIMPLER
        return NULL;
#endif
    }

    return NULL;
}

int smart_parse(char* msg)
{
    
    LOG_DEBUG("Smart_parse: parsing message: %s", msg);
    size_t len = strlen(msg);
    if (len < 9)
    {
        LOG_DEBUG("Wrong size: too short.");
        return 0;
    }
    if (len > 20)
    {
        LOG_DEBUG("Wrong size: too long.");
        return 0;
    }

    // First a magic number.
    if (!(msg[0] == 'M' && msg[1] == 'A' && msg[2] == 'G' && msg[3] == 'I'
            && msg[4] == 'C'))
    {
        LOG_DEBUG("Wrong magic.");
        return 1;
    }

    // Then a type.
    switch (msg[5])
    {
    case 'A': // Historic error message.
        switch (msg[6])
        {
        case 'L':
            // Everything is fine.
            LOG_DEBUG("Everything is fine.");
            break;
        case 'B':
            if (msg[7] == 'R' && msg[8] == 'T')
            {
                LOG_INFO("ABORT ! ABORT ! ABORT !");
                abort();
            }
            LOG_DEBUG("Almost abort.\n");
            break;
        case 'H':
            if (msg[7] == 'N' && msg[8] == 'G')
            {
                LOG_INFO("Simulating hang !");
                while (1)
                {
                    sleep(1);
                }
            }
            LOG_DEBUG("Almost hang.");
            break;
        default:
            // Wrong type.
            return 2;
            LOG_DEBUG("Default.");
        }
        break;
    case 'O': // A stateful bug
        if (msg[6] == 'O')
        {
            if (msg[7] == 'L' && msg[8] == '!') {
                first_step = 1;
            }
            if (msg[7] == 'P' && msg[8] == 'S') {
                if (first_step)
                {
                    LOG_INFO("STATEFUL ABORT!");
                    abort();
                }
            }

        }
        break;
    //case 'P':
    //    interprocess_communication(msg);
        break;
    default:
        LOG_DEBUG("Wrong type.");
        return 2;
    }
    return 0;
}

void interprocess_communication(const char *msg)
{
    size_t len = strlen(msg);
    FILE *interprocess_channel = fopen("/tmp/interprocess_channel", "wb+");
    if(interprocess_channel == NULL)
    {
        LOG_DEBUG("Could not open interprocess channel file");
    }
    else
    {
        fwrite(msg, len, sizeof(char), interprocess_channel);
        fclose(interprocess_channel);
    }

}

/* ----------------------------------------------------------------------------
 * Broker thread.
 * --------------------------------------------------------------------------*/
void *smart_broker_task()
{
    LOG_DEBUG("Broker starting.");
    // Setting sockets.
    int sock, csock;
    struct sockaddr caddr;
    struct sockaddr_in addr;
    char buffer[BUFFER_SIZE] =
    { 0 };

    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) == -1)
    {
        LOG_ERROR("Socket error: %s (%d).", strerror(errno), errno);
        goto END;
    }

    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &addr, sizeof(addr)) == -1)
    {
        LOG_ERROR("Set socket option error: %s (%d).", strerror(errno), errno);
        goto END;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(8080);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(sock, (struct sockaddr*) &addr, sizeof(addr)) == -1)
    {
        LOG_ERROR("Bind error: %s (%d).", strerror(errno), errno);
        goto END;
    }

    if (listen(sock, 5) == -1)
    {
        LOG_ERROR("Listen error: %s (%d).", strerror(errno), errno);
        goto END;
    }

    while (1)
    {
        // Accepting connections
        unsigned int caddr_size = sizeof(caddr);
        LOG_DEBUG("Waiting for data.");
        if((csock = accept(sock, (struct sockaddr*) &caddr, &caddr_size)) == -1)
        {
            LOG_ERROR("accept error: %s (%d).", strerror(errno), errno);
            continue;
        }
        LOG_DEBUG("Connection accepted.");

        while (1)
        {
           // Receiving data.
           if (recv(csock, buffer, BUFFER_SIZE, 0) == -1)
            {
                LOG_ERROR("recv error: %s (%d).", strerror(errno), errno);
                goto KILL;
            }
            LOG_DEBUG("Data received: %s.", buffer);
            smart_broke(buffer);
        }

        KILL: close(csock);
    }

    END: close(sock);
    return NULL;
}

int smart_broke(char* buffer)
{
    LOG_DEBUG("Smart_broke: adding message.");
    fifo_write(buffer);
    return 1;
}

/* ----------------------------------------------------------------------------
 * Noise thread
 * --------------------------------------------------------------------------*/
void *noise_task()
{
    LOG_DEBUG("Noise starting.");
    while (1)
    {
        make_some_noise(rand());
    }
    return NULL;
}

int make_some_noise(int seed)
{
    uint32_t value = 0;

    switch (seed % 5)
    {
    case 0:
        value = 3;
        break;
    case 1:
        value = 1;
        break;
    case 2:
        value = 4;
        break;
    case 3:
        value = 1;
        break;
    case 4:
        value = 5;
        break;
    }

    switch ((seed / 5) % 5)
    {
    case 0:
        value += 9;
        break;
    case 1:
        value += 2;
        break;
    case 2:
        value += 6;
        break;
    case 3:
        value += 5;
        break;
    case 4:
        value += 3;
        break;
    }

    switch ((seed / 25) % 5)
    {
    case 0:
        value = value * 5;
        break;
    case 1:
        value = value * 8;
        break;
    case 2:
        value = value * 9;
        break;
    case 3:
        value = value * 7;
        break;
    case 4:
        value = value * 9;
        break;
    }

    switch ((seed / 725) % 5)
    {
    case 0:
        value = value / 3;
        break;
    case 1:
        value = value / 2;
        break;
    case 2:
        value = value / 3;
        break;
    case 3:
        value = value / 8;
        break;
    case 4:
        value = value / 4;
        break;
    }

    switch ((seed / (725 * 5)) % 5)
    {
    case 0:
        value = value ^ 383;
        break;
    case 1:
        value = value ^ 279;
        break;
    case 2:
        value = value ^ 502;
        break;
    case 3:
        value = value ^ 884;
        break;
    case 4:
        value = value ^ 197;
        break;
    }

    switch (value % 5)
    {
    case 0:
        return 6;
    case 1:
        return 2;
    case 2:
        return 6;
    case 3:
        return 4;
    case 4:
        return 3;
    }
    return 3;
}

/* ----------------------------------------------------------------------------
 * Fifos management
 * --------------------------------------------------------------------------*/
struct Fifo* main_fifo;

int init_fifo()
{
    if ((main_fifo = malloc(4 * sizeof(unsigned int) + sizeof(char *))) == NULL)
    {
        LOG_ERROR("Malloc error.");
        return 0;
    }
    main_fifo->space = FIFO_SIZE;
    main_fifo->storage = 0;
    main_fifo->read_index = 0;
    main_fifo->write_index = 0;
    if ((main_fifo->data = malloc(BUFFER_SIZE * FIFO_SIZE * sizeof(char))) == NULL)
    {
        LOG_ERROR("Malloc error.");
        return 0;
    }
    if (!memset(main_fifo->data, 0, BUFFER_SIZE * FIFO_SIZE * sizeof(char)))
    {
        LOG_ERROR("Memset error.");
        return 0;
    }
    LOG_DEBUG("Fifo init done.");
    return 1;
}

int destroy_fifo()
{
    free(main_fifo->data);
    free(main_fifo);
    main_fifo = NULL;
    LOG_DEBUG("Fifo destroyed.");
    return 1;
}

int fifo_write(char* buffer)
{
    LOG_DEBUG("fifo_write: %d space", main_fifo->space);

    // Waiting for the fifo to have space before writing the received buffer in it.
    while (main_fifo->space <= 0)
    {
        usleep(1);
    }
    if (!memcpy(main_fifo->data + main_fifo->write_index * BUFFER_SIZE, buffer,
            BUFFER_SIZE))
    {
        LOG_ERROR("Copy error.");
        exit(0);
    }
    main_fifo->write_index = (main_fifo->write_index + 1) % FIFO_SIZE;
    main_fifo->space--;
    main_fifo->storage++;
    return 1;
}

int fifo_read(char* buffer)
{
    LOG_DEBUG("fifo_read: %d storage", main_fifo->storage);

    // Waiting for the fifo to have data before reading it.
    while (main_fifo->storage <= 0)
    {
        usleep(1);
    }
    if (!memcpy(buffer, main_fifo->data + main_fifo->read_index * BUFFER_SIZE,
            BUFFER_SIZE))
    {
        LOG_ERROR("Copy error.");
        exit(0);
    }
    if (!memset(main_fifo->data + main_fifo->read_index * BUFFER_SIZE, 0,
            BUFFER_SIZE * sizeof(char)))
    {
        LOG_ERROR("Cleaning error.");
        exit(0);
    }
    main_fifo->read_index = (main_fifo->read_index + 1) % FIFO_SIZE;
    main_fifo->space++;
    main_fifo->storage--;
    return 1;
}

#ifdef DEBUG
void fifo_log()
{
    LOG_DEBUG("space: %d, storage: %d, read_index: %d, write_index: %d", main_fifo->space, main_fifo->storage, main_fifo->read_index, main_fifo->write_index);
    for(uint16_t i = 0; i < main_fifo->storage; i++)
    {
        raw_log(main_fifo->data + main_fifo->read_index + i);
    }
}
#endif

/* ----------------------------------------------------------------------------
 * Main thread
 * --------------------------------------------------------------------------*/
int very_long_init()
{
    LOG_DEBUG("Very long init.");
    sleep(2);
    LOG_DEBUG("Init done.");
    return 1;
}

int init_threads()
{
    LOG_DEBUG("Init threads.");
    pthread_t parser_t = 0, broker_t = 0, noise_t = 0;
    if (pthread_create(&broker_t, 0, smart_broker_task, 0)) {
        LOG_ERROR("Pthread_create of smart_broker_task failed.");
        exit(0);
    }
    if (pthread_create(&parser_t, 0, smart_parser_task, 0)) {
        LOG_ERROR("Pthread_create of smart_parser_task failed.");
        exit(0);
    }
    if (pthread_create(&noise_t, 0, noise_task, 0)) {
        LOG_ERROR("Pthread_create of noise_task failed.");
        exit(0);
    }

    if (broker_t) pthread_join(broker_t, 0);
    if (parser_t) pthread_join(parser_t, 0);
    if (noise_t) pthread_join(noise_t, 0);
    return 1;
}

int main()
{
    LOG_DEBUG("Smart sample launched.");
#ifdef SIMPLEST
    // Direct smart_parse
    char buf[128];
    read(0, buf, 128);
    smart_parse(buf);

#elif defined(SIMPLER)
    // Indirect smart_parse
    // With useless threads
    srand((unsigned int)time(NULL));
    pthread_t parser_t = 0, noise_t = 0;
    if (pthread_create(&noise_t, 0, noise_task, 0)) {
        LOG_ERROR("Pthread_create of noise_task failed.");
        exit(0);
    }
    if (!init_fifo())
    {
        LOG_ERROR("Init fifo error.");
        exit(0);
    }
    if (pthread_create(&parser_t, 0, smart_parser_task, 0)) {
        LOG_ERROR("Pthread_create of smart_parser_task failed.");
        exit(0);
    }

    char buf[128];
    read(0, buf, 128);
    smart_broke(buf);

    if (parser_t) pthread_join(parser_t, 0);
    if (!destroy_fifo())
    {
        LOG_ERROR("Destroy fifo error.");
        exit(0);
    }

#else
    LOG_DEBUG("Target started in debug mode.");
    LOG_DEBUG("Smart_broke is at %p.", &smart_broke);
    srand((unsigned int)time(NULL));
    if (!very_long_init())
    {
        LOG_ERROR("Very long init error.");
        exit(0);
    }
    srand((unsigned int)(time(NULL)));
    if (!init_fifo())
    {
        LOG_ERROR("Init fifo error.");
        exit(0);
    }
    if (!init_threads())
    {
        LOG_ERROR("Init threads error.");
        exit(0);
    }
    if (!destroy_fifo())
    {
        LOG_ERROR("Destroy fifo error.");
        exit(0);
    }
#endif
    return 1;
}
