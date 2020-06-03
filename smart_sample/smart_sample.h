/*
 * smart_sample.h
 *
 *  Created on: Oct 14, 2019
 *      Author: user
 */

#ifndef SMART_SAMPLE_H_
#define SMART_SAMPLE_H_


// Defines
#define BUFFER_SIZE 512
#define FIFO_SIZE 10

// Fifo
struct Fifo
{
    unsigned int space;
    unsigned int storage;
    unsigned int read_index;
    unsigned int write_index;
    char* data;
};

// Functions
void *smart_parser_task();
int smart_parse(char* msg);

void *smart_broker_task();
int smart_broke(char* msg);

void interprocess_communication(const char *msg);

void *noise_task();
int make_some_noise(int seed);

int init_fifo();
int fifo_read(char* buffer);
int fifo_write(char* buffer);

int very_long_init();
int init_threads();

#endif /* SMART_SAMPLE_H_ */
