/*
 * thread_tracking.h
 */

#ifndef AFL_TAENIA_QEMU_MODE_TAENIA_THREAD_TRACKING_H_
#define AFL_TAENIA_QEMU_MODE_TAENIA_THREAD_TRACKING_H_

#include <stdint.h>

void *get_function_address_by_name(char const *modulePath, char const *funcName);
void *get_symbol_address_by_name(char const *funcName);

uint32_t tracked_inputs_number;
uint32_t tracked_threads_number;
uint8_t **tracked_inputs;


uint8_t **make_tracked_inputs();
int track_input(uint8_t *input);
int untrack_input(uint8_t *input);
int track_thread(long int thid);
int untrack_thread_short();
int untrack_thread(long int thid);
int clean_inputs();
int clean_threads();

#endif /* AFL_TAENIA_QEMU_MODE_TAENIA_THREAD_TRACKING_H_ */
