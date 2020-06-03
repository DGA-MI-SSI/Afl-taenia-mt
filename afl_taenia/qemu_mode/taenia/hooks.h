/*
 * hooks_with_calls.h
 *
 *  Created on: Nov 6, 2019
 *      Author: user
 */

#ifndef AFL_TAENIA_QEMU_MODE_TAENIA_HOOKS_H_
#define AFL_TAENIA_QEMU_MODE_TAENIA_HOOKS_H_

#include <stdint.h>

#ifdef EXECUTION_MODE_INDIRECT_CALL
extern uint8_t indirect_mode_first_take;
extern uint8_t *indirect_mode_target_input;
extern pthread_mutex_t indirect_mutex_need_input;
extern pthread_mutex_t indirect_mutex_need_execution;

#endif

int add_hooks(char *targeted_lib);

#endif /* AFL_TAENIA_QEMU_MODE_TAENIA_HOOKS_H_ */
