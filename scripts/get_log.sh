#!/bin/bash


echo "tail -f /dev/shm/afl_debug"
touch /dev/shm/afl_debug
tail -f /dev/shm/afl_debug
