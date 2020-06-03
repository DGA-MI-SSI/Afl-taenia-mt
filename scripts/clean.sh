#!/bin/bash

# This script clean everything, in the case of a crash.

killall -9 -q afl-fuzz
killall -9 -q afl-qemu-trace
killall -9 -q afl-qemu-trace-bin
killall -9 -q bot_save.sh

rm -R /mnt/afl_fs/*
rm -R smart_sample/output
