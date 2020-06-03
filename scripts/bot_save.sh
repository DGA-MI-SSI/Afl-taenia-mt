#!/bin/bash
# This script is used to save the output dir from the tmpfs to the disk regularly.

SAVE_OUTPUT=$1

while true
do
    sleep 10
    cp -R /mnt/afl_fs/output/* $SAVE_OUTPUT/
done

