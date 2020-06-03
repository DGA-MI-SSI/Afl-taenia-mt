#!/bin/bash

# This script prints the inputs saved by afl (hangs, crashes, queued inputs) in a readable way.
# $1: time between refresh
# $2: output dir


function print_queue {
    i=1
    for f in $(ls $1 | grep -v "README"); do
        echo "  $i ($(tr -d '\0' < $1/$f | wc -c)): $(tr -d '\0' < $1/$f)"
        i=$((i+1))
    done
}

j=0
t=10
if [ $# -eq 1 ]
then
    t=$1
fi

pushd $2
while true
do
    echo "---- $((j*t))s -----"
    echo "* crashes"
    print_queue crashes
    echo "* hangs"
    print_queue hangs
    echo "* queue"
    print_queue queue
    j=$((j+1))
    sleep $t
done

popd
