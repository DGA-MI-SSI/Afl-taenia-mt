#!/bin/bash

if [ $# -lt 1 ] 
then
    printf "Usage: ./run.sh <configuration file>\n"
    exit 1
fi

# Functions

function fail {
    echo -e "\e[1m\e[91m[-] SCRIPT ERROR :\e[0m $1"
    exit 0
}

echo -e "\e[1m[+] AFL-TAENIA\e[0m"
echo "    Usage: ./run.sh <configuration file> {continue}"

# Clean logs
echo -e "\e[1m\e[92m[+]\e[0m Cleaning logs."
echo "" > /dev/shm/afl_debug
echo "" > /dev/shm/afl_debug_path


SCRIPTPATH="$( cd "$(dirname "$0")";pwd -P)"
CONF=$1

# Conf parsing
source conf_parser.sh
parse_config_file $CONF
# All variable in this tab must be set for AFL to work
readonly -a tab_mandatory=( "afl_binary" "afl_taenia_library" "afl_input_directory" "afl_output_directory" "afl_output_filename" "afl_target" )
validate_mandatory_variables


STATIC_ARGS="-Q"

# Mandatory arguments
AFL="${tab_conf["afl_binary"]}"
LIBTAENIA="${tab_conf["afl_taenia_library"]}"
INPUT="${tab_conf["afl_input_directory"]}"
OUTPUT="${tab_conf["afl_output_directory"]}"
FILE="${tab_conf["afl_output_filename"]}"
PROG="${tab_conf["afl_target"]}"
LIB_PATH="${tab_conf["afl_target_libs_dir"]}"

CONTINUE=false
AFL_ARGS=""
# Command line options
shift
while [[ $# -gt 0 ]]
do
option="$1"

case $option in
    -a|--calibrate)
    echo -e "\e[1m\e[92m[+]\e[0m Calibrate only."
    AFL_ARGS="-a"
    shift
    ;;

    -c|--continue)
    echo -e "\e[1m\e[92m[+]\e[0m Continue the previous fuzzing session."
    CONTINUE=true
    INPUT="-"
    shift
    ;;

    *)
    echo "[-] Wrong option: $1."
    echo "Use -h or --help to have help."
    echo ""
    exit 0
    ;;
esac
done


# Cleaning process that might still be there from previous execution.
function cleanup {
    killall -9 -q scripts/bot_save.sh
    killall -9 -q afl-fuzz afl-qemu-trace afl-qemu-trace-bin
    killall -9 -q $PROG
    echo -e "\e[1m\e[92m[+]\e[0m Processus cleaned."
}
cleanup
trap cleanup EXIT


# Optional arguments
if [ -n "${tab_conf["afl_target_args"]}" ]
then
    PROG_ARGS="${tab_conf["afl_target_args"]}"
else
    PROG_ARGS=""
fi

if [ -n "${tab_conf["afl_memory"]}" ]
then
    AFL_ARGS="$AFL_ARGS -m ${tab_conf["afl_memory"]}"
fi

if [ -n "${tab_conf["afl_power_schedule"]}" ]
then
    POWER_SCHEDULE=" -p ${tab_conf["afl_power_schedule"]}"
else
    POWER_SCHEDULE=""
fi

if [ -n "${tab_conf["afl_debug_child_output"]}" ]
then
    if [ ${tab_conf["afl_debug_child_output"]} == 1 ]
    then
        export AFL_DEBUG_CHILD_OUTPUT=${tab_conf["afl_debug_child_output"]}
    fi
fi

if [ -n "${tab_conf["max_input_size"]}" ]
then
    export AFL_MAX_INPUT_SIZE=${tab_conf["max_input_size"]}
fi

# Setting tmpfs file system
if [ -n "${tab_conf["afl_use_tmpfs"]}" ] && [ "${tab_conf["afl_use_tmpfs"]}" == "1" ]
then
    touch /mnt/afl_fs || fail "Permission denied.\n    Please setup the tmpfs filesystem first, you may use the following commands (as root):\n      mkdir -p /mnt/afl_fs\n      mount -t tmpfs -o size=512m tmpfs /mnt/afl_fs/"

    # Cleaning
    rm -R /mnt/afl_fs/*

    # Pushing input and output on the tmpfs.
    mkdir /mnt/afl_fs/input/ 2>/dev/null
    rm /mnt/afl_fs/input/*

    mkdir /mnt/afl_fs/output/ 2>/dev/null
    if [ $CONTINUE == true ]
    then
        rm /mnt/afl_fs/output/*
        cp -R ${tab_conf["afl_output_directory"]}/* /mnt/afl_fs/output/
    else
        cp -R ${tab_conf["afl_input_directory"]}/* /mnt/afl_fs/input/
        INPUT="/mnt/afl_fs/input"

        # Clean output
        rm -R ${tab_conf["afl_output_directory"]}
    fi
    OUTPUT="/mnt/afl_fs/output"

    # Pushing all interested binaries and libs on the tmpfs.
    cp ${tab_conf["afl_taenia_library"]} /mnt/afl_fs/
    LIBTAENIA=/mnt/afl_fs/$(echo "mnt/afl_fs/${tab_conf["afl_taenia_library"]}" | grep -o '[^/]*$')

    cp ${tab_conf["afl_target"]} /mnt/afl_fs/
    PROG=/mnt/afl_fs/$(echo "${tab_conf["afl_target"]}" | grep -o '[^/]*$')
    cp ${tab_conf["afl_target_libs_dir"]}/* /mnt/afl_fs/

    # Saving outputs from the tmpfs to the disk
    mkdir ${tab_conf["afl_output_directory"]} 2>/dev/null
    ./scripts/bot_save.sh ${tab_conf["afl_output_directory"]} &
    echo -e "\e[1m\e[92m[+]\e[0m Use a tmpfs to increase perfs!"
fi

if [ -n "${tab_conf["afl_libdislocator"]}" ]
then
    export "AFL_PRELOAD=./${tab_conf["afl_libdislocator"]}"
    echo -e "\e[1m\e[92m[+]\e[0m Export AFL_PRELOAD=./${tab_conf["afl_libdislocator"]}"
fi

# Set LD_PRELOAD for Qemu with libtaenia
export QEMU_SET_ENV="LD_PRELOAD=$LIBTAENIA,LIBTAENIA_CONF=$CONF,LD_LIBRARY_PATH=$LD_LIBRARY_PATH:$LIB_PATH"
echo -e "\e[1m\e[92m[+]\e[0m export QEMU_SET_ENV=LD_PRELOAD=$LIBTAENIA,LIBTAENIA_CONF=$CONF,LD_LIBRARY_PATH=$LD_LIBRARY_PATH:$LIB_PATH"
export "LIBTAENIA_CONF=$CONF"
echo -e "\e[1m\e[92m[+]\e[0m export LIBTAENIA_CONF=$CONF"
export "LD_LIBRARY_PATH=$LD_LIBRARY_PATH:$LIB_PATH"
echo -e "\e[1m\e[92m[+]\e[0m export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:$LIB_PATH"

# Running AFL
echo -e "\e[1m\e[92m[+]\e[0m Execute $AFL $STATIC_ARGS -i $INPUT -o $OUTPUT $AFL_ARGS -f $FILE $POWER_SCHEDULE -- $PROG $PROG_ARGS"
$AFL $STATIC_ARGS -i $INPUT -o $OUTPUT $AFL_ARGS -f $FILE $POWER_SCHEDULE -- $PROG $PROG_ARGS

