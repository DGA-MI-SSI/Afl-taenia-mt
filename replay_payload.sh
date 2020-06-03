#!/bin/bash

if [ $# -ne 1 ] 
then
    printf "Usage: ./replay_payload.sh <configuration file>\n"
    exit 1
fi

# Launch fuzzer

echo "---- Run payload replay ----"

SCRIPTPATH="$( cd "$(dirname "$0")";pwd -P)"
LIB_PATH="$SCRIPTPATH/smart_sample"
CONF=$1

# Conf parsing
source conf_parser.sh
parse_config_file $CONF
# All variable in this tab must be set for AFL to work
readonly -a tab_mandatory=( "replay_qemu_binary" "replay_taenia_library" "replay_payload_path" "replay_target" "afl_output_filename")
validate_mandatory_variables

# Mandatory arguments
QEMU="${tab_conf["replay_qemu_binary"]}"
LIBTAENIA="${tab_conf["replay_taenia_library"]}"
PROG=" -- ${tab_conf["replay_target"]}"

# Cleaning process that might still be there from previous execution
killall -9 -q afl-fuzz afl-qemu-trace
killall -9 -q $PROG

# Set LD_PRELOAD for Qemu with libtaenia
echo "export QEMU_SET_ENV=LD_PRELOAD=$LIBTAENIA,TAENIA_CONF=$CONF"
export QEMU_SET_ENV="LD_PRELOAD=$LIBTAENIA,TAENIA_CONF=$CONF,LD_LIBRARY_PATH=$LIB_PATH"
export "LIBTAENIA_CONF=$CONF"
export REPLAY_MODE=1

# Running AFL
echo $QEMU $PROG
echo "------------------------"
echo ""
$QEMU $PROG