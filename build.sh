#!/bin/bash

echo "#######################"
echo "# Building afl-taenia #"
echo "#######################"
echo ""

function fail {
    echo -e "\e[1m\e[91m[-] COMPILATION ERROR\e[0m"
    exit 0
}


AFL_CFLAGS=""
ARCH=""
LIBTAENIA_CFLAGS=""
TAENIA_OPT_FLAGS="-O3"
SAMPLE_OPT_FLAGS=""    # Default to no optimization (because of hooks)
QEMU_DO_COMPILE=true
QEMU_OPTIONS=""
SAMPLE_CFLAGS=""

# Variable to check options consistency.
THREAD_ONLY_ME=false
THREAD_TRACKING=false
THREAD_LOGS=false

echo "Compilation options: "
while [[ $# -gt 0 ]]
do
option="$1"

case $option in
    -a|--arch)
    case "$2" in
        x86|i386)
        echo "  * Arch: x86"
        ARCH="-m32"
        ;;

        x86_64)
        echo "  * Arch: x86_64"
        ARCH="" # Default on 64 bit machines
        ;;
    esac
    shift
    shift
    ;;

    -d|--debug)
    echo "  * Compile in debug mode."
    AFL_CFLAGS="$AFL_CFLAGS -DDEBUG"
    LIBTAENIA_CFLAGS="$LIBTAENIA_CFLAGS -DDEBUG"
    TAENIA_OPT_FLAGS="-Og -g3"
    SAMPLE_OPT_FLAGS="-Og -g3"
    QEMU_OPTIONS="$QEMU_OPTIONS --debug"
    SAMPLE_CFLAGS="$SAMPLE_CFLAGS -DDEBUG"
    shift
    ;;

    -g|--gdb)
    echo "  * Prepare qemu to listen on port 1234 for gdb."
    QEMU_OPTIONS="$QEMU_OPTIONS --gdb"
    shift
    ;;

    -h|--help)
    echo "Help:"
    echo "  -h --help          : this help."
    echo "  -a --arch          : set arch among: x86, x86_64."
    echo "  -g --gdb           : prepare qemu to listen on port 1234 for gdb."
    echo "  -d --debug         : compile in debug mode."
    echo "  -m --thread-filter : only follow libtaenia's thread."
    echo "  -t --thtrack       : enable the thread tracking."
    echo "  -i --indirect-mode : the target takes its input from the fuzzer instead of the fuzzer providing its inputs directly (useful to fuzz after standard function like recvfrom, memcpy...)."
    echo "  -l --thread-logs   : enable macro logs for the thread-tracking option."
    echo "  -p --debug-path    : compile in order to follow the paths taken by afl."
    echo "  -s --sample <mode> : define complexity mode for smart_sample, mode can be: SIMPLE, SIMPLER, SIMPLEST."
    echo "  -o --core-only     : do not compile qemu (which is pretty long to compile)."
    echo ""
    exit 1
    ;;

    -i|--indirect-mode)
    echo "  * Set to indirect mode."
    LIBTAENIA_CFLAGS="$LIBTAENIA_CFLAGS -DEXECUTION_MODE_INDIRECT_CALL"
    shift
    ;;

    -l|--thread-logs)
    echo "  * Enable macro thread logs."
    LIBTAENIA_CFLAGS="$LIBTAENIA_CFLAGS -DTHREAD_LOGS"
    QEMU_OPTIONS="$QEMU_OPTIONS --thread-logs"
    THREAD_LOGS=true
    shift
    ;;

    -m|--thread-filtering) # Cannot be used with thread-tracking
    echo "  * Only follow libtaenia's thread."
    LIBTAENIA_CFLAGS="$LIBTAENIA_CFLAGS -DTAENIA_MY_THREAD_ONLY"
    QEMU_OPTIONS="$QEMU_OPTIONS --thread-filtering"
    THREAD_ONLY_ME=true
    shift
    ;;

    -o|--core-only)
    echo "  * Do not compile Qemu."
    QEMU_DO_COMPILE=false
    shift
    ;;

    -p|--debug-path)
    echo "  * Compile in order to follow paths taken by afl."
    LIBTAENIA_CFLAGS="$LIBTAENIA_CFLAGS -DTAENIA_DEBUG_PATH"
    AFL_CFLAGS="$AFL_CFLAGS -DTAENIA_DEBUG_PATH"
    QEMU_OPTIONS="$QEMU_OPTIONS --debug-path"
    shift
    ;;

    -s|--sample)
    echo "  * Compile smart_sample with mode $2."
    SAMPLE_CFLAGS="$SAMPLE_CFLAGS -D$2"
    shift
    shift
    ;;

    -t|--thtrack|--thread-tracking)
    echo "  * Compile with thread tracking."
    LIBTAENIA_CFLAGS="$LIBTAENIA_CFLAGS -DTHREAD_TRACKING"
    QEMU_OPTIONS="$QEMU_OPTIONS --thread-tracking"
    THREAD_TRACKING=true
    shift
    ;;

    *)
    echo "[-] Wrong option: $1."
    echo "Use -h or --help to have help."
    echo ""
    exit 1
    ;;
esac
done

# Check options consistencies
if [ $THREAD_ONLY_ME == true ]
then
    if [ $THREAD_TRACKING == true ]
    then
        echo "[-] Cannot follow only libtaenia's thread and track threads."
        echo ""
        exit 1
    fi
fi
if [ $THREAD_TRACKING == false ]
then
    if [ $THREAD_LOGS == true ]
    then
        echo "[-] Cannot log threads without tracking them."
        echo ""
        exit 1
    fi
fi


SCRIPTPATH="$( cd "$(dirname "$0")";pwd -P)"
echo ""
echo ""


echo "====================="
echo "Building smart_sample"
echo "====================="
pushd $SCRIPTPATH/smart_sample
make clean
CFLAGS="$SAMPLE_CFLAGS $SAMPLE_OPT_FLAGS $ARCH" make -j2 || fail
mv libsample.so libs/.
popd
echo ""
echo ""
echo ""


echo "=================="
echo "Building libtaenia"
echo "=================="
pushd $SCRIPTPATH/afl_taenia/qemu_mode/taenia
make clean
CFLAGS="$LIBTAENIA_CFLAGS $TAENIA_OPT_FLAGS $ARCH" make libtaenia -j2 || fail
popd
echo ""
echo ""
echo ""


echo "============"
echo "Building afl"
echo "============"
pushd $SCRIPTPATH/afl_taenia
make clean
CFLAGS=$AFL_CFLAGS make -j8 || fail
popd
echo ""
echo ""
echo ""


if [ $QEMU_DO_COMPILE == true ]
then
    echo "========================="
    echo "Building afl-qemu support"
    echo "========================="
    pushd $SCRIPTPATH/afl_taenia/qemu_mode
    if [ "$ARCH" == "-m32" ]
    then
        CPU_TARGET="i386" ./build_qemu_support.sh $QEMU_OPTIONS
    else
        ./build_qemu_support.sh $QEMU_OPTIONS || fail
    fi
    popd
fi

echo "======================"
exit 0
