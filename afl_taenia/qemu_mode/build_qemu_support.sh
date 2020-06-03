#!/bin/bash
#
# american fuzzy lop - QEMU build script
# --------------------------------------
#
# Written by Andrew Griffiths <agriffiths@google.com> and
#            Michal Zalewski <lcamtuf@google.com>
#
# Copyright 2015, 2016, 2017 Google Inc. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# This script downloads, patches, and builds a version of QEMU with
# minor tweaks to allow non-instrumented binaries to be run under
# afl-fuzz. 
#
# The modifications reside in patches/*. The standalone QEMU binary
# will be written to ../afl-qemu-trace.
#


VERSION="3.1.1"
QEMU_URL="http://download.qemu-project.org/qemu-${VERSION}.tar.xz"
QEMU_SHA384="68216c935487bc8c0596ac309e1e3ee75c2c4ce898aab796faa321db5740609ced365fedda025678d072d09ac8928105"

echo "================================================="
echo "AFL binary-only instrumentation QEMU build script"
echo "================================================="
echo

QFLAGS=""
USE_GDB=false
USE_THREAD_TRACKING=false

echo "Compilation options: "
while [[ $# -gt 0 ]]
do
option="$1"

case $option in
    -d|--debug)
    echo "  * Compile in debug."
    QFLAGS="$QFLAGS -DTAENIA_DEBUG"
    shift
    ;;

    -g|--gdb)
    echo "  * Prepare qemu for gdb."
    USE_GDB=true
    shift
    ;;

    -l|--thread-logs)
    echo "  * Enable macro thread logs."
    QFLAGS="$QFLAGS -DTAENIA_THREAD_LOGS"
    shift
    ;;

    -m|--thread-filtering)
    echo "  * Only follow libtaenia's thread."
    QFLAGS="$QFLAGS -DTAENIA_MY_THREAD_ONLY"
    shift
    ;;
 
    -p|--debug-path)
    echo "  * Compile in order to debug paths."
    QFLAGS="$QFLAGS -DTAENIA_DEBUG_PATH"
    shift
    ;;

    -t|--thtrack|--thread-tracking)
    echo "  * Compile with thread tracking."
    QFLAGS="$QFLAGS -DTAENIA_THREAD_TRACKING"
    USE_THREAD_TRACKING=true
    shift
    ;;

    *)
    echo "Wrong option: $1"
    shift
    ;;
esac
done

# This is used for the shared memory between libtaenia and qemu. We must do so because they must exchange data of the same type.
# Qemu is assumed to work on 64-bit.
if [ "$CPU_TARGET" == "i386" ]
then
    QFLAGS="$QFLAGS -DTAENIA_X86"
else
    # Default on 64-bit.
    QFLAGS="$QFLAGS -DTAENIA_AMD64"
fi
echo "  => QFLAGS=$QFLAGS"


echo ""
echo "[*] Performing basic sanity checks..."

if [ ! "`uname -s`" = "Linux" ]; then

  echo "[-] Error: QEMU instrumentation is supported only on Linux."
  exit 0

fi

if [ ! -f "patches/afl-qemu-cpu-inl.h" -o ! -f "../include/config.h" ]; then

  echo "[-] Error: key files not found - wrong working directory?"
  exit 0

fi

if [ ! -f "../afl-showmap" ]; then

  echo "[-] Error: ../afl-showmap not found - compile AFL first!"
  exit 0

fi


#for i in libtool python automake autoconf bison; do
##for i in libtool wget python automake autoconf sha384sum bison iconv; do
#
#  T=`which "$i" 2>/dev/null`
#
#  if [ "$T" = "" ]; then
#
#    echo "[-] Error: '$i' not found, please install first."
#    exit 0
#
#  fi
#
#done

if [ ! -d "/usr/include/glib-2.0/" -a ! -d "/usr/local/include/glib-2.0/" ]; then

  echo "[-] Error: devel version of 'glib2' not found, please install first."
  exit 0

fi

if echo "$CC" | grep -qF /afl-; then

  echo "[-] Error: do not use afl-gcc or afl-clang to compile this tool."
  exit 0

fi

echo "[+] All checks passed!"

ARCHIVE="`basename -- "$QEMU_URL"`"
# We already have the archive.
#CKSUM=`sha384sum -- "$ARCHIVE" 2>/dev/null | cut -d' ' -f1`
#
#if [ ! "$CKSUM" = "$QEMU_SHA384" ]; then
#
#  echo "[*] Downloading QEMU ${VERSION} from the web..."
#  rm -f "$ARCHIVE"
#  wget -O "$ARCHIVE" -- "$QEMU_URL" || exit 0
#
#  CKSUM=`sha384sum -- "$ARCHIVE" 2>/dev/null | cut -d' ' -f1`
#
#fi
#
#if [ "$CKSUM" = "$QEMU_SHA384" ]; then
#
#  echo "[+] Cryptographic signature on $ARCHIVE checks out."
#
#else
#
#  echo "[-] Error: signature mismatch on $ARCHIVE (perhaps download error?)."
#  exit 0
#
#fi
#

echo "[*] Uncompressing archive (this will take a while)..."

rm -rf "qemu-${VERSION}" || exit 0
tar xf "$ARCHIVE" || exit 0

echo "[+] Unpacking successful."

echo "[*] Configuring QEMU for $CPU_TARGET..."

ORIG_CPU_TARGET="$CPU_TARGET"

test "$CPU_TARGET" = "" && CPU_TARGET="`uname -m`"
test "$CPU_TARGET" = "i686" && CPU_TARGET="i386"

cd qemu-$VERSION || exit 0

echo "[*] Applying patches..."

patch -p1 <../patches/elfload.diff || exit 0
patch -p1 <../patches/cpu-exec.diff || exit 0
patch -p1 <../patches/syscall.diff || exit 0
patch -p1 <../patches/translate-all.diff || exit 0
patch -p1 <../patches/tcg.diff || exit 0
patch -p1 <../patches/i386-translate.diff || exit 0
patch -p1 <../patches/arm-translate.diff || exit 0

echo "[+] Patching done."

# --enable-pie seems to give a couple of exec's a second performance
# improvement, much to my surprise. Not sure how universal this is..

#CFLAGS="-O3 -ggdb $QFLAGS" ./configure --disable-system \
CFLAGS="-O0 -ggdb $QFLAGS" ./configure --disable-system \
  --enable-linux-user --disable-gtk --disable-sdl --disable-vnc \
  --target-list="${CPU_TARGET}-linux-user" --enable-pie --enable-kvm || exit 0

echo "[+] Configuration complete."

echo "[*] Attempting to build QEMU (fingers crossed!)..."

make -j8 || exit 0

echo "[+] Build process successful!"

echo "[*] Copying binary..."

cp -f "${CPU_TARGET}-linux-user/qemu-${CPU_TARGET}" "../../afl-qemu-trace" || exit 0

cd ..
ls -l "../afl-qemu-trace" || exit 0

if [ $USE_GDB == true ]
then
	# Copy the bash wrapper for the -g option of qemu.
	mv ../afl-qemu-trace ../afl-qemu-trace-bin
	cp afl-qemu-trace-gdb ../afl-qemu-trace
fi

echo "[+] Successfully created ../afl-qemu-trace."

if [ $USE_THREAD_TRACKING == true ]
then
	echo "[!] Note: compiled in thread tracking mode, can't test instrumentation."
	exit 0
fi

if [ "$ORIG_CPU_TARGET" = "" ]; then

  echo "[*] Testing the build..."

  cd ..

#  make >/dev/null || exit 0

  gcc test-instr.c -o test-instr || exit 0

  unset AFL_INST_RATIO

  echo 0 | ./afl-showmap -m none -Q -q -o .test-instr0 ./test-instr || exit 0
  echo 1 | ./afl-showmap -m none -Q -q -o .test-instr1 ./test-instr || exit 0

  rm -f test-instr

  cmp -s .test-instr0 .test-instr1
  DR="$?"

  rm -f .test-instr0 .test-instr1

  if [ "$DR" = "0" ]; then

    echo "[-] Error: afl-qemu-trace instrumentation doesn't seem to work!"
    exit 0

  fi

  echo "[+] Instrumentation tests passed. "
  echo "[+] All set, you can now use the -Q mode in afl-fuzz!"

else

  echo "[!] Note: can't test instrumentation when CPU_TARGET set."
  echo "[+] All set, you can now (hopefully) use the -Q mode in afl-fuzz!"

fi

exit 1
