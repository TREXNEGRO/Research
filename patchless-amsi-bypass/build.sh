#!/usr/bin/env bash
# Cross-compile the patchless AMSI / ETW HW BP test binary from Linux to
# Windows x64 via mingw-w64.
#
# Output:  bin/patchless-amsi-test.exe
#
# Authorised testing only.

set -e
cd "$(dirname "$0")"

CC="${CC:-x86_64-w64-mingw32-gcc}"
mkdir -p bin

CFLAGS="-Wall -Wextra -Wno-unused-parameter -O2 -DNDEBUG \
        -Iinclude -Isrc \
        -fno-stack-protector \
        -static-libgcc"
LDFLAGS="-lkernel32 -luser32 -lpsapi"

SRCS=(
    src/helpers.c
    src/veh_manager.c
    src/amsi_hwbp.c
    src/etw_hwbp.c
    src/bypass_main.c
    tests/test_minimal.c
)

echo "[*] Compiling with $CC ..."
"$CC" $CFLAGS "${SRCS[@]}" $LDFLAGS -o bin/patchless-amsi-test.exe
echo "[+] Built: bin/patchless-amsi-test.exe"

ls -l bin/patchless-amsi-test.exe
file bin/patchless-amsi-test.exe || true
