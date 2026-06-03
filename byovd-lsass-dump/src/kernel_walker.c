/*
 * kernel_walker.c — locate kernel module base + walk EPROCESS list.
 *
 * Step 1: NtQuerySystemInformation(SystemModuleInformation) returns kernel
 *         module table from user-mode (requires SeDebugPrivilege or admin).
 *
 * Step 2: From ntoskrnl.exe base + symbol offset to PsInitialSystemProcess,
 *         walk the circular ActiveProcessLinks doubly-linked list looking
 *         for the EPROCESS whose UniqueProcessId matches our PID.
 *
 * The kernel-symbol approach used here is simpler than DTB/CR3 traversal.
 * It does require SeDebugPrivilege to call NtQuerySystemInformation with
 * SystemModuleInformation, which is granted to admins.
 */
#include "common.h"

static pNtQuerySystemInformation pNtQSI;

static BOOL init_ntdll(void) {
    if (pNtQSI) return TRUE;
    HMODULE n = GetModuleHandleA("ntdll.dll");
    if (!n) { ERR("GetModuleHandle(ntdll)"); return FALSE; }
    pNtQSI = (pNtQuerySystemInformation)GetProcAddress(n, "NtQuerySystemInformation");
    if (!pNtQSI) { ERR("GetProcAddress(NtQSI)"); return FALSE; }
    return TRUE;
}

PVOID kw_kernel_base(const char *target_module) {
    if (!init_ntdll()) return NULL;
    ULONG sz = 0;
    pNtQSI(SystemModuleInformation, NULL, 0, &sz);
    if (sz == 0) { ERR("NtQSI sz=0"); return NULL; }
    PRTL_PROCESS_MODULES m = (PRTL_PROCESS_MODULES)HeapAlloc(GetProcessHeap(), 0, sz);
    if (!m) return NULL;
    NTSTATUS st = pNtQSI(SystemModuleInformation, m, sz, &sz);
    if (!NT_SUCCESS(st)) { ERR("NtQSI st=0x%lx", st); HeapFree(GetProcessHeap(), 0, m); return NULL; }

    PVOID base = NULL;
    for (ULONG i = 0; i < m->NumberOfModules; i++) {
        const char *name = (const char*)m->Modules[i].FullPathName + m->Modules[i].OffsetToFileName;
        if (_stricmp(name, target_module) == 0) {
            base = m->Modules[i].ImageBase;
            LOG("kernel module %s base = %p", target_module, base);
            break;
        }
    }
    HeapFree(GetProcessHeap(), 0, m);
    return base;
}

/*
 * Walk the ActiveProcessLinks list starting from any known EPROCESS.
 *
 * We don't yet have PsInitialSystemProcess address since this build doesn't
 * resolve kernel symbols. Use the System process (PID 4) and pivot.
 *
 * To get System EPROCESS without PDB:
 *   - Use NtQuerySystemInformation(SystemHandleInformation) and find a
 *     handle owned by PID 4 to any object; the Object field is a kernel
 *     pointer. From there we can find adjacent objects but not directly
 *     the EPROCESS.
 *
 * Cleanest: use NtQuerySystemInformation with SystemBigPoolInformation or
 * SystemExtendedHandleInformation. The latter lists every handle with the
 * owning EPROCESS pointer, which is exactly what we want.
 */

typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX {
    PVOID    Object;
    ULONG_PTR UniqueProcessId;
    ULONG_PTR HandleValue;
    ULONG    GrantedAccess;
    USHORT   CreatorBackTraceIndex;
    USHORT   ObjectTypeIndex;
    ULONG    HandleAttributes;
    ULONG    Reserved;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX, *PSYSTEM_HANDLE_TABLE_ENTRY_INFO_EX;

typedef struct _SYSTEM_HANDLE_INFORMATION_EX {
    ULONG_PTR NumberOfHandles;
    ULONG_PTR Reserved;
    SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX Handles[1];
} SYSTEM_HANDLE_INFORMATION_EX, *PSYSTEM_HANDLE_INFORMATION_EX;

PVOID kw_find_eprocess(HANDLE hDev, DWORD pid) {
    if (!init_ntdll()) return NULL;

    /*
     * Strategy: open a self-handle to ourselves, then query
     * SystemExtendedHandleInformation. Each entry has UniqueProcessId
     * and Object (kernel pointer to the underlying object, e.g. our
     * EPROCESS for a process handle). Find one where UniqueProcessId
     * == pid AND ObjectTypeIndex matches Process; the Object field
     * is the EPROCESS we want.
     */
    HANDLE hSelf = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hSelf) { ERR("OpenProcess(self) err=%lu", GetLastError()); return NULL; }

    ULONG sz = 0;
    NTSTATUS st = pNtQSI(SystemExtendedHandleInformation, NULL, 0, &sz);
    if (st != STATUS_INFO_LENGTH_MISMATCH) {
        ERR("NtQSI(SystemExtendedHandleInformation) sz probe st=0x%lx", st);
        CloseHandle(hSelf); return NULL;
    }
    /* allocate a bit more — handles change between probe and real query */
    sz += 0x10000;
    PSYSTEM_HANDLE_INFORMATION_EX info = (PSYSTEM_HANDLE_INFORMATION_EX)HeapAlloc(GetProcessHeap(), 0, sz);
    if (!info) { CloseHandle(hSelf); return NULL; }

    st = pNtQSI(SystemExtendedHandleInformation, info, sz, &sz);
    if (!NT_SUCCESS(st)) {
        ERR("NtQSI(SystemExtendedHandleInformation) st=0x%lx", st);
        HeapFree(GetProcessHeap(), 0, info);
        CloseHandle(hSelf);
        return NULL;
    }

    PVOID eproc = NULL;
    for (ULONG_PTR i = 0; i < info->NumberOfHandles; i++) {
        SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX *e = &info->Handles[i];
        if ((DWORD)e->UniqueProcessId == pid &&
            (HANDLE)e->HandleValue == hSelf) {
            /* Our own self-handle. Its Object is the EPROCESS. */
            eproc = e->Object;
            LOG("self EPROCESS = %p (pid %lu)", eproc, pid);
            break;
        }
    }

    HeapFree(GetProcessHeap(), 0, info);
    CloseHandle(hSelf);

    if (!eproc) ERR("EPROCESS for pid %lu not found", pid);
    return eproc;

    /* hDev unused in this path — kept in signature for future variants
     * that walk through driver-side kernel reads.
     */
    (void)hDev;
}
