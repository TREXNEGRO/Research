/* veh_manager.h — single VEH that dispatches per-Dr-register-trigger */
#ifndef BP_VEH_H
#define BP_VEH_H

#include <windows.h>

/* Per-Dr handler:
 *   exc      : exception info (we mutate Context to redirect execution)
 *   target   : the function address that fired the breakpoint
 *   user_ctx : user-supplied opaque
 * Return    : EXCEPTION_CONTINUE_EXECUTION if handled, or EXCEPTION_CONTINUE_SEARCH.
 */
typedef LONG (NTAPI *bp_dr_handler_t)(EXCEPTION_POINTERS *exc,
                                      PVOID target,
                                      PVOID user_ctx);

/* Register a handler bound to a Dr register (0..3) and a target address. */
BOOL bp_veh_install(int dr_index, PVOID target,
                    bp_dr_handler_t handler, PVOID user_ctx);

/* Remove handler for Dr index, clear Dr in current thread context. */
void bp_veh_uninstall(int dr_index);

/* Tear down VEH entirely. */
void bp_veh_shutdown(void);

#endif
