/* veh_manager.c — single VEH dispatch per Dr register trigger
 * Authorised testing only.
 */
#include "veh_manager.h"
#include "helpers.h"

typedef struct {
    PVOID            target;
    bp_dr_handler_t  handler;
    PVOID            user_ctx;
    BOOL             active;
} dr_slot_t;

static dr_slot_t g_slots[4];
static PVOID     g_veh_handle = NULL;

/* Set a Dr register on the CURRENT thread and arm Dr7 for "execute" type. */
static BOOL arm_dr_for_thread(HANDLE thread, int dr_index, PVOID target)
{
    if (dr_index < 0 || dr_index > 3) return FALSE;

    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (!GetThreadContext(thread, &ctx)) return FALSE;

    /* Store target in DrN */
    switch (dr_index) {
        case 0: ctx.Dr0 = (DWORD64)target; break;
        case 1: ctx.Dr1 = (DWORD64)target; break;
        case 2: ctx.Dr2 = (DWORD64)target; break;
        case 3: ctx.Dr3 = (DWORD64)target; break;
    }

    /* Dr7 layout: bit (2*N) = local enable for DrN, bits (16+4*N)..(19+4*N) hold:
     *   bits 16..17 of slot = condition (00 = execute), bits 18..19 = length (00 = 1 byte)
     */
    /* Clear our slot's bits then set local-enable + execute/1byte */
    DWORD64 dr7 = ctx.Dr7;
    int len_cond_shift = 16 + dr_index * 4;
    dr7 &= ~(0x3ull << (dr_index * 2));        /* clear LN+GN */
    dr7 &= ~(0xFull << len_cond_shift);        /* clear cond+len nibble */
    dr7 |=  (0x1ull << (dr_index * 2));        /* local enable */
    /* leave cond=00 (execute), len=00 (1 byte) — that's all zeros, fine */
    ctx.Dr7 = dr7;

    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (!SetThreadContext(thread, &ctx)) return FALSE;
    return TRUE;
}

static void disarm_dr_for_thread(HANDLE thread, int dr_index)
{
    if (dr_index < 0 || dr_index > 3) return;
    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (!GetThreadContext(thread, &ctx)) return;
    switch (dr_index) {
        case 0: ctx.Dr0 = 0; break;
        case 1: ctx.Dr1 = 0; break;
        case 2: ctx.Dr2 = 0; break;
        case 3: ctx.Dr3 = 0; break;
    }
    ctx.Dr7 &= ~(0x3ull << (dr_index * 2));            /* clear LN/GN */
    ctx.Dr7 &= ~(0xFull << (16 + dr_index * 4));       /* clear nibble */
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    SetThreadContext(thread, &ctx);
}

/* The single VEH that the OS will call for every exception. */
static LONG NTAPI veh_dispatch(EXCEPTION_POINTERS *exc)
{
    /* We only care about single-step (hardware breakpoint hit). */
    if (exc->ExceptionRecord->ExceptionCode != STATUS_SINGLE_STEP)
        return EXCEPTION_CONTINUE_SEARCH;

    PVOID rip = (PVOID)exc->ContextRecord->Rip;
    /* Find which Dr slot matches RIP. */
    for (int i = 0; i < 4; ++i) {
        if (!g_slots[i].active) continue;
        if (g_slots[i].target != rip) continue;
        /* Found — dispatch. */
        LONG r = g_slots[i].handler(exc, g_slots[i].target, g_slots[i].user_ctx);
        /* DR6 must be cleared by us (CPU sets B0..B3 bits to indicate which Dr fired). */
        exc->ContextRecord->Dr6 = 0;
        /* Resume Flag in EFlags so the same instr doesn't refire if RIP unchanged. */
        exc->ContextRecord->EFlags |= 0x10000; /* RF */
        return r;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

static BOOL ensure_veh(void)
{
    if (g_veh_handle) return TRUE;
    /* First param = 1 means insert at head of chain (runs before existing). */
    g_veh_handle = AddVectoredExceptionHandler(1, veh_dispatch);
    return g_veh_handle != NULL;
}

BOOL bp_veh_install(int dr_index, PVOID target,
                    bp_dr_handler_t handler, PVOID user_ctx)
{
    if (dr_index < 0 || dr_index > 3) return FALSE;
    if (!target || !handler) return FALSE;
    if (!ensure_veh()) return FALSE;

    g_slots[dr_index].target   = target;
    g_slots[dr_index].handler  = handler;
    g_slots[dr_index].user_ctx = user_ctx;
    g_slots[dr_index].active   = TRUE;

    return arm_dr_for_thread(GetCurrentThread(), dr_index, target);
}

void bp_veh_uninstall(int dr_index)
{
    if (dr_index < 0 || dr_index > 3) return;
    g_slots[dr_index].active = FALSE;
    disarm_dr_for_thread(GetCurrentThread(), dr_index);
}

void bp_veh_shutdown(void)
{
    for (int i = 0; i < 4; ++i) bp_veh_uninstall(i);
    if (g_veh_handle) {
        RemoveVectoredExceptionHandler(g_veh_handle);
        g_veh_handle = NULL;
    }
}
