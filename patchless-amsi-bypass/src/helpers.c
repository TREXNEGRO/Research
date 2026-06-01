/* helpers.c — FNV1a hash + PEB walking + dynamic API resolution
 * Authorised testing only.
 */
#include "helpers.h"
#include <winternl.h>

/* PEB + Ldr structures (from winternl.h but augmented for our needs). */
typedef struct _LDR_DATA_TABLE_ENTRY_FULL {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    /* ... more, but we only need the above. */
} LDR_DATA_TABLE_ENTRY_FULL, *PLDR_DATA_TABLE_ENTRY_FULL;

/* ---------------- FNV-1a (case-insensitive) ---------------- */

uint32_t bp_fnv1a(const char *s)
{
    uint32_t h = 2166136261u;
    while (*s) {
        char c = *s++;
        if (c >= 'A' && c <= 'Z') c |= 0x20;  /* tolower */
        h ^= (uint8_t)c;
        h *= 16777619u;
    }
    return h;
}

uint32_t bp_fnv1a_w(const wchar_t *s)
{
    uint32_t h = 2166136261u;
    while (*s) {
        wchar_t c = *s++;
        if (c >= L'A' && c <= L'Z') c |= 0x20;
        h ^= (uint8_t)(c & 0xff);
        h *= 16777619u;
    }
    return h;
}

/* ---------------- PEB walking ---------------- */

static PEB *get_peb(void)
{
#ifdef _WIN64
    return (PEB *)__readgsqword(0x60);
#else
    return (PEB *)__readfsdword(0x30);
#endif
}

PVOID bp_get_module_by_hash(uint32_t hash)
{
    PEB *peb = get_peb();
    if (!peb || !peb->Ldr) return NULL;

    PEB_LDR_DATA *ldr = peb->Ldr;
    LIST_ENTRY *head = &ldr->InMemoryOrderModuleList;
    LIST_ENTRY *cur  = head->Flink;

    while (cur != head) {
        PLDR_DATA_TABLE_ENTRY_FULL e = CONTAINING_RECORD(
            cur, LDR_DATA_TABLE_ENTRY_FULL, InMemoryOrderLinks);
        if (e->BaseDllName.Buffer && e->BaseDllName.Length > 0) {
            wchar_t name[260];
            ULONG n = e->BaseDllName.Length / sizeof(wchar_t);
            if (n >= 260) n = 259;
            for (ULONG i = 0; i < n; ++i) name[i] = e->BaseDllName.Buffer[i];
            name[n] = 0;
            if (bp_fnv1a_w(name) == hash)
                return e->DllBase;
        }
        cur = cur->Flink;
    }
    return NULL;
}

/* ---------------- Export resolution ---------------- */

PVOID bp_get_proc_by_hash(PVOID module_base, uint32_t hash)
{
    if (!module_base) return NULL;
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)module_base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return NULL;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((PBYTE)module_base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return NULL;

    IMAGE_DATA_DIRECTORY *exp_dir =
        &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (exp_dir->Size == 0) return NULL;

    PIMAGE_EXPORT_DIRECTORY exp =
        (PIMAGE_EXPORT_DIRECTORY)((PBYTE)module_base + exp_dir->VirtualAddress);

    DWORD *names    = (DWORD *)((PBYTE)module_base + exp->AddressOfNames);
    DWORD *funcs    = (DWORD *)((PBYTE)module_base + exp->AddressOfFunctions);
    WORD  *ordinals = (WORD  *)((PBYTE)module_base + exp->AddressOfNameOrdinals);

    for (DWORD i = 0; i < exp->NumberOfNames; ++i) {
        const char *name = (const char *)((PBYTE)module_base + names[i]);
        if (bp_fnv1a(name) == hash) {
            DWORD rva = funcs[ordinals[i]];
            /* skip forwarded exports (RVA inside export directory) */
            if (rva >= exp_dir->VirtualAddress &&
                rva <  exp_dir->VirtualAddress + exp_dir->Size) {
                return NULL;
            }
            return (PVOID)((PBYTE)module_base + rva);
        }
    }
    return NULL;
}

PVOID bp_resolve(uint32_t mod_hash, uint32_t fn_hash)
{
    PVOID m = bp_get_module_by_hash(mod_hash);
    if (!m) return NULL;
    return bp_get_proc_by_hash(m, fn_hash);
}
