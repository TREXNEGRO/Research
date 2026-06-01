/* helpers.h — common utilities */
#ifndef BP_HELPERS_H
#define BP_HELPERS_H

#include <windows.h>
#include <stdint.h>

/* Compute FNV-1a hash of an ASCII string (case-insensitive). */
uint32_t bp_fnv1a(const char *s);

/* Same, but for a wide string. */
uint32_t bp_fnv1a_w(const wchar_t *s);

/* Walk the PEB loader list to find a loaded module by hash of its base name.
 * Returns module base address or NULL. */
PVOID bp_get_module_by_hash(uint32_t hash);

/* Resolve an export from a module by hash of its name.
 * Returns function address or NULL. Forwarded exports are NOT chased. */
PVOID bp_get_proc_by_hash(PVOID module_base, uint32_t hash);

/* Convenience: get module + proc in one call. */
PVOID bp_resolve(uint32_t mod_hash, uint32_t fn_hash);

/* Pre-computed FNV-1a hashes (case-insensitive) of module names. */
#define HASH_NTDLL       0xA62A3B3B  /* "ntdll.dll" */
#define HASH_KERNEL32    0xA3E6F6C3  /* "kernel32.dll" */
#define HASH_AMSI        0x0187B681  /* "amsi.dll" */

#endif
