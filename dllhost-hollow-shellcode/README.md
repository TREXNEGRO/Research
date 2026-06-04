# dllhost-hollow-shellcode

Companion code for the SixSixSix research post
**"Eight rounds against Cortex XDR's driver-load coverage — process hollowing,
the IAT trap, and a 2.7 KB shellcode that finally landed"**.

> Authorised lab / research use only. Do not deploy on systems you do not own
> or are not authorised to test.

## What this is

A loader chain that:

1. Spawns `C:\Windows\System32\dllhost.exe` suspended.
2. `VirtualAllocEx` an RWX region in the remote.
3. `WriteProcessMemory` a **2.7 KB position-independent shellcode**.
4. `SetThreadContext` so the thread resumes at the shellcode's entry RVA.
5. `ResumeThread`.
6. The shellcode, running inside `dllhost`:
    - Walks the PEB to find `kernel32` and `ntdll`.
    - Resolves all needed APIs by FNV-1a hash of the export name.
    - Enables `SeLoadDriverPrivilege`.
    - Writes the driver service registry key.
    - Recovers `NtLoadDriver`'s SSN from ntdll.
    - Issues a direct syscall to `NtLoadDriver`.
    - Writes a marker file.
    - Cleanly exits via `NtTerminateProcess` (no WerFault).

The dropper relies on the operator's in-house **edr-bypass-kit** primitives
for `ETW` silence + indirect syscalls + selective `ntdll` unhook.

## Files

| File | Purpose |
|---|---|
| `shellcode.c` | Position-independent shellcode (compiles to ~2.7 KB raw bytes). |
| `dropper.c` | Loader that spawns dllhost suspended and injects the shellcode. |
| `sc.ld` | Linker script that consolidates `.text/.rdata/.rodata/.data` into a single section for `objcopy -O binary`. |

## Build

```bash
# shellcode -> raw bytes
x86_64-w64-mingw32-gcc -ffreestanding -fPIC -nostdlib -nostartfiles \
  -fno-stack-protector -fno-unwind-tables -fno-asynchronous-unwind-tables \
  -mno-red-zone -Os -Wno-unused-function -fno-jump-tables \
  -Wl,-T,sc.ld,-e,sc_entry \
  shellcode.c -o sc.elf

x86_64-w64-mingw32-objcopy -O binary --only-section=.text sc.elf sc.bin

# extract the sc_entry offset for the dropper
ENTRY=$(x86_64-w64-mingw32-objdump -d sc.elf | grep '<sc_entry>:' | head -1 | awk '{print $1}')
TEXT_VA=$(x86_64-w64-mingw32-objdump -h sc.elf | awk '/\.text/{print $4; exit}')
python3 -c "print(f'sc_entry offset = 0x{int(\"$ENTRY\",16) - int(\"$TEXT_VA\",16):x}')"

# build the embed header (sc.bin -> shellcode_embedded.h)
python3 - <<'PY'
data = open('sc.bin','rb').read()
out = "#ifndef SHELLCODE_EMBEDDED_H\n#define SHELLCODE_EMBEDDED_H\n#include <stdint.h>\n\n"
out += f"#define SC_LEN {len(data)}\n"
out += "#define SC_ENTRY_OFFSET 0x???   /* from above */\n\n"
out += "static const unsigned char SC_BYTES[] = {\n"
for i in range(0, len(data), 16):
    out += "  " + ",".join(f"0x{b:02x}" for b in data[i:i+16]) + ",\n"
out += "};\n\n#endif\n"
open('shellcode_embedded.h','w').write(out)
PY

# now build dropper (assumes edr-bypass-kit headers + src in known locations)
x86_64-w64-mingw32-gcc -O2 -Wall -Wno-format \
  -Iinclude -Isrc -I. \
  src/helpers.c src/veh_manager.c src/etw_hwbp.c src/amsi_hwbp.c \
  src/ntdll_unhook.c src/ntdll_selective.c src/syscalls.c \
  src/syscalls_stub.S src/bypass_main.c \
  dropper.c \
  -o dropper.exe \
  -static -Wl,--gc-sections \
  -ladvapi32 -lpsapi -lkernel32 -luser32
```

The shellcode is *the* payload — the dropper is essentially the well-known
"hollow + RWX + write + SetThreadContext" five-syscall sequence wrapped with
indirect-syscalls hygiene from the bypass kit.

## License

Same as the parent `TREXNEGRO/Research` repo (lab / research use).
