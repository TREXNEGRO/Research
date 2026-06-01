# patchless-amsi-bypass

Minimal in-process AMSI + ETW bypass via x86 hardware debug registers and a
vectored exception handler. Reference implementation for the writeup at
[trexnegro.github.io](https://trexnegro.github.io/posts/patchless-amsi-bypass-hwbp/).

> Authorised security research and AV/EDR efficacy testing only. The code is
> intentionally small and recognisable; defenders should treat any custom
> derivative as a known-pattern dual-use tool.
{: .prompt-warning }

## What it does

- `bp_init(BP_AMSI_HWBP)` — installs a vectored exception handler at the head
  of the chain, sets `DR0 = &amsi!AmsiScanBuffer`, and arms `DR7` for an
  execute-1-byte breakpoint. When the host calls `AmsiScanBuffer`, the
  handler writes `AMSI_RESULT_CLEAN` into the caller's output slot
  (`[RSP+0x30]` per MS x64 ABI), sets `RAX = S_OK`, advances `RIP` to the
  caller's return address, and resumes — the function body never executes.
- `bp_init(BP_ETW_PATCH)` — same shape via `DR1`, targeting
  `ntdll!EtwEventWrite`. Returns `STATUS_SUCCESS` without emitting any ETW
  events.
- `bp_shutdown()` — disarms both breakpoints and unregisters the VEH.

Neither `amsi.dll` nor `ntdll.dll` is patched. Memory-integrity scanners
that look for AMSI patch signatures find nothing because nothing was
modified.

The companion blog post walks through the stack mechanics (`AmsiScanBuffer`
result pointer at `[RSP+0x30]`), the VEH dispatch logic, the `DR6` clear and
`RF` flag, and the four classes of detection that defenders can still use.

## Layout

```
include/bypass.h           public API + result codes + technique mask bits
src/veh_manager.c, .h      single VEH dispatcher, slot table, DR arm/disarm
src/amsi_hwbp.c            DR0 → amsi!AmsiScanBuffer + result-pointer handler
src/etw_hwbp.c             DR1 → ntdll!EtwEventWrite + RAX-fix handler
src/helpers.c, .h          module + procedure lookup by FNV-1a hash (no IAT)
src/bypass_main.c          bp_init / bp_shutdown / bp_result_str entry points
tests/test_minimal.c       minimal sanity-check: install AMSI BP, scan a
                           known-malicious string, expect AMSI_RESULT_CLEAN
build.sh                   mingw-w64 cross-compile script (Linux → Win64)
```

Total: ~500 lines of C, no external dependencies beyond `kernel32 / user32 /
psapi`. Builds clean on `mingw-w64 gcc 13+` and on MSVC 2022 (with trivial
project setup).

## Building

### Cross-compile from Linux (recommended for reproducibility)

```bash
sudo apt install mingw-w64        # Debian/Ubuntu
./build.sh
# → bin/patchless-amsi-test.exe
```

### Native MSVC

Open the source in a Visual Studio "Console App" project, drop in the
contents of `include/` + `src/` + `tests/test_minimal.c`, and link against
`kernel32.lib user32.lib psapi.lib`. Disable `/GS` (stack canaries) if you
hit issues with the inline asm in `helpers.c` — the rest is plain C.

## Running

```text
> patchless-amsi-test.exe
[*] bp_init(BP_AMSI_HWBP | BP_ETW_PATCH) ...
[+] OK
[*] testing AmsiScanBuffer with known-malicious string...
[+] AMSI returned CLEAN (result = 0)
[*] bp_shutdown()
[+] done.
```

The test binary loads `amsi.dll`, resolves `AmsiScanBuffer`, calls it on a
string that the host's installed AMSI provider (Defender, etc.) would flag,
and asserts the result is `AMSI_RESULT_CLEAN`. If the result is non-zero,
the bypass did not engage — investigate the VEH chain and `DR0` state on
the calling thread.

## What it does *not* do

- It does **not** unhook `ntdll`. The companion blog post discusses this as
  a follow-on layer; the reference implementation here stays small to make
  the AMSI/ETW pieces obvious.
- It does **not** do indirect syscalls. Same reason — out of scope for this
  entry.
- It does **not** persist across thread boundaries automatically. The DR
  set is per-thread; if the host spawns additional threads that call
  `AmsiScanBuffer`, you'll need to either arm the new threads or hook
  `LdrpInitializeThread` to do so. The companion blog post discusses this
  as a limitation.
- It does **not** evade defenders who specifically look for VEH chain
  entries or `DR0–DR3` set to function addresses inside `amsi.dll` /
  `ntdll.dll`. The blog post enumerates four such detection avenues.

## Threat-model notes

- Process-local. Does not touch other processes' memory.
- User-mode only. Does not bypass kernel-mode AMSI providers (rare but real).
- Single-AMSI-provider model. If a host implements its own AMSI-equivalent
  routing without going through `amsi!AmsiScanBuffer`, this does nothing.
- The intent is to make a known-published technique reproducible for
  defender benchmarking. The same idea has been published several times
  before by other researchers; this code does not claim originality, only
  a clean reference port.

## Prior art

- TheEnergyStory — `PatchlessEtwAndAmsiBypass` (the canonical HW-BP AMSI
  reference). <https://github.com/TheEnergyStory/PatchlessEtwAndAmsiBypass>
- RastaMouse — Memory Patching AMSI Bypass (the predecessor patch-based
  technique, useful for comparison).
- D1rkMtr — `UnhookingPatch` (an adjacent in-process unhook approach).

The blog post enumerates additional references and detection sketches.

## License

MIT — see [`../LICENSE`](../LICENSE) at the repository root.
