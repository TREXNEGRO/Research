# Research

PoCs, reproducers, and supporting artifacts for the writeups at
**<https://trexnegro.github.io>**.

Each subdirectory corresponds to one finding or research note and contains
the minimum needed to reproduce or audit it. New entries are appended over
time; older entries are not rewritten unless the upstream fix changes shape.

## Index

| Finding | Class | Status | Companion writeup |
|---|---|---|---|
| [`cifs-smb2-read-overflow/`](./cifs-smb2-read-overflow) | Linux kernel — cifs / SMB2 client | Patched upstream (`81a8742`), AUTOSEL'd to stable 2026-05-20 | [u32 + u32 = 0 is still a bug in 2026](https://trexnegro.github.io/posts/u32-plus-u32-equals-zero-smb2-overflow/) |
| [`patchless-amsi-bypass/`](./patchless-amsi-bypass) | Windows — in-process AMSI/ETW evasion | Reference port, public technique | [Patchless AMSI Bypass via Hardware Breakpoints](https://trexnegro.github.io/posts/patchless-amsi-bypass-hwbp/) |

## License

MIT. See `LICENSE` at the repository root.
