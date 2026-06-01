# research

PoCs, reproducers, and supporting artifacts for the writeups at
**<https://trexnegro.github.io>**.

Each subdirectory corresponds to one finding or research note and contains
the minimum needed to reproduce or audit it. New entries are appended over
time; older entries are not rewritten unless the upstream fix changes shape.

## Index

| Finding | Class | Status | Companion writeup |
|---|---|---|---|
| [`cifs-smb2-read-overflow/`](./cifs-smb2-read-overflow) | Linux kernel — cifs / SMB2 client | Patched upstream (`81a8742`), AUTOSEL'd to stable 2026-05-20 | [u32 + u32 = 0 is still a bug in 2026](https://trexnegro.github.io/posts/u32-plus-u32-equals-zero-smb2-overflow/) |

## Conventions

- Each finding's directory contains its own `README.md` with the bug,
  affected versions, and step-by-step reproduction.
- Code is MIT-licensed (see top-level `LICENSE`) unless a subdir overrides.
- Logs included under `logs/` are redacted of build-host identifiers but
  otherwise verbatim.
- Nothing in this repository carries customer data, third-party PII, or
  any artifact that depends on credentials.

## Scope

Authorised security research and education only. Reproducers exist to make
public, upstream-fixed bugs verifiable for defenders and curious readers.
Do not point reproducers at systems you do not own or have explicit, written
permission to test.

## Contact

Issues / pull requests / corrections welcome on this repository.

For coordinated-disclosure work — including kernel.org `security@kernel.org`,
vendor PSIRTs, or HackerOne-mediated programs — contact via the channel
listed on the [About page of the writeup site](https://trexnegro.github.io/about/).

## License

MIT. See `LICENSE` at the repository root.
