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
| [`iscsi-chap-base64-oob/`](./iscsi-chap-base64-oob) | Linux kernel — LIO iSCSI target CHAP auth | Patched upstream (`85db7391310b`), AUTOSEL'd to stable 2026-05-25 | [Found the same iSCSI CHAP base64 overflow 25 days early](https://trexnegro.github.io/posts/found-the-same-iscsi-chap-overflow-25-days-early/) |
| [`crowdstrike-logscale-waf-graphql-bypass/`](./crowdstrike-logscale-waf-graphql-bypass) | Web — WAF URL-decode mismatch + pre-auth GraphQL | CVE-2026-40050 mitigation bypass; vendor declined report 2026-06-01 | [One byte of URL-encoding past a WAF](https://trexnegro.github.io/posts/crowdstrike-logscale-waf-bypass-graphql-preauth/) |

## License

MIT. See `LICENSE` at the repository root.
