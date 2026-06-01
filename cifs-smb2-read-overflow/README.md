# cifs-smb2-read-overflow

Reproducer for an integer overflow in the Linux SMB2 client (`fs/smb/client/`)
that lets a malicious SMB server stall a `mount.cifs` mount for 180 seconds
per READ. Fixed upstream in `81a874233c305d29e37fdb70b691ff4254294c0b` ("smb:
client: avoid integer overflow in SMB2 READ length check"), AUTOSEL'd to
stable on 2026-05-20.

This is one finding inside the unified `research` repository. Top-level
index: [`../README.md`](../README.md).

Companion write-up:
**<https://trexnegro.github.io/posts/u32-plus-u32-equals-zero-smb2-overflow/>**

## What the bug is

`cifs_readv_receive()` and `handle_read_data()` validate the SMB2 READ
response with an unguarded sum:

```c
if (!use_rdma_mr && (data_offset + data_len > buflen))   /* transport.c */
    return -1;

} else if (buf_len >= data_offset + data_len) {          /* smb2ops.c */
    copy_to_iter(buf + data_offset, data_len, &rdata->subreq.io_iter);
```

Both `data_offset` and `data_len` are `unsigned int`. A malicious server that
replies with `DataOffset = 0x50` and `DataLength = 0xFFFFFFB0` wraps the sum
to `0`, the check passes, and the kernel walks into reading ~4 GiB off the
TCP socket — stalling for the 180-second response timeout before reconnecting.

## Layout

```
server/malicious_server.py    impacket-based hostile SMB2 server
lab/run-vulnerable.sh         QEMU lifter against an unpatched bzImage
lab/run-patched.sh            same lifter against a patched bzImage
lab/init.sh                   guest init script (place in initrd as /init)
logs/qemu-vulnerable-redacted.log    ~245 s vulnerable run (stall + reconnect)
logs/qemu-patched-clean.log          ~66 s patched run (clean shutdown)
```

## Running it

Pre-reqs on the host:

- Python 3.10+ with `pip install impacket` (>=0.11)
- QEMU 10+ with TCG (KVM not required)
- A Linux source tree at `linux-v7.0` or earlier (vulnerable) for one run
- A Linux source tree at `linux-v7.1+` or with the patch backported (patched)
  for comparison

Build kernels with at minimum:

```
CONFIG_CIFS=y
CONFIG_KASAN_GENERIC=y
CONFIG_KASAN_OUTLINE=y
CONFIG_FORTIFY_SOURCE=y
```

Pack an initrd containing `mount.cifs` and BusyBox, with `lab/init.sh`
installed as `/init`.

Then:

```bash
# vulnerable
export KERNEL=/path/to/vulnerable/arch/x86/boot/bzImage
export INITRD=/path/to/initrd.cpio.gz
./lab/run-vulnerable.sh

# patched
export KERNEL=/path/to/patched/arch/x86/boot/bzImage
./lab/run-patched.sh
```

Expected vulnerable output, around the 240-second mark:

```text
CIFS: VFS: \\10.0.2.2 has not responded in 180 seconds. Reconnecting...
CIFS: fs/smb/client/transport.c:
  total_read=4294967273  buflen=144  remaining=4294967216
```

The `remaining=4294967216` value is `0xFFFFFFB0` — exactly the attacker's
`DataLength`. That value reaching the receive call is the smoking gun.

Patched output: mount + dd + clean shutdown in ~66 s, no `not responded`
line.

Sample side-by-side logs are included under `logs/`.

## The fix, for reference

The upstream patch wraps both sites with `check_add_overflow()`:

```diff
- } else if (buf_len >= data_offset + data_len) {
+ } else if (!check_add_overflow(data_offset, data_len, &end_off) &&
+        buf_len >= end_off) {
```

```diff
- if (!use_rdma_mr && (data_offset + data_len > buflen))
-     return -1;
+ if (!use_rdma_mr) {
+     if (check_add_overflow(data_offset, data_len, &end_off))
+         return -1;
+     if (end_off > buflen)
+         return -1;
+ }
```

`check_add_overflow()` lives in `include/linux/overflow.h` and is already
used elsewhere in `fs/smb/`.

## Scope and intent

Authorised research / education use only. The malicious server is small,
boring, and easy to detect; it exists to make the bug reproducible on a
single workstation. Do not point it at servers you don't own.

## License

MIT — see [`../LICENSE`](../LICENSE) at the repository root.
