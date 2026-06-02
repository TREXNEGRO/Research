# iscsi-chap-base64-oob

Reproducer for the Linux LIO iSCSI target's CHAP `BASE64`-branch heap
out-of-bounds write, fixed upstream as commit `85db7391310b`
("scsi: target: iscsi: bound BASE64 CHAP_R input to digest size") on
the `7.1/scsi-fixes` queue and AUTOSEL'd to stable on 2026-05-25.

Companion writeup:
**[trexnegro.github.io/posts/found-the-same-iscsi-chap-overflow-25-days-early/](https://trexnegro.github.io/posts/found-the-same-iscsi-chap-overflow-25-days-early/)**

The canonical write-up of the bug itself is on **ahossu's blog**:
<https://ahossu.ro/blog/iscsi-chap-base64-overflow>.

This repository entry exists because I found the same bug independently
on 2026-05-05, had the same fix shape ready by 2026-05-12, but never
sent it upstream. ahossu shipped first; the credit is theirs. The
walkthrough in the blog post above explains what I learned about review
cadence; this directory is the reproducer I built.

## The bug, in one paragraph

`drivers/target/iscsi/iscsi_target_auth.c::chap_server_compute_hash()`
decodes the attacker-controlled `CHAP_R` BASE64 string into a
`kzalloc(chap->digest_size)` buffer. The decoder writes one byte per
four input chars **with no destination-size argument**, and the
post-decode length check fires after the write. A 128-char `CHAP_R`
BASE64 decodes to 96 bytes; with MD5 (`digest_size = 16`) that's
80 bytes of attacker-chosen out-of-bounds write into kmalloc-16,
pre-auth, one TCP connection.

## Layout

```
poc/iscsi_chap_overflow.c     malicious initiator — sends the malformed Login sequence
lab/setup_iscsi.sh            LIO target configuration (CHAP enabled, MD5)
logs/KASAN-vulnerable.log     example KASAN trace (redacted build identifiers)
```

## Building and running the PoC

Dependencies on the host:

- `gcc` (any version)
- A Linux box on the same network as the target, or `localhost` for a QEMU lab

Build:

```bash
cc -O2 -o iscsi_chap_overflow poc/iscsi_chap_overflow.c
```

Run against a target you own:

```bash
./iscsi_chap_overflow <target-ip> <chap-username>
```

The PoC walks the iSCSI Login state machine through CSG=0
SecurityNegotiation, sends `AuthMethod=CHAP`, then the malformed
`CHAP_R = base64(96 bytes)`. The target's kernel hits the OOB write on
the unauth side of the digest comparison.

## Setting up a vulnerable lab target

`lab/setup_iscsi.sh` configures `targetcli` to expose a single demo-mode
LUN with CHAP authentication enabled (MD5, default `digest_size = 16`).
Run it inside a guest:

```bash
sudo bash lab/setup_iscsi.sh
```

Then the malicious initiator from the host:

```bash
./iscsi_chap_overflow 192.0.2.42 testuser
```

Expected on the **vulnerable** guest: a KASAN slab-out-of-bounds report
matching the structure in `logs/KASAN-vulnerable.log` — write of size 1
into the kmalloc-16 region from `chap_base64_decode`.

Expected on a **patched** guest (kernel containing commit
`85db7391310b` or its stable backport): the iSCSI Login fails cleanly
with `"Malformed CHAP_R: BASE64 input too long"` and no KASAN report.

## What the fix looks like

The patch is a single hunk in `chap_server_compute_hash()`:

```diff
     case BASE64:
+        if (strlen(chap_r) >
+            DIV_ROUND_UP(chap->digest_size * 4, 3)) {
+            pr_err("Malformed CHAP_R: BASE64 input too long\n");
+            goto out;
+        }
         if (chap_base64_decode(client_digest, chap_r, strlen(chap_r)) !=
             chap->digest_size) {
             pr_err("Malformed CHAP_R: invalid BASE64\n");
             goto out;
         }
         break;
```

`DIV_ROUND_UP(digest_size * 4, 3)` is the maximum BASE64 input length
that can decode to `digest_size` bytes. For MD5 (16) that's 22 chars.
Anything longer is by definition malformed.

## Scope and intent

Authorised security research and education only. The PoC exists to
make a public, upstream-fixed kernel bug verifiable for defenders and
curious readers. **Do not point it at targets you do not own or have
written permission to test.**

## License

MIT — see [`../LICENSE`](../LICENSE) at the repository root.
