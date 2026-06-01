#!/usr/bin/env bash
# Same as run-vulnerable.sh but expects KERNEL to point at a kernel built
# with commit 81a874233c305d29e37fdb70b691ff4254294c0b applied (or any tag
# >= v7.1 / stable backports).
set -e
: "${KERNEL:?point KERNEL at a PATCHED linux bzImage (>= v7.1 or stable backport)}"
: "${INITRD:?point INITRD at an initrd with mount.cifs}"

python3 server/malicious_server.py --port 1445 > logs/server-patched.log 2>&1 &
SRV=$!
trap "kill $SRV 2>/dev/null" EXIT
sleep 2

exec qemu-system-x86_64 \
    -kernel "$KERNEL" -initrd "$INITRD" \
    -append 'console=ttyS0 panic=1 oops=panic kasan_multi_shot loglevel=8' \
    -nographic -m 1G -smp 2 \
    -net nic,model=virtio \
    -net user,hostfwd=tcp::1445-:1445 \
  | tee logs/qemu-patched.log
