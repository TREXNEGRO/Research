#!/usr/bin/env bash
# Drive the vulnerable kernel against the malicious SMB2 server.
# Expects: KERNEL, INITRD env vars pointing at your built bzImage and an
# initrd with mount.cifs + busybox.
set -e
: "${KERNEL:?point KERNEL at a vulnerable linux-v7.0 bzImage}"
: "${INITRD:?point INITRD at an initrd with mount.cifs}"

# Start the malicious server in the background.
python3 server/malicious_server.py --port 1445 > logs/server.log 2>&1 &
SRV=$!
trap "kill $SRV 2>/dev/null" EXIT
sleep 2

# Boot the kernel under QEMU with host networking forwarding 1445.
exec qemu-system-x86_64 \
    -kernel "$KERNEL" -initrd "$INITRD" \
    -append 'console=ttyS0 panic=1 oops=panic kasan_multi_shot loglevel=8' \
    -nographic -m 1G -smp 2 \
    -net nic,model=virtio \
    -net user,hostfwd=tcp::1445-:1445 \
  | tee logs/qemu-vulnerable.log
