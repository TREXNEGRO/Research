#!/bin/sh
# K-CHAP setup — LIO target with CHAP authentication required
set -x

LUN_FILE=/tmp/lun.img
dd if=/dev/zero of=$LUN_FILE bs=1M count=10 2>&1
TGT_FILEIO=/sys/kernel/config/target/core/fileio_0/lun0
mkdir -p $TGT_FILEIO
echo "fd_dev_name=$LUN_FILE,fd_dev_size=$((10 * 1024 * 1024))" > $TGT_FILEIO/control
echo 0 > $TGT_FILEIO/attrib/emulate_tpu 2>&1
echo 1 > $TGT_FILEIO/enable

IQN_TGT=iqn.2026-05.local.poc:tgt0
TPG=/sys/kernel/config/target/iscsi/$IQN_TGT/tpgt_1
mkdir -p $TPG

# Disable demo-mode, REQUIRE auth (CHAP)
echo 0 > $TPG/attrib/demo_mode_write_protect
echo 0 > $TPG/attrib/generate_node_acls
echo 0 > $TPG/attrib/cache_dynamic_acls
echo 1 > $TPG/attrib/authentication
echo 0 > $TPG/attrib/default_cmdsn_depth 2>&1

# Map LUN to TPG
mkdir -p $TPG/lun/lun_0
ln -s /sys/kernel/config/target/core/fileio_0/lun0 $TPG/lun/lun_0/iscsi_lun

# Real ACL for the initiator IQN with CHAP creds.
# Attacker doesn't need correct creds — the OOB write happens in
# chap_base64_decode BEFORE the digest memcmp.
INI_IQN=iqn.2026.local.poc:01
ACL=$TPG/acls/$INI_IQN
mkdir -p $ACL
mkdir -p $ACL/lun_0
ln -s /sys/kernel/config/target/core/fileio_0/lun0 $ACL/lun_0/lun
printf 'testuser' > $ACL/auth/userid
printf 'Password0123456' > $ACL/auth/password

# Portal MUST come before TPG enable
mkdir -p $TPG/np/0.0.0.0:3260

echo 1 > $TPG/enable

echo "[setup_iscsi] iSCSI target ready (CHAP REQUIRED)"
echo "auth=$(cat $TPG/attrib/authentication)"
echo "ACL: $(ls $TPG/acls/)"
