"""
Test script to trigger SFTPGo's MinWriteOffset check.

NOTE: This only works against a server with a local/OS filesystem backend.
S3 backends do not support upload resume and will reject the OPEN with APPEND.
"""
import paramiko
import struct
from paramiko.sftp import CMD_OPEN, CMD_WRITE, CMD_CLOSE, CMD_STATUS, CMD_HANDLE
from paramiko.sftp_attr import SFTPAttributes
from paramiko.sftp import SFTP_FLAG_WRITE, SFTP_FLAG_CREATE, SFTP_FLAG_APPEND
from paramiko.message import Message

HOST = "sftpgo.sema-staging.corproot.net"
PORT = 443
USER = "testuser"
PASSWORD = "password"
REMOTE_FILE = "/upload-local/offset_test.txt"

data1 = b"first line\n"
data2 = b"second line\n"

transport = paramiko.Transport((HOST, PORT))
transport.connect(username=USER, password=PASSWORD)

sftp = paramiko.SFTPClient.from_transport(transport)

# --- create file normally ---
print("Creating file with initial content...")
with sftp.open(REMOTE_FILE, "wb") as f:
    f.write(data1)

size = sftp.stat(REMOTE_FILE).st_size
print(f"Initial file size: {size}")

# --- reopen for append (resume) using paramiko's high-level API ---
# Open in append mode — this triggers SFTPGo to set MinWriteOffset = current file size
print("Opening file in append mode...")
try:
    f = sftp.open(REMOTE_FILE, "ab")
except IOError as e:
    print(f"OPEN with APPEND failed: {e}")
    print("This is expected on S3 backends which do not support upload resume.")
    sftp.close()
    transport.close()
    raise SystemExit(1)

print(f"File opened, server expects writes at offset >= {size}")

# --- write at offset 0 (intentionally wrong) ---
# paramiko's SFTPFile.write() auto-increments the offset, so we need to
# manually seek to 0 to send a write at the wrong offset
f.seek(0)
print(f"Sending WRITE at offset 0 (should be {size}) to trigger MinWriteOffset check...")
try:
    f.write(data2)
    # Force flush to send the write immediately
    f.flush()
    print("Write accepted (offset was auto-corrected by patched SFTPGo)")
except IOError as e:
    print(f"Write rejected as expected: {e}")

f.close()
sftp.close()
transport.close()

print("Done")
