import sys

LOCALHOST = True

if LOCALHOST:
    SERVER_IP = "127.0.0.1"
else:
    SERVER_IP = "0.0.0.0"
SERVER_PORT = 22223
CLIENT_PORT = 30001
CLIENT_IP = "0.0.0.0"
LOGLEVEL = 1
BACKUP_PATH = r"backups\\"
RESTORE_PATH = r"restore\\"
RESTORE_TEMP_PATH = r"temp\for_restore\\"
UNFINISHED_STRIPE_PATH = r"temp\not_final\\"
BYTEORDER = sys.byteorder
