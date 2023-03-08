import sys
BYTEORDER = sys.byteorder

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
TEMP_STRIPE_PATH = r"temp\stripes\\"
RESTORE_TEMP_PATH = r"temp\for_restore\\"
RESTORE_STRIPE_FINISHED_PATH = r"temp\for_restore_finished\\"
TEMP_PEER_STRIPE_PATH = r"temp\not_final\\"


SEND_DELAY = 0.01
MAX_DATA_SIZE = 650
MAX_PACKET_TIMEOUT = 0.5
