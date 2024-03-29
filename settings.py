import sys

BYTEORDER = sys.byteorder

LOCALHOST = False

if LOCALHOST:
    SERVER_IP = "127.0.0.1"
else:
    SERVER_IP = "0.0.0.0"
SERVER_PORT = 22223
SERVER_ADDR = (SERVER_IP, SERVER_PORT)
CLIENT_PORT = 30001
CLIENT_IP = "0.0.0.0"
LOGLEVEL = 1
BACKUP_PATH = r"backups\\"
RESTORE_PATH = r"restore\\"
TEMP_STRIPE_PATH = r"temp\stripes\\"
RESTORE_TEMP_PATH = r"temp\for_restore\\"
RESTORE_STRIPE_FINISHED_PATH = r"temp\for_restore_finished\\"
TEMP_PEER_STRIPE_PATH = r"temp\not_final\\"
CLIENT_KEYS_PATH = r"keys\client_keys\\"
KEYS_PATH = r"keys\\"
DEF_KEYS_PATH = r"keys\default\\"
DB_PATH = r".\database\server.db"
LOGIN_INFO_PATH = r"login_info\\"

GET_LOGIN_INFO = True
RESTART_DB = True
SEND_DELAY = 0.01
MAX_DATA_SIZE = 600
MAX_PACKET_TIMEOUT = 0.5
