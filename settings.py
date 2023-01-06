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
FPATH = r"backups\\"
BYTEORDER = sys.byteorder
