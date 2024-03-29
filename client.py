import collections
import json
import os.path
import socket
import sys
from collections import deque
from threading import Thread
from typing import Deque
from utils import *
from math import ceil
from task_handler import *
import encryption_utils
from cryptography.fernet import Fernet, InvalidToken


FILE_NAME: str
STRIPE_ID: str
NAME: str
FINAL_IN_SEQ: int
TASK: dict
ADDRESS = tuple


class Client:
    def __init__(self, name: str, port: int, chacha_key=None):
        self.name = name
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((CLIENT_IP, port))
        self._server_addr = (SERVER_IP, SERVER_PORT)
        self.tasks: Deque[Tuple[tuple | None, TASK]] = deque()  # deque of (address, task)
        self.task_wait_queue: Deque[tuple[Tuple | None, TASK]] = deque()
        self.peers: Dict[ADDRESS, NAME] = {}
        self.peer_names: Dict[NAME, Tuple] = {}
        self.files_on_server: Dict[FILE_NAME, File] = {}
        self.sum_backups_size: float = 0
        self.stripe_handlers: Dict[STRIPE_ID, RecvStripeHandler] = {}
        self.recv_file_handlers: Dict[FILE_NAME, RecvFileHandler] = {}
        self.stripe_to_filename: Dict[STRIPE_ID, FILE_NAME] = {}
        self.chacha_key = chacha_key
        self.server_fernet = None
        self.peer_fernets: Dict[ADDRESS, Fernet] = {}
        self.file_list_received: List[str] | None = None
        self.peer_handshakes: Dict[ADDRESS, encryption_utils.ConnectToPeerTask] = {}

    def send_to_peer(self, msg: Message, addr: tuple):
        data = json.dumps(msg.to_dict()).encode()
        if addr in self.peer_fernets:
            data = encryption_utils.encrypt_with_fernet(self.peer_fernets[addr], data)
        else:
            logging.warning(f"no fernet for peer in addr: {addr}")
        self.sock.sendto(data, addr)

    def send_to_server(self, msg: Message):
        data = json.dumps(msg.to_dict()).encode()
        encrypted = encryption_utils.encrypt_with_fernet(self.server_fernet, data)
        self.sock.sendto(encrypted, self._server_addr)

    def connect_to_peer(self, msg: ConnectToPeer):
        if msg.peer_address in self.peers or msg.peer_address in self.peer_fernets:
            logging.debug(f"Peer in addr {msg.peer_address} is already known")
            return
        print(f"connecting to peer: {msg.peer_name} on address {msg.peer_address}")
        a = encryption_utils.ConnectToPeerTask(msg=msg, sock=self.sock, name=self.name)
        self.peer_handshakes[msg.peer_address] = a
        self.peer_fernets[msg.peer_address] = encryption_utils.get_fernet_from_b64(msg.fernet_key)

    def remove_peer(self, address):
        try:
            del self.peer_names[self.peers[address]]
            del self.peers[address]
            del self.peer_fernets[address]
        except KeyError:
            print(f"No such client: {address}")

    def add_peer(self, addr, msg: Connect):
        if addr in self.peers:
            logging.debug(f"Peer {msg.name} on address {addr} is already known")
            return
        self.peer_handshakes[addr].finished = True
        del self.peer_handshakes[addr]
        self.peers[addr] = msg.name
        self.peer_names[msg.name] = addr

    def req_send_file(self, absolute_path: str):
        # check if file encryption key is known:
        if self.chacha_key is None:
            self.send_to_server(GetFileKey())
            self.tasks.append((None, {"task": "req_send_file", "path": absolute_path}))
            return

        file = abstract_file(absolute_path, key=self.chacha_key)
        dicts = [{"hash": stripe.hash, "id": stripe.id, "is_parity": stripe.is_parity, "is_first": stripe.is_first} for stripe in file.stripes]
        self.files_on_server[file.name] = file
        request = SendFileReq(file_name=file.name, file_hash=file.hash, size=file.len, nonce=encode_for_json(file.nonce), stripes=dicts)
        self.send_to_server(request)

    def send_stripe(self, stripe_id: str, peer_addr: tuple):
        with open("temp/stripes/" + stripe_id, "rb") as f:
            data = f.read()
        new_stripe_msg = NewStripe(stripe_id=stripe_id, size=len(data), amount=ceil(len(data) / MAX_DATA_SIZE))
        self.send_to_peer(new_stripe_msg, peer_addr)
        time.sleep(0.1)
        k = 0
        while k * MAX_DATA_SIZE < len(data):
            append_stripe_msg = AppendStripe(stripe_id=stripe_id, seq=k, raw=encode_for_json(data[k * MAX_DATA_SIZE : (k + 1) * MAX_DATA_SIZE]))
            self.send_to_peer(append_stripe_msg, peer_addr)
            k += 1
            time.sleep(SEND_DELAY)
        # TEMP STRIPE NO LONGER NEEDED:
        remove_temp_stripes(stripe_id, path=TEMP_STRIPE_PATH)

    def handle_get_stripe(self, msg: GetStripe, peer_addr: tuple):
        stripe_id = msg.stripe_id
        if not os.path.isfile(BACKUP_PATH + stripe_id):
            self.task_wait_queue.append((None, {"task": "handle_get_stripe", "msg": msg, "addr": peer_addr}))
            return
        with open(BACKUP_PATH + stripe_id, "rb") as f:
            data = f.read()
        size = len(data)
        amount = ceil(size / MAX_DATA_SIZE)
        self.send_to_peer(GetStripeResp(stripe_id=stripe_id, amount=amount, size=size), peer_addr)
        time.sleep(0.1)
        k = 0
        while k * MAX_DATA_SIZE < len(data):
            self.send_to_peer(
                AppendGetStripe(stripe_id=stripe_id, seq=k, raw=encode_for_json(data[k * MAX_DATA_SIZE : (k + 1) * MAX_DATA_SIZE])),
                peer_addr,
            )
            time.sleep(SEND_DELAY)
            k += 1

    def handle_file_resp(self, response: SendFileResp):
        file_name = response.file_name
        for resp in response.stripes:
            self.send_stripe(resp["id"], tuple(resp["addr"]))
            update_stripe_location(self.files_on_server[file_name], resp["id"], resp["peer"])

    def request_file_list(self):
        self.send_to_server(GetFileList())

    def get_file_list(self) -> List[str]:
        self.request_file_list()
        while True:
            time.sleep(0.1)
            files = self.file_list_received
            if files is not None:
                self.file_list_received = None
                return files

    def handle_file_list_resp(self, resp: FileListResp):
        self.file_list_received = resp.files
        print(f"files on server: {resp.files}")

    def request_file(self, filename: str):
        if self.chacha_key is None:
            self.send_to_server(GetFileKey())
            self.task_wait_queue.append((None, {"task": "request_file", "file_name": filename}))
            return
        self.send_to_server(GetFileReq(file_name=filename))

    def create_recv_file_handler(self, msg: GetFileResp):
        file_name = msg.file_name
        self.recv_file_handlers[file_name] = RecvFileHandler(msg, key=self.chacha_key)
        for msg_stripe in msg.stripes:
            self.stripe_to_filename[msg_stripe["id"]] = file_name
            self.send_to_peer(GetStripe(stripe_id=msg_stripe["id"]), tuple(msg_stripe["addr"]))

    def handle_self(self, task: dict):
        match task["task"]:
            case "handle_get_stripe":
                self.handle_get_stripe(task["msg"], task["addr"])
            case "req_send_file":
                self.req_send_file(task["path"])
            case "request_file":
                self.request_file(task["file_name"])

    def handle_server(self, msg: dict):
        match msg["cmd"]:
            case "connect_to_peer":
                self.connect_to_peer(ConnectToPeer.from_dict(msg))
            case "send_file_resp":
                self.handle_file_resp(SendFileResp.from_dict(msg))
            case "file_list_resp":
                self.handle_file_list_resp(FileListResp.from_dict(msg))
            case "get_file_resp":
                self.create_recv_file_handler(GetFileResp.from_dict(msg))
            case "get_file_key_resp":
                self.chacha_key = utils.decode_from_json(GetFileKeyResp.from_dict(msg).key)

    def handle_peer(self, task: Tuple[ADDRESS, dict]):
        addr = task[0]
        msg = task[1]
        match msg["cmd"]:
            case "received_connection":
                if msg["accept"]:
                    # TODO handle this
                    return
                self.remove_peer(addr)
            case "new_stripe":
                self.stripe_handlers[msg["id"]] = RecvStripeHandler(
                    NewStripe.from_dict(msg),
                    temp_dir_path=TEMP_PEER_STRIPE_PATH,
                    final_dir_path=BACKUP_PATH,
                )
            case "append_stripe":
                self.stripe_handlers[msg["id"]].new_append(AppendStripe.from_dict(msg))
            case "get_stripe":
                self.handle_get_stripe(GetStripe.from_dict(msg), addr)
            case "get_stripe_resp":
                self.recv_file_handlers[self.stripe_to_filename[msg["id"]]].new_recv_handler(GetStripeResp.from_dict(msg))
            case "append_get_stripe":
                self.recv_file_handlers[self.stripe_to_filename[msg["id"]]].append_stripe(AppendGetStripe.from_dict(msg))
            case "connect":
                self.add_peer(addr, Connect.from_dict(msg))

    def handle_tasks(self):
        while True:
            if not self.tasks:
                if not self.task_wait_queue:
                    time.sleep(0)  # release GIL
                    continue
                time.sleep(0.1)
                task = self.task_wait_queue.popleft()
            else:
                task = self.tasks.popleft()
            addr = task[0]
            msg = task[1]
            logging.debug(f"the current task is {task if len(msg) < 120 else msg['cmd']}")
            if addr == self._server_addr:
                self.handle_server(msg)  # if task not finished
                continue
            elif addr in self.peers or addr in self.peer_fernets:
                self.handle_peer(task)
                continue
            elif addr is None:
                self.handle_self(msg)

    def receive_data(self):
        while True:
            data, addr = self.sock.recvfrom(2048)
            try:
                if self.server_fernet is None:
                    continue
                if addr == self._server_addr:
                    msg = encryption_utils.decrypt_fernet_to_json(self.server_fernet, data)
                    logging.debug(f"Received message from server: {msg}")
                    self.tasks.append((addr, msg))
                elif addr in self.peers:
                    msg = encryption_utils.decrypt_fernet_to_json(self.peer_fernets[addr], data)
                    logging.debug(f"Received message from peer: {msg}")
                    self.tasks.append((addr, msg))
                elif addr in self.peer_fernets:
                    msg = encryption_utils.decrypt_fernet_to_json(self.peer_fernets[addr], data)
                    logging.debug(f"Received message from peer: {addr} msg: {msg}")
                    self.tasks.append((addr, msg))
                else:
                    print(f"unknown addr: {addr}")

            except (json.JSONDecodeError, TypeError, InvalidToken) as e:
                print(f"Invalid data from address {addr}\ndata: {data.decode()}\n{e=}")
                print(self.peer_fernets[addr])
                raise e


def main():
    logging.basicConfig(level=LOGLEVEL)
    assert len(sys.argv) > 2
    name = sys.argv[1]
    port = int(sys.argv[2])

    client = Client(name, port)
    logging.debug(f"Client {name } up and running on port {port}")

    p = Path(CLIENT_KEYS_PATH) / name
    if not p.is_dir():
        os.makedirs(p)
    private_key, public_key = encryption_utils.generate_ecdh_keys(path_private=p / "private.pem", path_public=p / "public.pem")

    f = encryption_utils.HandshakeWithServerTask(
        private_key=private_key, public_key=public_key, server_addr=SERVER_ADDR, sock=client.sock
    ).begin()
    client.server_fernet = f
    password = "lalalolo"
    hashed_password = encryption_utils.hash_password(password)

    if RESTART_DB:
        chacha_key = utils.get_chacha_key()
        client.chacha_key = chacha_key
        register_task = encryption_utils.RegisterToServerTask(
            name=client.name,
            password_hash=hashed_password,
            sock=client.sock,
            file_encryption_key=client.chacha_key,
            fernet=client.server_fernet,
        )

        register_task.begin()
    else:
        login_task = encryption_utils.LoginToServerTask(
            name=client.name,
            password_hash=hashed_password,
            sock=client.sock,
            fernet=client.server_fernet,
        )
        login_task.begin()

    receive_thread = Thread(target=client.receive_data)
    task_thread = Thread(target=client.handle_tasks)
    receive_thread.start()
    task_thread.start()


if __name__ == "__main__":
    main()
