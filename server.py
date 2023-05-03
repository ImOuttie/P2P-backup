import encryption_utils
from utils import *

from server_dataclasses import UserFile, FileStripe, User
from protocol import *
from settings import *
import json
import logging
import socket
from collections import deque
from threading import Thread
import time
from typing import List, Tuple, Dict, Deque
from cryptography.fernet import Fernet
from database.sql_loader import SQLLoader
from pathlib import Path

Files = List[UserFile]
NAME = str
FILENAME: str
ADDRESS = Tuple[str, int]
KEY: str


class Server:
    def __init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((SERVER_IP, SERVER_PORT))
        self.clients: Dict[ADDRESS, NAME] = {}
        self.names: Dict[NAME, ADDRESS] = {}
        self.file_names: Dict[NAME, Dict[FILENAME, UserFile]] = {}
        self.tasks: Deque[Tuple[ADDRESS | None, Dict]] = deque()
        self.users: Dict[NAME, User] = {}
        self.task_wait_queue: Deque[Tuple[Tuple | None, Dict]] = deque()
        self.avg_storage = 4
        self.fernets: Dict[ADDRESS, Fernet] = {}
        self.private_key, self.public_key = encryption_utils.generate_ecdh_keys(
            path_private="keys/server_keys/private.PEM", path_public="keys/server_keys/public.PEM"
        )
        self.database = SQLLoader(db_file_path=DB_PATH)

    def load_client(self, msg: Login, address: ADDRESS):
        user = self.database.load_user_data(msg.name, address)
        if user is None:
            self.send_to_client(LoginResp(ServerLoginResponse.NAME_INVALID), address)
            return
        if not self.database.check_user_password(user, msg.password_hash):
            self.send_to_client(LoginResp(ServerLoginResponse.INCORRECT_PASSWORD), address)
            return
        name = user.name
        self.clients[address] = user.name
        self.names[name] = address
        self.users[name] = user
        self.send_to_client(LoginResp(ServerLoginResponse.SUCCESS), address)
        logging.debug(f"Client {name} successfully signed in")

    def register_client(self, msg: Register, addr: tuple):
        if self.database.check_if_user_exist_by_name(msg.name):
            self.send_to_client(RegisterResp(ServerRegisterResponse.NAME_TAKEN), addr)
            return

        user = self.database.add_user(msg.name, addr, msg.password_hash, msg.file_encryption_key)
        name = user.name
        self.clients[addr] = name
        self.names[name] = addr
        self.users[name] = user
        self.file_names[msg.name] = {}
        self.send_to_client(RegisterResp(ServerRegisterResponse.SUCCESS), addr)
        logging.debug(f"Client {name} successfully registered")

    def remove_client(self, address):
        try:
            del self.users[self.clients[address]]
            del self.names[self.clients[address]]
            del self.clients[address]
        except KeyError:
            print(f"No such client: {address}")

    def send_to_client(self, msg: Message, addr: tuple):
        data = json.dumps(msg.to_dict()).encode()
        encrypted = encryption_utils.encrypt_with_fernet(self.fernets[addr], data)
        self.sock.sendto(encrypted, addr)

    def decrypt_msg(self, data: bytes, addr: ADDRESS) -> dict:
        f = self.fernets[addr]
        return json.loads(encryption_utils.decrypt_with_fernet(f, ciphertext=data).decode())

    def create_connection(self, client1: tuple, client2: tuple):
        logging.debug(f"Creating connection between {self.clients[client1]}: {client1} and {self.clients[client2]}: {client2}")
        key = encryption_utils.generate_b64_fernet_key()
        connect_msg1 = ConnectToPeer(peer_name=self.clients[client1], peer_address=client1, fernet_key=key)
        connect_msg2 = ConnectToPeer(peer_name=self.clients[client2], peer_address=client2, fernet_key=key)
        self.send_to_client(connect_msg1, client2)
        self.send_to_client(connect_msg2, client1)

    def find_connection(self, client_addr: Tuple) -> Tuple | None:
        for client in self.clients:
            if client != client_addr:
                return client
        # if not found client return none
        return None

    def handle_file_req(self, user: User, request: SendFileReq):
        if self.database.is_file_exist_by_name(user, request.file_name):
            logging.debug(f"Client {user.name} tried to backup file that is already backed up or has the same name: {request.file_name}")
            return
        availables = self.find_location_for_data(user.name)
        if availables is None:
            self.task_wait_queue.append((None, {"task": "find_location_for_data", "client": user, "msg": request}))
            return
        file = self.add_file_to_db(user, request, availables)
        if file is None:
            logging.debug(f"Couldn't backup file {request.file_name} from client {user.name}, perhaps because of its size.")
            return
        self.send_addrs_to_client(user, availables, file)

    def find_location_for_data(self, owner: str) -> List[User] | None:
        """Returns list of three available users if found. Otherwise returns None."""
        availables = []
        for user in self.users.values():
            if user.name == owner or user.storing_gb > self.avg_storage:
                continue
            availables.append(user)
            if len(availables) == 3:
                return availables
        # TODO: FIX ASSUMPTION THAT ALL CLIENTS ARE AVAILABLE, CHECK FOR SIZE
        return None

    def send_addrs_to_client(self, owner: User, users: List[User], file: UserFile):
        for user in users:
            self.create_connection(owner.current_addr, user.current_addr)
        file_stripes = []
        for file_stripe in file.stripes:
            peer_name = file_stripe.location
            file_stripes.append({"id": file_stripe.id, "peer": peer_name, "addr": self.names[peer_name]})
        resp = SendFileResp(file_name=file.name, stripes=file_stripes)
        self.send_to_client(resp, owner.current_addr)

    def send_file_list(self, request: GetFileList, addr: tuple):
        self.send_to_client(FileListResp(files=[file.name for file in self.users[self.clients[addr]].owned_files]), addr)

    def handle_file_request(self, req: GetFileReq, addr: tuple):
        user = self.users[self.clients[addr]]
        file = find_file_by_name(user.owned_files, req.file_name)
        if file is None:
            # TODO: HANDLE
            return
        dicts = []
        count = 0
        clients_needing_connection = []
        for stripe in file.stripes:
            # TODO: CHECK IF CLIENT IS AVAILABLE
            client_name = stripe.location
            if client_name not in self.users:
                continue
            client_user = self.users[client_name]
            clients_needing_connection.append(client_user)
            dicts.append(
                {
                    "id": stripe.id,
                    "is_parity": stripe.is_parity,
                    "is_first": stripe.is_first,
                    "peer": client_user.name,
                    "addr": client_user.current_addr,
                    "hash": stripe.hash,
                }
            )
            count += 1
            if count == 2:
                break
        if count != 2:
            self.task_wait_queue.append((None, {"task": "handle_file_request", "user": user, "msg": req}))
            return
        for user in clients_needing_connection:
            self.create_connection(user.current_addr, addr)
        self.send_to_client(GetFileResp(file_name=req.file_name, stripes=dicts, nonce=file.nonce), addr)

    def add_file_to_db(self, owner: User, msg: SendFileReq, availables: List[User]) -> UserFile | None:
        as_gb = gb_from_amount__bytes(msg.size)
        if owner.storing_gb + as_gb > self.avg_storage:
            logging.debug(f"Client {owner.name} tried to backup file too large for their remaining capacity\n"
                          f"{msg.file_name}\n{msg.size}")
            return None

        file_stripes: List[GetFileRespStripe] = []
        for file_stripe, user in zip(msg.stripes, availables):
            stripe = {
                "id": file_stripe["id"],
                "hash": file_stripe["hash"],
                "peer": user.name,
                "addr": user.current_addr,
                "is_first": file_stripe["is_first"],
                "is_parity": file_stripe["is_parity"],
            }
            file_stripes.append(stripe)

        file = self.database.add_file(
            filename=msg.file_name,
            file_hash=msg.hash,
            file_len=msg.size,
            nonce=msg.nonce,
            user=owner,
            user_file_stripes=file_stripes,
        )
        return file

    def handle_get_file_key(self, msg: GetFileKey, addr: ADDRESS):
        user = self.users[self.clients[addr]]
        key = self.database.get_user_file_key(user)
        self.send_to_client(GetFileKeyResp(key=key), addr)

    def handle_auth(self, data: bytes, addr: ADDRESS):
        try:
            msg = json.loads(data.decode())
            match msg["cmd"]:
                case "send_public_key":
                    msg = SendPublicKey(msg["key"])
                    task = encryption_utils.HandshakeWithClientTask(
                        private_key=self.private_key,
                        public_key=self.public_key,
                        client_addr=addr,
                        sock=self.sock,
                        client_msg=msg,
                    )
                    fernet = task.exchange_keys()
                    self.fernets[addr] = fernet
        except json.JSONDecodeError:
            logging.debug(f"Improper data received from addr {addr}\n{data=}")
        except TypeError as e:
            logging.debug(f"Improper data received from addr {addr}\n{data=}\n{e=}")

    def handle_self(self, task: dict):
        match task["task"]:
            case "find_location_for_data":
                self.handle_file_req(user=task["client"], request=task["msg"])
            case "authenticate":
                pass
            case "handle_file_request":
                self.handle_file_request(req=task["msg"], addr=task["user"].current_addr)

    def handle_client(self, client_addr, msg: dict):
        match msg["cmd"]:
            case "send_file_req":
                file_req_msg = SendFileReq.from_dict(msg)
                user = self.users[self.clients[client_addr]]
                self.handle_file_req(user, file_req_msg)
                return
            case "get_file_list":
                self.send_file_list(GetFileList(), client_addr)
                return
            case "get_file_req":
                self.handle_file_request(GetFileReq.from_dict(msg), addr=client_addr)
                return
            case "get_file_key":
                self.handle_get_file_key(GetFileKey.from_dict(msg), client_addr)
            case _:
                logging.debug(f"Message contained invalid command: {msg}")

    def handle_tasks(self):
        while True:
            if not self.tasks:
                if not self.task_wait_queue:
                    time.sleep(0)  # release GIL; don't waste rest of quantum
                    continue
                addr, msg = self.task_wait_queue.pop()
                if addr:
                    self.handle_client(addr, msg)
                else:
                    self.handle_self(msg)
                continue
            addr, msg = self.tasks.popleft()
            if addr:
                self.handle_client(addr, msg)
                continue
            self.handle_self(msg)

    def handle_logins(self, msg: dict, addr: ADDRESS):
        match msg["cmd"]:
            case "register":
                self.register_client(Register.from_dict(msg), addr)
            case "login":
                self.load_client(Login.from_dict(msg), address=addr)

    def receive_data(self):
        while True:
            data, address = self.sock.recvfrom(1024)
            try:
                if address in self.clients:
                    msg = self.decrypt_msg(data, address)
                    logging.debug(f"Received message: {msg} from {self.clients[address]}")
                    self.tasks.append((address, msg))
                elif address in self.fernets:
                    # clients that have completed handshakes but not yet loaded/registered:
                    msg = self.decrypt_msg(data, address)
                    self.handle_logins(msg, address)
                else:
                    self.handle_auth(data, address)
            except (json.JSONDecodeError, TypeError) as e:
                print(f"Invalid msg: {data.decode()}\n{e=}")


def main():
    logging.basicConfig(level=LOGLEVEL)
    if RESTART_DB:
        if Path(DB_PATH).exists():
            os.remove(DB_PATH)
    p2p_server = Server()
    logging.debug(f"Server up and running on address {SERVER_IP} port {SERVER_PORT}")
    receive_thread = Thread(target=p2p_server.receive_data)
    task_thread = Thread(target=p2p_server.handle_tasks)
    receive_thread.start()
    task_thread.start()
    if not LOCALHOST:
        pass
    # p2p_server.sock.close()


if __name__ == "__main__":
    main()
