import logging
import json
import os.path
import socket
import time
from collections import deque
from threading import Thread
from typing import List, Optional, Tuple, Deque, Dict
from client_dataclasses import *
from protocol import *
from settings import *
from utils import *
from math import ceil
from TaskHandler import *

FILE_NAME: str
STRIPE_ID: str
NAME: str
FINAL_IN_SEQ: int
TASK: dict


class Client:
    def __init__(self, name: str, port: int):
        self.name = name
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((CLIENT_IP, port))
        self._server_addr = (SERVER_IP, SERVER_PORT)
        self.tasks: Deque[Tuple[tuple | None, TASK]] = deque()  # deque of (address, task)
        self.task_wait_queue: Deque[tuple[Tuple | None, TASK]] = deque()
        self.peers: Dict[Tuple, NAME] = {}
        self.peer_names: Dict[NAME, Tuple] = {}
        self.files_on_server: Dict[FILE_NAME, File] = {}
        self.sum_backups_size: float = 0
        self.stripe_handlers: Dict[STRIPE_ID, RecvStripeHandler] = {}
        self.recv_file_handlers: Dict[FILE_NAME, RecvFileHandler] = {}
        self.stripe_to_filename: Dict[STRIPE_ID, FILE_NAME] = {}

    def send_to_peer(self, msg: Message, addr: tuple):
        data = json.dumps(msg.to_dict()).encode()
        self.sock.sendto(data, addr)

    def send_to_server(self, msg: Message):
        data = json.dumps(msg.to_dict()).encode()
        self.sock.sendto(data, self._server_addr)

    def connect_to_peer(self, msg: ConnectToPeer):
        print(f"connecting to peer: {msg.peer_name} on address {msg.peer_address}")
        connect_msg = Connect(name=self.name)
        self.send_to_peer(connect_msg, msg.peer_address)

    def remove_peer(self, address):
        try:
            del self.peer_names[self.peers[address]]
            del self.peers[address]
        except KeyError:
            print(f"No such client: {address}")

    def add_peer(self, addr, name):
        if addr in self.peers:
            logging.debug(f"Peer {name} on address {addr} is already known")
            return
        self.peers[addr] = name
        self.peer_names[name] = addr

    def req_send_file(self, absolute_path: str):
        file = abstract_file(absolute_path)
        dicts = [
            {"hash": stripe.hash, "id": stripe.id, "is_parity": stripe.is_parity, "is_first": stripe.is_first}
            for stripe in file.stripes
        ]
        self.files_on_server[file.name] = file
        request = SendFileReq(file_name=file.name, file_hash=file.hash, size=file.len, stripes=dicts)
        self.send_to_server(request)

    def send_stripe(self, stripe_id: str, peer_addr: tuple):
        with open("temp/stripes/" + stripe_id, "rb") as f:
            data = f.read()
        new_stripe_msg = NewStripe(id=stripe_id, size=len(data), amount=ceil(len(data) / MAX_DATA_SIZE))
        self.send_to_peer(new_stripe_msg, peer_addr)
        time.sleep(0.1)
        k = 0
        while k * MAX_DATA_SIZE < len(data):
            append_stripe_msg = AppendStripe(
                id=stripe_id, seq=k, raw=encode_for_json(data[k * MAX_DATA_SIZE : (k + 1) * MAX_DATA_SIZE])
            )
            self.send_to_peer(append_stripe_msg, peer_addr)
            k += 1
            time.sleep(SEND_DELAY)
        # TEMP STRIPE NO LONGER NEEDED:
        remove_temp_stripes(stripe_id, path=TEMP_STRIPE_PATH)

    def handle_get_stripe(self, msg: GetStripe, peer_addr: tuple):
        stripe_id = msg.stripe_id
        if not os.path.isfile(BACKUP_PATH + stripe_id):
            self.task_wait_queue.append((None, {"cmd": "handle_get_stripe", "msg": msg, "addr": peer_addr}))
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
                AppendGetStripe(
                    stripe_id=stripe_id, seq=k, raw=encode_for_json(data[k * MAX_DATA_SIZE : (k + 1) * MAX_DATA_SIZE])
                ),
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

    @staticmethod
    def handle_file_list_resp(resp: FileListResp):
        print(f"files on server: {resp.files}")

    def request_file(self, filename: str):
        self.send_to_server(GetFileReq(file_name=filename))

    def create_recv_file_handler(self, msg: GetFileResp):
        file_name = msg.file_name
        self.recv_file_handlers[file_name] = RecvFileHandler(GetFileResp(file_name=file_name, stripes=msg.stripes))
        for msg_stripe in msg.stripes:
            self.stripe_to_filename[msg_stripe["id"]] = file_name
            self.send_to_peer(GetStripe(stripe_id=msg_stripe["id"]), tuple(msg_stripe["addr"]))

    def handle_self(self, msg: dict):
        match msg["cmd"]:
            case "handle_get_stripe":
                self.handle_get_stripe(msg["msg"], msg["addr"])

    def handle_server(self, msg: dict):
        match msg["cmd"]:
            case "connect_to_peer":
                self.connect_to_peer(ConnectToPeer(peer_name=msg["name"], peer_address=tuple(msg["peer_address"])))
            case "send_file_resp":
                self.handle_file_resp(SendFileResp(file_name=msg["name"], stripes=msg["stripes"]))
            case "file_list_resp":
                self.handle_file_list_resp(FileListResp(files=msg["files"]))
            case "get_file_resp":
                self.create_recv_file_handler(GetFileResp(file_name=msg["file"], stripes=msg["stripes"]))
                # todo you were here

    def handle_peer(self, task: Tuple[tuple, dict]):
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
                    NewStripe(id=msg["id"], size=msg["size"], amount=msg["amount"]),
                    temp_dir_path=TEMP_PEER_STRIPE_PATH,
                    final_dir_path=BACKUP_PATH,
                )
            case "append_stripe":
                self.stripe_handlers[msg["id"]].new_append(AppendStripe(id=msg["id"], raw=msg["raw"], seq=msg["seq"]))
            case "get_stripe":
                print("got get_stripe")
                self.handle_get_stripe(GetStripe(stripe_id=msg["id"]), addr)
            case "get_stripe_resp":
                self.recv_file_handlers[self.stripe_to_filename[msg["id"]]].new_recv_handler(
                    GetStripeResp(stripe_id=msg["id"], amount=msg["amount"], size=msg["size"])
                )
            case "append_get_stripe":
                self.recv_file_handlers[self.stripe_to_filename[msg["id"]]].append_stripe(
                    AppendGetStripe(stripe_id=msg["id"], seq=msg["seq"], raw=msg["raw"])
                )

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
            elif addr in self.peers:
                self.handle_peer(task)
                continue
            elif addr is None:
                self.handle_self(msg)

    def receive_data(self):
        while True:
            data, addr = self.sock.recvfrom(1024)
            try:
                msg = json.loads(data.decode())
                if addr == self._server_addr:
                    logging.debug(f"Received message from server: {msg}")
                    self.tasks.append((addr, msg))
                elif addr in self.peers:
                    logging.debug(f"Received message from peer: {addr} msg: {msg}")
                    self.tasks.append((addr, msg))
                elif msg["cmd"] == "connect":
                    self.add_peer(addr, msg["name"])
            except json.JSONDecodeError:
                print(f"Invalid JSON format for data: {data.decode()}")


def main():
    logging.basicConfig(level=LOGLEVEL)
    if len(sys.argv) < 3:
        name = "Omri"
        port = 30000
    else:
        name = sys.argv[1]
        port = int(sys.argv[2])
    client = Client(name, port)
    if not LOCALHOST:
        client._server_addr = (input("enter ip \r\n"), SERVER_PORT)
    logging.debug(f"Client {name } up and running on port {port}")
    receive_thread = Thread(target=client.receive_data)
    task_thread = Thread(target=client.handle_tasks)
    receive_thread.start()
    task_thread.start()
    connect_msg = Connect(name=client.name, register=True)
    client.send_to_server(connect_msg)
    if name == "alice":
        time.sleep(1.5)
        client.req_send_file(r"C:\Cyber\Projects\P2P-backup\for_testing\text.txt")
        time.sleep(2)
        client.request_file_list()
        time.sleep(1.5)
        client.request_file("text.txt")
        time.sleep(3)
        client.req_send_file(r"C:\Cyber\Projects\P2P-backup\for_testing\video.mp4")
        time.sleep(45)
        client.request_file("video.mp4")


if __name__ == "__main__":
    main()
