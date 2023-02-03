from utils import *

from server_dataclasses import *
from protocol import *
from settings import *
import json
import logging
import socket
import threading
from collections import deque
from threading import Thread
import time
from typing import List, Tuple, Dict, Deque
from dataclasses import dataclass, field


Files = List[File]
NAME = str
FILENAME: str
ADDRESS = Tuple


class Server:
    def __init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((SERVER_IP, SERVER_PORT))
        self.clients: Dict[ADDRESS, NAME] = {}
        self.names: Dict[NAME, ADDRESS] = {}
        self.file_names: Dict[NAME, Dict[FILENAME, File]]
        self.tasks: Deque[Tuple[Tuple | None, Dict]] = deque()
        self.users: Dict[NAME, User] = {}
        self.task_wait_queue: Deque[Tuple[Tuple | None, Dict]] = deque()
        self.avg_storage = 4

    def add_client(self, msg: Connect, address: tuple):
        name = msg.name
        self.clients[address] = name
        self.names[name] = address
        self.users[name] = User(name=name, current_addr=address)

    def remove_client(self, address):
        try:
            del self.users[self.clients[address]]
            del self.names[self.clients[address]]
            del self.clients[address]
        except KeyError:
            print(f"No such client: {address}")

    def send_to_client(self, msg: Message, addr: tuple):
        data = json.dumps(msg.to_dict()).encode()
        self.sock.sendto(data, addr)

    def create_connection(self, client1: tuple, client2: tuple):
        logging.debug(f"Creating connection between {self.clients[client1]}: {client1} and {self.clients[client2]}: {client2}")
        connect_msg1 = ConnectToPeer(peer_name=self.clients[client1], peer_address=client1)
        connect_msg2 = ConnectToPeer(peer_name=self.clients[client2], peer_address=client2)
        self.send_to_client(connect_msg1, client2)
        self.send_to_client(connect_msg2, client1)

    def find_connection(self, client_addr: Tuple) -> Tuple | None:
        for client in self.clients:
            if client != client_addr:
                return client
        # if not found client return none
        return

    def handle_file_req(self, user: str, request: SendFileReq):
        new_file = File(owner=user, hash=request.hash, name=request.file_name, len=request.size)
        self.users[user].owned_files.append(new_file)
        for stripe in request.stripes:
            new_stripe = FileStripe(hash=stripe["hash"], is_parity=stripe["is_parity"], id=stripe["id"], is_first=stripe["is_first"])
            new_file.stripes.append(new_stripe)
        print(f"new file: {new_file}")
        self.tasks.append((None, {"task": "find_location_for_data", "client": user, "file": new_file}))

    def find_location_for_data(self, owner: str, filename: str) -> List | None:
        """ returns list of three available users if found, otherwise returns none"""
        availables = []
        for user in self.users.values():
            if user.name == owner or user.storing_gb > self.avg_storage:
                continue
            availables.append(user)
            if len(availables) == 3:
                return availables
        # TODO: FIX ASSUMPTION THAT ALL CLIENTS ARE AVAILABLE, CHECK FOR SIZE
        return None

    def send_addrs_to_client(self, owner: User, users: List[User], file: File):
        for user in users:
            self.create_connection(owner.current_addr, user.current_addr)
        file_stripes = []
        for user, filestripe in zip(users, file.stripes):
            file_stripes.append({"id": filestripe.id, "peer": user.name, "addr": user.current_addr})
            filestripe.location = user.name
        resp = SendFileResp(file_name=file.name, stripes=file_stripes)
        self.send_to_client(resp, owner.current_addr)

    def send_file_list(self, request: GetFileList, addr: tuple):
        self.send_to_client(FileListResp(files=[file.name for file in self.users[self.clients[addr]].owned_files]), addr)

    def handle_file_request(self, req: GetFileReq, addr: tuple):
        user = self.users[self.clients[addr]]
        file = find_file_by_name(user.owned_files, req.file_name)
        if not file:
            # TODO: HANDLE
            return
        dicts = []
        count = 0
        for stripe in file.stripes:
            # TODO: CHECK IF CLIENT IS AVAILABLE
            self.create_connection(self.names[stripe.location], addr)
            dicts.append({"id": stripe.id, "is_parity": stripe.is_parity, "is_first": stripe.is_first, "peer": stripe.location, "addr": self.names[stripe.location]})
            count += 1
            if count == 2:
                break
        self.send_to_client(GetFileResp(file_name=req.file_name, stripes=dicts), addr)

    def handle_self(self, task: dict):
        match task["task"]:
            case "find_location_for_data":
                owner = self.users[task["client"]]
                file = task["file"]
                availables = self.find_location_for_data(owner.name, file.name)
                if not availables:
                    self.task_wait_queue.append((None, task))
                    return
                self.send_addrs_to_client(owner, availables, file)

    def handle_client(self, client_addr, msg: dict):
        match msg["cmd"]:
            case "send_file_req":
                file_req_msg = SendFileReq(file_name=msg["name"], hash=msg["hash"], size=msg["size"], stripes=msg["stripes"])
                self.handle_file_req(self.clients[client_addr], file_req_msg)
                return
            case "get_file_list":
                self.send_file_list(GetFileList(), client_addr)
                return
            case "get_file_req":
                self.handle_file_request(GetFileReq(file_name=msg["file"]), addr=client_addr)
                return
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

    def receive_data(self):
        while True:
            data, address = self.sock.recvfrom(1024)
            try:
                if address in self.clients:
                    msg = json.loads(data.decode())
                    logging.debug(f"Received message: {msg} from {self.clients[address]}")
                    self.tasks.append((address, msg))
                else:
                    msg = json.loads(data.decode())
                    logging.debug(f"Received message: {msg} from {address}")
                    if msg["cmd"] == "connect" and msg["register"]:
                        self.add_client(Connect(name=msg["name"], register=msg["register"]), address)
                        # TODO: HANDLE NON REGISTER CONNECTION
            except json.JSONDecodeError:
                print(f"Invalid msg: {data.decode()}")


def main():
    logging.basicConfig(level=LOGLEVEL)
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
