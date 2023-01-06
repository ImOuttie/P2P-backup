import json
import logging
import socket
import threading
from settings import *
from utils import *
from collections import deque
from threading import Thread
import time
from typing import List, Optional, Tuple, Dict, Deque
from dataclasses import dataclass, field
from my_classes import *


Files = List[File]
Name = str
Filename: str
Address = Tuple


class Server:
    def __init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((SERVER_IP, SERVER_PORT))
        self.clients: Dict[Address, Name] = {}
        self.names: Dict[Name, Address] = {}
        self.files: Dict[Name, Files] = {}
        self.file_names: Dict[Name, Dict[Filename, File]]
        self.tasks: Deque[Tuple[Optional[Tuple], Dict]] = deque()

    def add_client(self, name: str, address: Tuple):
        self.clients[address] = name
        self.names[name] = address
        self.files[name] = []
        logging.debug(f"Client connected: {name, address}")

    def remove_client(self, address):
        try:
            del self.files[self.clients[address]]
            del self.names[self.clients[address]]
            del self.clients[address]
        except KeyError:
            print(f"No such client: {address}")

    def create_connection(self, client1: tuple, client2: tuple):
        logging.debug(
            f"Creating connection between {self.clients[client1]}: {client1} and"
            f" {self.clients[client2]}: {client2}"
        )
        data1 = json.dumps(
            {
                "cmd": "connect_to_peer",
                "peer_address": client1,
                "name": self.clients[client1],
            }
        ).encode()
        data2 = json.dumps(
            {
                "cmd": "connect_to_peer",
                "peer_address": client2,
                "name": self.clients[client2],
            }
        ).encode()
        self.sock.sendto(data2, client1)
        self.sock.sendto(data1, client2)

    def find_connection(self, client_addr: Tuple) -> Optional[Tuple]:
        for client in self.clients.keys():
            if client != client_addr:
                return client
        # if not found client return none
        return

    def handle_file_req(self, user: str, request: dict):
        file_name = request["name"]
        file_hash = request["hash"]
        new_file = File(owner=user, hash=file_hash, name=file_name)
        self.files[user].append(new_file)
        for stripe in request["stripes"]:
            new_stripe = FileStripe(hash=stripe["hash"], is_parity=stripe["is_parity"])
            new_file.stripes.append(new_stripe)
        print(new_file)
        self.tasks.append((None, {"task": "find_location_for_data", "client": user, file_name: new_file.name}))

    def handle_self(self, task: dict):
        if task["task"] == "find_location_for_data":
            pass

    def handle_client(self, client_addr, msg: dict):
        if msg["cmd"] == "get_connection":
            client = self.find_connection(client_addr)
            if not client:
                self.tasks.append((client_addr, msg))
                return
            self.create_connection(client_addr, client)
        elif msg["cmd"] == "send_file_req":
            name = self.clients[client_addr]
            self.handle_file_req(name, msg)

    def handle_tasks(self):
        while True:
            if not self.tasks:
                time.sleep(0)  # release GIL; don't waste rest of quantum
                continue
            addr, msg = self.tasks.pop()
            if addr:
                self.handle_client(addr, msg)
                continue

    def receive_data(self):
        while True:
            data, address = self.sock.recvfrom(1024)
            try:
                if address in self.clients:
                    msg = json.loads(data.decode())
                    logging.debug(
                        f"Received message: {msg} from {self.clients[address]}"
                    )
                    self.tasks.append((address, msg))
                else:
                    msg = json.loads(data.decode())
                    logging.debug(f"Received message: {msg} from {address}")
                    if msg["cmd"] == "connect":
                        self.add_client(msg["name"], address)
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
