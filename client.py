import json
import logging
import socket
import time
import sys
from settings import *
from utils import *
from collections import deque
from threading import Thread
from typing import List, Optional, Tuple, Deque, Dict


class Client:
    def __init__(self, name: str, port: int):
        self.name = name
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((CLIENT_IP, port))
        self._server_addr = (SERVER_IP, SERVER_PORT)
        self.tasks: Deque[Tuple, dict] = deque()  # deque of (address, task)
        self.wait_queue: Dict[Tuple, List] = {}
        self.peers: Dict[Tuple, str] = {}

    def connect_to_peer(self, peer_name: str, peer_addr: tuple) -> bool:
        print(f"connecting to peer: {peer_name} on address {peer_addr}")
        data = json.dumps({"cmd": "connect", "name": self.name}).encode()
        self.sock.sendto(data, peer_addr)
        return False  # task not finished until received connection

    def remove_peer(self, address):
        try:
            del self.peers[address]
        except KeyError:
            print(f"No such client: {address}")

    def add_peer(self, addr, name):
        if addr not in self.peers:
            logging.debug(f"Peer {name} from address {addr} is already known")
        self.peers[addr] = name

    def handle_server(self, msg: dict) -> bool:
        if msg["cmd"] == "connect_to_peer":
            peer_addr = tuple(msg["peer_address"])  # json doesn't support tuples
            peer_name = msg["name"]
            return self.connect_to_peer(peer_name, peer_addr)

    def handle_peer(self, task: Tuple[tuple, dict]):
        msg = task[1]
        addr = task[0]
        if msg["cmd"] == "received_connection":
            if msg["accept"]:
                # TODO handle this
                pass
            else:
                self.remove_peer(addr)
        elif msg["cmd"] == "send_file":
            pass

    def send_to_server(self, msg: dict):
        data = json.dumps(msg).encode()
        self.sock.sendto(data, self._server_addr)

    def handle_tasks(self):
        while True:
            if not self.tasks:
                time.sleep(0)  # release GIL
                continue
            task = self.tasks.pop()
            addr = task[0]
            msg = task[1]
            logging.debug(f"the current task is {task}")
            if addr == self._server_addr:
                if not self.handle_server(msg):  # if task not finished
                    if addr in self.wait_queue:
                        self.wait_queue[addr].append(task)
                    else:
                        self.wait_queue[addr] = [task]
            if addr in self.peers:
                self.handle_peer(task)

    def receive_data(self):
        while True:
            data, addr = self.sock.recvfrom(1024)
            try:
                msg = json.loads(data.decode()[0:100])
                if addr == self._server_addr:
                    logging.debug(f"Received message from server: {msg}")
                    self.tasks.append((addr, msg))
                elif addr in self.peers:
                    logging.debug(f"Received message from peer: {addr} msg: {msg}")
                    self.tasks.append((addr, msg))
                else:
                    self.add_peer(addr, msg["name"])
            except json.JSONDecodeError:
                print(f'Invalid JSON format for data: {data.decode()}')


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
    client.send_to_server({"cmd": "connect", "name": client.name})
    time.sleep(1)
    if name == "alice":
        client.send_to_server({"cmd": "get_connection"})


if __name__ == "__main__":
    main()
