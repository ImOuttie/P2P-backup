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
        self.tasks: Deque[Tuple, dict] = deque()
        self.peers: Dict[Tuple, str] = {}

    def connect_to_peer(self, peer_name: str, peer_addr: tuple) -> bool:
        if peer_addr in self.peers:
            return True
        print(f'connecting to peer: {peer_name} on address {peer_addr}')
        data = json.dumps({"cmd": "connect", "name": self.name}).encode()
        self.sock.sendto(data, peer_addr)
        return False

    def handle_server(self, task) -> bool:
        msg = task[1]
        if msg["cmd"] == "connect_to_peer":
            peer_addr = tuple(msg["peer_address"])  # json doesn't support tuples
            peer_name = msg["name"]
            return self.connect_to_peer(peer_name, peer_addr)

    def handle_peer(self, task: tuple):
        msg = task[1]
        if task[0] in self.peers:
            pass
        else:
            if msg["cmd"] == "connect":
                self.peers[task[0]] = msg["name"]
                return

    def send_to_server(self, msg: dict):
        data = json.dumps(msg).encode()
        self.sock.sendto(data, self._server_addr)

    def handle_tasks(self):
        while True:
            if not self.tasks:
                time.sleep(0)  # release GIL
                continue
            task = self.tasks.pop()
            logging.debug(f'the current task is {task}')
            if task[0] == self._server_addr:
                if not self.handle_server(task):  # if task not finished
                    # self.tasks.append(task)
                    pass
            else:
                self.handle_peer(task)

    def receive_data(self):
        while True:
            data, addr = self.sock.recvfrom(1024)
            if addr == self._server_addr:
                msg = json.loads(data.decode())
                logging.debug(f'Received message from server: {msg}')
                self.tasks.append((addr, msg))
            else:
                msg = json.loads(data.decode())
                logging.debug(f'Received message from peer: {addr} msg: {msg}')
                self.tasks.append((addr, msg))


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
        client._server_addr = (input('enter ip \r\n'), SERVER_PORT)
    logging.debug(f'Client {name } up and running on port {port}')
    receive_thread = Thread(target=client.receive_data)
    task_thread = Thread(target=client.handle_tasks)
    receive_thread.start()
    task_thread.start()
    client.send_to_server({"cmd": "connect", "name": client.name})
    time.sleep(1)
    if name == "alice":
        client.send_to_server({"cmd": "get_connection"})


if __name__ == '__main__':
    main()