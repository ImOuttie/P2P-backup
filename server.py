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


class Server:
    def __init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((SERVER_IP, SERVER_PORT))
        self.clients: Dict[Tuple, str] = {}
        self.names: Dict[str, Tuple] = {}
        self.tasks: Deque[Tuple[Tuple, Dict]] = deque()

    def add_client(self, name: str, address):
        self.clients[address] = name
        self.names[name] = address
        logging.debug(f'Client connected: {name, address}')

    def remove_client(self, address):
        try:
            del self.names[self.clients[address]]
            del self.clients[address]
        except KeyError:
            print(f'No such client: {address}')

    def create_connection(self, client1: tuple, client2: tuple):
        logging.debug(f'Creating connection between {self.clients[client1]}: {client1} and'
                      f' {self.clients[client2]}: {client2}')
        data1 = json.dumps({"cmd": "connect_to_peer", "peer_address": client1, "name": self.clients[client1]}).encode()
        data2 = json.dumps({"cmd": "connect_to_peer", "peer_address": client2, "name": self.clients[client2]}).encode()
        self.sock.sendto(data2, client1)
        self.sock.sendto(data1, client2)

    def handle_client(self, client_addr, msg: dict):
        if msg["cmd"] == "get_connection":
            for client2 in self.clients.keys():
                if client2 != client_addr:
                    self.create_connection(client2, client_addr)
                    return

            self.tasks.append((client_addr, msg))

    def handle_tasks(self):
        while True:
            if not self.tasks:
                time.sleep(0)  # release GIL; don't waste rest of quantum
                continue
            addr, msg = self.tasks.pop()
            self.handle_client(addr, msg)

    def receive_data(self):
        while True:
            data, address = self.sock.recvfrom(1024)
            if address in self.clients:
                msg = json.loads(data.decode())
                logging.debug(f'Received message: {msg} from {self.clients[address]}')
                self.tasks.append((address, msg))
            else:
                msg = json.loads(data.decode())
                logging.debug(f'Received message: {msg} from {address}')
                if msg["cmd"] == "connect":
                    self.add_client(msg["name"], address)



def main():
    logging.basicConfig(level=LOGLEVEL)
    p2p_server = Server()
    logging.debug(f'Server up and running on address {SERVER_IP} port {SERVER_PORT}')
    receive_thread = Thread(target=p2p_server.receive_data)
    task_thread = Thread(target=p2p_server.handle_tasks)
    receive_thread.start()
    task_thread.start()
    if not LOCALHOST:
        address = (input('enter ip\r\n'), int(input('enter port\r\n')))
        for i in range(0, 20):
            p2p_server.sock.sendto(b'random data', address)
            time.sleep(0.5)
            print('done')
    # p2p_server.sock.close()


if __name__ == '__main__':
    main()