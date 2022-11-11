import logging
import socket
import threading
from settings import *


class Server:
    def __init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((SERVER_IP, SERVER_PORT))
        self.clients = {}
        self.names = {}

    def add_client(self, name: str, address):
        self.clients[address] = name
        self.names[name] = address
        logging.debug(f'Client connected: {name, address}')

    def remove_client(self, address):
        try:
            del self.clients[address]
        except KeyError:
            print(f'No such client: {address}')

    def handle_client(self, client_addr, data):
        msg = data.decode()
        print(f'Received message: {msg} from {self.clients[client_addr]}')
        if msg == "connect":
            print('received msg correctly')
        pass

    def receive_data(self):
        while True:
            data, address = self.sock.recvfrom(1024)
            if address in self.clients:
                self.handle_client(address, data)
            else:
                name = data.decode()
                self.add_client(name, address)


def main():
    logging.basicConfig(level=LOGLEVEL)
    p2p_server = Server()
    receive_thread = threading.Thread(target=p2p_server.receive_data())
    receive_thread.start()





if __name__ == '__main__':
    main()