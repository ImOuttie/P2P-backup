import logging
import socket
import time

from settings import *


class Client:
    def __init__(self, name: str):
        self.name = name
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((CLIENT_IP, CLIENT_PORT))
        self._server_addr = (SERVER_IP, SERVER_PORT)

    def handle_server(self, data):
        pass

    def handle_peer(self, peer_addr, data):
        pass

    def send_to_server(self, msg):
        data = msg.encode()
        self.sock.sendto(data, self._server_addr)

    def receive_data(self):
        while True:
            data, addr = self.sock.recvfrom(1024)
            if addr == self._server_addr:
                self.handle_server(data)
            else:
                self.handle_peer(addr, data)


def main():
    client = Client(input('Input Name\r\n'))
    client.send_to_server(client.name)
    time.sleep(1)
    client.send_to_server("connect")


if __name__ == '__main__':
    main()