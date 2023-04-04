import base64
import json
import socket
import threading
import time
from typing import Tuple

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

import settings
import utils
from protocol import ConnectToPeer, Connect, Register
from socket import socket

CURVE = ec.SECP256R1()


def deserialize_public_key(key: bytes) -> EllipticCurvePublicKey:
    return serialization.load_pem_public_key(key)


def deserialize_private_key(key: bytes) -> EllipticCurvePrivateKey:
    return serialization.load_pem_private_key(key, password=None)


def serialize_public_key(key: EllipticCurvePublicKey) -> bytes:
    return key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )


def serialize_private_key(key: EllipticCurvePrivateKey) -> bytes:
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )


def generate_ecdh_keys(path_private: str, path_public: str) -> Tuple[EllipticCurvePrivateKey, EllipticCurvePublicKey]:
    with open(path_private, 'wb') as f:
        private_key = ec.generate_private_key(
            CURVE
        )
        serialized_private = serialize_private_key(private_key)
        f.write(serialized_private)
    with open(path_public, 'wb') as f:
        public_key = private_key.public_key()
        serialized_public = serialize_public_key(public_key)
        f.write(serialized_public)
    return private_key, public_key


def load_public_ecdh_key(path: str) -> EllipticCurvePublicKey:
    with open(path, 'rb') as f:
        loaded_public_key = serialization.load_pem_public_key(
            f.read(),
        )
        return loaded_public_key


def load_private_ecdh_key(path: str) -> EllipticCurvePrivateKey:
    with open(path, 'rb') as f:
        loaded_private_key = serialization.load_pem_private_key(
            f.read(),
            # or password=None, if in plain text
            password=None,
        )
        return loaded_private_key


def get_fernet(public_key: EllipticCurvePublicKey, private_key: EllipticCurvePrivateKey):
    shared_key = private_key.exchange(ec.ECDH(), public_key)
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'handshake data',
    ).derive(shared_key)
    derived_key = base64.urlsafe_b64encode(derived_key)
    return Fernet(derived_key)


def encrypt_with_fernet(f: Fernet, data: bytes) -> bytes:
    return f.encrypt(data)


def decrypt_with_fernet(f: Fernet, ciphertext: bytes) -> bytes:
    return f.decrypt(ciphertext)


class ConnectToServerTask:
    def __init__(self, name: str, path: str):
        self.private_key = load_private_ecdh_key(path)
        pass


class RegisterToServerTask:
    def __init__(self, path_private: str, path_public: str, name: str, sock: socket):
        self.private_key, self.public_key = generate_ecdh_keys(path_private, path_public)
        self.name = name
        self.sock = sock
        self._server_addr = settings.SERVER_ADDR

    def authenticate(self):
        # send public key:
        self.sock.sendto(serialize_public_key(self.public_key), self._server_addr)


class AuthenticateServerTask:
    def __init__(self, path_private: str, path_public: str, name: str):
        self.private_key, self.public_key = generate_ecdh_keys(path_private, path_public)
        self.name = name


class ConnectToPeerTask:
    def __init__(self, msg: ConnectToPeer, name: str, sock: socket):
        self.self_name = name
        self.peer_addr = msg.peer_address
        self.peer_name = msg.peer_name
        self.fernet = Fernet(msg.key)
        self.sock = sock
        self.finished = False
        self.daemon_thread = threading.Thread(target=self.run_daemon)
        self.daemon_thread.start()

    def try_connect(self):
        msg = Connect(name=self.self_name).to_dict()
        ct = encrypt_with_fernet(self.fernet, json.dumps(msg).encode())
        self.sock.sendto(ct, self.peer_addr)

    def run_daemon(self):
        while True:
            if self.finished:
                return
            time.sleep(0.5)


def main():
    generate_ecdh_keys("private.pem", "public.pem")






if __name__ == '__main__':
    main()