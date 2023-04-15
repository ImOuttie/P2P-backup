import base64
import json
import logging
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
import hashlib

import protocol
import settings
import utils
from protocol import ConnectToPeer, Connect, Register
from socket import socket

CURVE = ec.SECP256R1()
ADDRESS = Tuple[str, int]


def hash_password(password: str) -> str:
    m = hashlib.sha256()
    m.update(password.encode())
    return base64.b64encode(m.digest()).decode()


def generate_b64_fernet_key() -> str:
    return base64.b64encode(Fernet.generate_key()).decode()


def get_fernet_from_b64(encoded_key: str) -> Fernet:
    return Fernet(base64.b64decode(encoded_key.encode()))


def decrypt_fernet_to_json(f: Fernet, data: bytes) -> dict:
    return json.loads(f.decrypt(data).decode())


def deserialize_public_key(key: bytes) -> EllipticCurvePublicKey:
    return serialization.load_pem_public_key(key)


def deserialize_private_key(key: bytes) -> EllipticCurvePrivateKey:
    return serialization.load_pem_private_key(key, password=None)


def serialize_public_key(key: EllipticCurvePublicKey) -> bytes:
    return key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)


def serialize_private_key(key: EllipticCurvePrivateKey) -> bytes:
    return key.private_bytes(
        encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8, encryption_algorithm=serialization.NoEncryption()
    )


def generate_ecdh_keys(path_private: str, path_public: str) -> Tuple[EllipticCurvePrivateKey, EllipticCurvePublicKey]:
    with open(path_private, "wb") as f:
        private_key = ec.generate_private_key(CURVE)
        serialized_private = serialize_private_key(private_key)
        f.write(serialized_private)
    with open(path_public, "wb") as f:
        public_key = private_key.public_key()
        serialized_public = serialize_public_key(public_key)
        f.write(serialized_public)
    return private_key, public_key


def load_public_ecdh_key(path: str) -> EllipticCurvePublicKey:
    with open(path, "rb") as f:
        loaded_public_key = serialization.load_pem_public_key(
            f.read(),
        )
        return loaded_public_key


def load_private_ecdh_key(path: str) -> EllipticCurvePrivateKey:
    with open(path, "rb") as f:
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
        info=b"handshake data",
    ).derive(shared_key)
    derived_key = base64.urlsafe_b64encode(derived_key)
    return Fernet(derived_key)


def encrypt_with_fernet(f: Fernet, data: bytes) -> bytes:
    return f.encrypt(data)


def decrypt_with_fernet(f: Fernet, ciphertext: bytes) -> bytes:
    return f.decrypt(ciphertext)


def public_key_to_str(key: EllipticCurvePublicKey) -> str:
    return utils.encode_for_json(serialize_public_key(key))


def str_to_public_key(key: str) -> EllipticCurvePublicKey:
    return deserialize_public_key(utils.decode_from_json(key))


class HandshakeWithClientTask:
    def __init__(
        self,
        private_key: EllipticCurvePrivateKey,
        public_key: EllipticCurvePublicKey,
        client_addr: ADDRESS,
        sock: socket,
        client_msg: protocol.SendPublicKey,
    ):
        self.private_key = private_key
        self.public_key = public_key
        self.client_addr = client_addr
        self.sock = sock
        client_public_key = str_to_public_key(client_msg.public_key)
        self.fernet = get_fernet(client_public_key, self.private_key)

    def exchange_keys(self):
        msg = protocol.SendPublicKey(public_key=public_key_to_str(self.public_key))
        data = json.dumps(msg.to_dict()).encode()
        self.sock.sendto(data, self.client_addr)
        return self.fernet


class HandshakeWithServerTask:
    def __init__(self, private_key: EllipticCurvePrivateKey, public_key: EllipticCurvePublicKey, server_addr: ADDRESS, sock: socket):
        self.private_key = private_key
        self.public_key = public_key
        self.sock = sock
        self._server_addr = server_addr

    def begin(self) -> Fernet:
        self.send_public_key()
        while True:
            data, addr = self.sock.recvfrom(1024)
            try:
                if addr != self._server_addr:
                    raise Exception(f"Server spoofed \n{data=}\n{addr=}")
                msg = json.loads(data.decode())
                if msg["cmd"] == "send_public_key":
                    msg = protocol.SendPublicKey(msg["key"])
                    f = self.get_shared_key(msg)
                    return f
            except (json.JSONDecodeError, ValueError):
                raise Exception(f"bad data: {data}")

    def send_public_key(self):
        msg = protocol.SendPublicKey(public_key=public_key_to_str(self.public_key))
        data = json.dumps(msg.to_dict()).encode()
        self.sock.sendto(data, self._server_addr)

    def get_shared_key(self, msg: protocol.SendPublicKey) -> Fernet:
        server_public_key = str_to_public_key(msg.public_key)
        f = get_fernet(server_public_key, self.private_key)
        return f


class LoginToServerTask:
    def __init__(self, name: str, password_hash: str, sock: socket, fernet: Fernet):
        self.name = name
        self.password_hash = password_hash
        self._server_addr = settings.SERVER_ADDR
        self.sock = sock
        self.fernet = fernet

    def begin(self):
        self.send_login_msg()
        while True:
            data, addr = self.sock.recvfrom(1024)
            try:
                if addr != self._server_addr:
                    raise Exception(f"Server spoofed \n{data=}\n{addr=}")
                msg = decrypt_fernet_to_json(self.fernet, data)
                if msg["cmd"] == "login_resp":
                    msg = protocol.LoginResp.from_dict(msg)
                    if msg.resp == protocol.ServerLoginResponse.SUCCESS:
                        return
                    # TODO: handle these
                    elif msg.resp == protocol.ServerLoginResponse.INCORRECT_PASSWORD:
                        logging.exception("incorrect password")
                    elif msg.resp == protocol.ServerLoginResponse.NAME_INVALID:
                        logging.exception("invalid name")
            except (json.JSONDecodeError, ValueError):
                raise Exception(f"bad data: {data}")

    def send_login_msg(self):
        login_msg = protocol.Login(name=self.name, password_hash=self.password_hash)
        data = encrypt_with_fernet(self.fernet, json.dumps(login_msg.to_dict()).encode())
        self.sock.sendto(data, self._server_addr)


class RegisterToServerTask:
    def __init__(self, name: str, password_hash: str, sock: socket, file_encryption_key: bytes, fernet: Fernet):
        self.name = name
        self.password_hash = password_hash
        self.sock = sock
        self.key = file_encryption_key
        self.fernet = fernet
        self._server_addr = settings.SERVER_ADDR

    def begin(self):
        self.send_register_msg()
        while True:
            data, addr = self.sock.recvfrom(1024)
            try:
                if addr != self._server_addr:
                    raise Exception(f"Server spoofed \n{data=}\n{addr=}")
                msg = decrypt_fernet_to_json(self.fernet, data)
                if msg["cmd"] == "register_resp":
                    msg = protocol.RegisterResp.from_dict(msg)
                    if msg.resp == protocol.ServerRegisterResponse.SUCCESS:
                        return
                    # TODO: handle this
                    elif msg.resp == protocol.ServerRegisterResponse.NAME_TAKEN:
                        logging.exception("name taken")
            except (json.JSONDecodeError, ValueError):
                raise Exception(f"bad data: {data}")

    def send_register_msg(self):
        register_msg = Register(name=self.name, key=utils.encode_for_json(self.key), password_hash=self.password_hash)
        data = encrypt_with_fernet(self.fernet, json.dumps(register_msg.to_dict()).encode())
        self.sock.sendto(data, self._server_addr)


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
    generate_ecdh_keys(rf"{settings.CLIENT_KEYS_PATH}alice\private.pem", rf"{settings.CLIENT_KEYS_PATH}alice\public.pem")
    generate_ecdh_keys(rf"{settings.CLIENT_KEYS_PATH}bob\private.pem", rf"{settings.CLIENT_KEYS_PATH}bob\public.pem")
    generate_ecdh_keys(rf"{settings.CLIENT_KEYS_PATH}charlie\private.pem", rf"{settings.CLIENT_KEYS_PATH}charlie\public.pem")
    generate_ecdh_keys(rf"{settings.CLIENT_KEYS_PATH}dan\private.pem", rf"{settings.CLIENT_KEYS_PATH}dan\public.pem")


if __name__ == "__main__":
    main()
