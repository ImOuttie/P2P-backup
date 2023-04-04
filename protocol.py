from abc import abstractmethod
from typing import List, Dict, Any, TypedDict


class GetFileRespStripe(TypedDict):
    id: str
    peer: str
    addr: tuple
    is_first: bool
    is_parity: bool


class SendFileRespStripe(TypedDict):
    id: str
    peer: str
    addr: tuple


class SendFileReqStripe(TypedDict):
    id: str
    hash: str
    is_parity: bool
    is_first: bool


FILENAME = str


class Message:
    """
    Baseclass for protocol message, every message class
    Must contain to_dict method so it can be passed to json.
    """

    def to_dict(self) -> dict:
        raise NotImplementedError


class Authenticate(Message):
    def __init__(self, public_key: str):
        self._cmd = "authenticate"
        self.public_key = public_key

    def to_dict(self) -> dict:
        return {
            "cmd": self._cmd,
            "key": self.public_key,
        }


class AuthenticateResp(Message):
    def __init__(self, public_key: str):
        self._cmd = "authenticate_resp"
        self.public_key = public_key

    def to_dict(self) -> dict:
        return {
            "cmd": self._cmd,
            "key": self.public_key,
        }


class Register(Message):
    def __init__(self, name: str, key: str):
        self._cmd = "register"
        self.name = name
        self.key = key

    def to_dict(self) -> dict:
        return {
            "cmd": self._cmd,
            "name": self.name,
            "key": self.key,
        }


class Login(Message):
    def __init__(self, name: str):
        self._cmd = "Login"
        self.name = name

    def to_dict(self) -> dict:
        return {
            "cmd": self._cmd,
            "name": self.name
        }


class Connect(Message):
    def __init__(self, name: str):
        self._cmd = "connect"
        self.name = name

    def to_dict(self) -> dict:
        return {
            "cmd": self._cmd,
            "name": self.name,
        }


class ConnectToPeer(Message):
    def __init__(self, peer_name: str, peer_address: tuple, key: str = 'removelater'):
        self._cmd = "connect_to_peer"
        self.peer_name = peer_name
        self.peer_address = peer_address
        self.key = key

    def to_dict(self) -> dict:
        return {
            "cmd": self._cmd,
            "name": self.peer_name,
            "peer_address": self.peer_address,
            "key": self.key,
        }


class ReceivedConnection(Message):
    def __init__(self, name: str, accept: bool):
        self._cmd = "received_connection"
        self.name = name
        self.accept = accept

    def to_dict(self) -> dict:
        return {
            "cmd": self._cmd,
            "name": self.name,
            "accept": self.accept,
        }


class SendFileReq(Message):
    def __init__(self, file_name: str, file_hash: str, size: int, nonce: str, stripes: List[SendFileReqStripe]):
        self._cmd = "send_file_req"
        self.file_name = file_name
        self.hash = file_hash
        self.size = size
        self.stripes = stripes
        self.nonce = nonce

    def to_dict(self) -> dict:
        return {
            "cmd": self._cmd,
            "name": self.file_name,
            "hash": self.hash,
            "size": self.size,
            "nonce": self.nonce,
            "stripes": self.stripes,
        }


class SendFileResp(Message):
    def __init__(self, file_name: str, stripes: List[SendFileRespStripe]):
        self._cmd = "send_file_resp"
        self.file_name = file_name
        self.stripes = stripes

    def to_dict(self) -> dict:
        return {
            "cmd": self._cmd,
            "name": self.file_name,
            "stripes": self.stripes,
        }


class NewStripe(Message):
    def __init__(self, id: str, size: int, amount: int):
        self.cmd = "new_stripe"
        self.stripe_id = id
        self.size = size
        self.amount = amount

    def to_dict(self) -> dict:
        return {
            "cmd": self.cmd,
            "id": self.stripe_id,
            "size": self.size,
            "amount": self.amount,
        }


class AppendStripe(Message):
    def __init__(self, id: str, raw: str, seq: int):
        self.cmd = "append_stripe"
        self.id = id
        self.raw = raw
        self.seq = seq

    def to_dict(self) -> dict:
        return {
            "cmd": self.cmd,
            "id": self.id,
            "raw": self.raw,
            "seq": self.seq,
        }


class GetFileList(Message):
    def __init__(self):
        self._cmd = "get_file_list"

    def to_dict(self) -> dict:
        return {
            "cmd": self._cmd,
        }


class FileListResp(Message):
    def __init__(self, files: List[FILENAME]):
        self._cmd = "file_list_resp"
        self.files = files

    def to_dict(self) -> dict:
        return {
            "cmd": self._cmd,
            "files": self.files,
        }


class GetFileReq(Message):
    def __init__(self, file_name: str):
        self._cmd = "get_file_req"
        self.file_name = file_name

    def to_dict(self) -> dict:
        return {
            "cmd": self._cmd,
            "file": self.file_name,
        }


class GetFileResp(Message):
    def __init__(self, file_name: str, nonce: str, stripes: List[GetFileRespStripe]):
        self._cmd = "get_file_resp"
        self.file_name = file_name
        self.nonce = nonce
        self.stripes = stripes

    def to_dict(self) -> dict:
        return {
            "cmd": self._cmd,
            "file": self.file_name,
            "nonce": self.nonce,
            "stripes": self.stripes,
        }


class GetStripe(Message):
    def __init__(self, stripe_id: str):
        self._cmd = "get_stripe"
        self.stripe_id = stripe_id

    def to_dict(self) -> dict:
        return {
            "cmd": self._cmd,
            "id": self.stripe_id,
        }


class GetStripeResp(Message):
    def __init__(self, stripe_id: str, amount: int, size: int):
        self._cmd = "get_stripe_resp"
        self.stripe_id = stripe_id
        self.amount = amount
        self.size = size

    def to_dict(self) -> dict:
        return {
            "cmd": self._cmd,
            "id": self.stripe_id,
            "amount": self.amount,
            "size": self.size,
        }


class AppendGetStripe(Message):
    def __init__(self, stripe_id: str, seq: int, raw: str):
        self._cmd = "append_get_stripe"
        self.stripe_id = stripe_id
        self.seq = seq
        self.raw = raw

    def to_dict(self) -> dict:
        return {
            "cmd": self._cmd,
            "id": self.stripe_id,
            "raw": self.raw,
            "seq": self.seq,
        }

