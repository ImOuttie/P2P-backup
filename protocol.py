import json
from dataclasses import dataclass
from typing import List, Dict, Any


class Message:
    """ baseclass for protocol message, every message class
     must contain to_dict method so it can be passed to json"""

    def to_dict(self) -> dict:
        raise NotImplementedError


class Connect(Message):
    def __init__(self, name: str, register: bool = False):
        self._cmd = "connect"
        self.name = name
        self.register = register

    def to_dict(self) -> dict:
        return {
            "cmd": self._cmd,
            "name": self.name,
            "register": self.register
        }


class ConnectToPeer(Message):
    def __init__(self, peer_name: str, peer_address: tuple):
        self._cmd = "connect_to_peer"
        self.peer_name = peer_name
        self.peer_address = peer_address

    def to_dict(self) -> dict:
        return {
            "cmd": self._cmd,
            "name": self.peer_name,
            "peer_address": self.peer_address
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
            "accept": self.accept
        }


class SendFileReq(Message):

    def __init__(self, file_name: str, hash: str, size: int, stripes: List[Dict]):
        self._cmd = "send_file_req"
        self.file_name = file_name
        self.hash = hash
        self.size = size
        self.stripes = stripes

    def to_dict(self) -> dict:
        return {
            "cmd": self._cmd,
            "name": self.file_name,
            "hash": self.hash,
            "size": self.size,
            "stripes": self.stripes
        }


class SendFileResp(Message):
    stripe = Dict[str, tuple | str]

    def __init__(self, file_name: str, stripes: List[stripe]):
        self._cmd = "send_file_resp"
        self.file_name = file_name
        self.stripes = stripes

    def to_dict(self) -> dict:
        return {
            "cmd": self._cmd,
            "name": self.file_name,
            "stripes": self.stripes
        }


class NewStripe(Message):
    def __init__(self, id: str, size: int, amount: int):
        self.cmd = "new_stripe"
        self.id = id
        self.size = size
        self.amount = amount

    def to_dict(self) -> dict:
        return {
            "cmd": self.cmd,
            "id": self.id,
            "size": self.size,
            "amount": self.amount
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
            "cmd": self._cmd
        }


class FileListResp(Message):
    FILENAME = str

    def __init__(self, files: List[FILENAME]):
        self._cmd = "file_list_resp"
        self.files = files

    def to_dict(self) -> dict:
        return {
            "cmd": self._cmd,
            "files": self.files
        }


class GetFileReq(Message):
    def __init__(self, file_name: str):
        self._cmd = "get_file_req"
        self.file_name = file_name

    def to_dict(self) -> dict:
        return {
            "cmd": self._cmd,
            "file": self.file_name
        }


class GetFileResp(Message):

    def __init__(self, file_name: str, stripes: List[dict]):
        self._cmd = "get_file_resp"
        self.file_name = file_name
        self.stripes = stripes

    def to_dict(self) -> dict:
        return {
            "cmd": self._cmd,
            "file": self.file_name,
            "stripes": self.stripes
        }


class GetStripe(Message):

    def __init__(self, stripe_id: str):
        self._cmd = "get_stripe"
        self.stripe_id = stripe_id

    def to_dict(self) -> dict:
        return {
            "cmd": self._cmd,
            "id": self.stripe_id
        }


class GetStripeResp(Message):

    def __init__(self, stripe_id: str, amount: int):
        self._cmd = "get_stripe_resp"
        self.stripe_id = stripe_id
        self.amount = amount

    def to_dict(self) -> dict:
        return {
            "cmd": self._cmd,
            "id": self.stripe_id,
            "amount": self.amount
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
            "seq": self.seq,
            "raw": self.raw
        }


def message_reader(msg: dict) -> Message:
    """" READS PROTOCOL MESSAGE AND RETURNS MATCHING MESSAGE CLASS INSTANCE"""
    try:
        match msg["cmd"]:
            case "connect":
                return Connect(name=msg["name"], register=msg["register"] if "register" in msg.keys() else False)
            case "connect_to_peer":
                return ConnectToPeer(peer_name=msg["name"], peer_address=msg["peer_address"])
            case "received_connection":
                return ReceivedConnection(msg["name"], accept=msg["accept"])
            case "send_file_req":
                return SendFileReq(file_name=msg["name"], hash=msg["hash"], size=msg["len"], stripes=msg["stripes"])
            case "send_file_resp":
                return SendFileResp(file_name=msg["name"], stripes=msg["stripes"])
            case "new_stripe":
                return NewStripe(id=msg["id"], size=msg["size"])
            case "append_stripe":
                return AppendStripe(id=msg["id"], raw=msg["raw"])
            case "get_file_list":
                return GetFileList()
            case "file_list_resp":
                return FileListResp(files=msg["files"])
            case "get_file_req":
                return GetFileReq(file_name=msg["file"])
            case "get_file_resp":
                return GetFileResp(file_name=msg["file"], stripes=msg["stripes"])
        raise Exception(f"message contains command that doesn't exist: {msg}")
    except KeyError:
        raise KeyError(f"message contains invalid key: {msg}")



