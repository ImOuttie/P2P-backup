import os
from itertools import cycle, islice

from settings import *
from typing import Tuple
import uuid
from hashlib import md5
from client_dataclasses import File, FileStripe
import base64


def get_unique_id() -> str:
    """returns (str) hex representation of a unique ID using UUID"""
    return str(uuid.uuid1().hex)


def get_hash(data: bytes) -> str:
    """returns (str) hex representation of hash"""
    return md5(data).digest().hex()


def get_parity(data1: bytes, *other_data: bytes) -> bytes:
    """returns the result of the repeated xor operation on all given (separate) data stripes"""
    length = len(data1)
    p = int.from_bytes(data1, BYTEORDER)
    for data in other_data:
        if len(data) > length:
            length = len(data)
        data = int.from_bytes(data, BYTEORDER)
        p = p ^ data
    return p.to_bytes(length, BYTEORDER)


def fragment_data(data: bytes) -> Tuple[bytes, bytes]:
    """ " returns tuple of all the even bytes and all the uneven bytes"""
    return data[::2], data[1::2]


def defragment_data(data1: bytes, data2: bytes) -> bytes:
    """defragments data stripes and returns the original data"""
    defrag = []
    for bit1, bit2 in zip(data1, data2):
        defrag.append(bit1)
        defrag.append(bit2)
    if len(data1) > len(data2):
        defrag.append(data1[-1])
    elif len(data2) > len(data1):
        defrag.append(data2[-1])
    return bytes(defrag)


def get_stripe_with_parity(stripe: bytes, parity: bytes) -> bytes:
    """uses parity data and a data stripe to return the other missing data stripe.
    this is essentially virtual RAID 5"""
    return (
        int.from_bytes(parity, BYTEORDER) ^ int.from_bytes(stripe, BYTEORDER)
    ).to_bytes(len(parity), BYTEORDER)


def save_temp_stripe(id: str, data: bytes, temppath="temp/stripes/"):
    with open(temppath + id, "wb") as f:
        f.write(data)


def abstract_file(absolute_path: str) -> File:
    """reads file and creates matching dataclass representation of it
    also saves all stripes of file (including parity) in temp folder"""
    with open(absolute_path, "rb") as f:
        data = f.read()
    name = os.path.basename(absolute_path)
    file_hash = get_hash(data)
    file = File(name=name, hash=file_hash, len=len(data), absolute_path=absolute_path)
    data_stripes = fragment_data(data)
    for data_stripe in data_stripes:
        file_stripe = FileStripe(
            hash=get_hash(data_stripe), id=get_unique_id(), is_parity=False
        )
        file.stripes.append(file_stripe)
        save_temp_stripe(file_stripe.id, data_stripe)
    parity_data = get_parity(*data_stripes)
    parity = FileStripe(hash=get_hash(parity_data), id=get_unique_id(), is_parity=True)
    file.stripes.append(parity)
    save_temp_stripe(parity.id, parity_data)
    return file


def append_to_file(file_id: str, data: bin):
    """APPENDS DATA (BYTES) TO FILE IN BACKUPS FOLDER"""
    with open(FPATH + file_id, "ab") as f:
        f.write(data)


def encode_for_json(data: bytes) -> str:
    """ENCODES DATA TO BASE64 STRING"""
    return str(base64.b64encode(data), encoding="ASCII")


def decode_from_json(data: str) -> bytes:
    """DECODES BASE64 STRING TO BYTES"""
    return base64.b64decode(data)


def remove_temp_stripe(id: str):
    """REMOVES TEMP STRIPE BY ID"""
    os.remove("temp/stripes/" + id)


def update_stripe_location(file: File, stripe_id: str, location: str):
    """UPDATES STRIPE LOCATION (PEER NAME) BY FILE AND STRIPE ID"""
    for stripe in file.stripes:
        if stripe.id == stripe_id:
            stripe.location = location
            return
