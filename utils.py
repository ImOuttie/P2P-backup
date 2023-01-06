from itertools import cycle, islice

from settings import *
from typing import Tuple
import uuid
from hashlib import md5


def get_unique_id() -> str:
    return str(uuid.uuid1().hex)


def get_hash(data: bytes) -> str:
    """ returns (str) hex representation of hash"""
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
    """uses parity data and one data stripe to return the other missing data stripe this is essentially virtual RAID
    5"""
    return (
        int.from_bytes(parity, BYTEORDER) ^ int.from_bytes(stripe, BYTEORDER)
    ).to_bytes(len(parity), BYTEORDER)


def fragment_data(data: bytes) -> Tuple[bytes, bytes]:
    return data[::2], data[1::2]
