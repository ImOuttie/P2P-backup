import binascii
import os
from itertools import cycle, islice

from settings import *
from typing import Tuple, List
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
    for byte1, byte2 in zip(data1, data2):
        defrag.append(byte1)
        defrag.append(byte2)
    if len(data1) > len(data2):
        defrag.append(data1[-1])
    elif len(data2) > len(data1):
        defrag.append(data2[-1])
    return bytes(defrag)


def get_stripe_with_parity(stripe: bytes, parity: bytes) -> bytes:
    """uses parity data and a data stripe to return the other missing data stripe.
    this is essentially virtual RAID 5"""
    return (int.from_bytes(parity, BYTEORDER) ^ int.from_bytes(stripe, BYTEORDER)).to_bytes(len(parity), BYTEORDER)


def save_temp_stripe(id: str, data: bytes, temppath="temp/stripes/"):
    # NEEDS REFACTORING (SAME FUNCTIONALITY AS save_file_in_restore
    with open(temppath + id, "wb") as f:
        f.write(data)


def save_file_in_restore(name: str, data, path=RESTORE_PATH):
    """ " WRITES DATA TO FILE AND SAVES IT IN RESTORE PATH UNLESS SPECIFIED OTHERWISE"""
    with open(path + name, "wb") as f:
        f.write(data)


def abstract_file(absolute_path: str) -> File:
    """reads file and creates matching dataclass representation of it.
    also saves all stripes of file (including parity) in temp folder"""
    with open(absolute_path, "rb") as f:
        data = f.read()
    name = os.path.basename(absolute_path)
    file_hash = get_hash(data)
    file = File(name=name, hash=file_hash, len=len(data), absolute_path=absolute_path)
    data_stripes = fragment_data(data)
    first = True
    for data_stripe in data_stripes:
        file_stripe = FileStripe(hash=get_hash(data_stripe), id=get_unique_id(), is_parity=False, is_first=first)
        file.stripes.append(file_stripe)
        save_temp_stripe(file_stripe.id, data_stripe)
        if first:
            first = False
    parity_data = get_parity(*data_stripes)
    parity = FileStripe(hash=get_hash(parity_data), id=get_unique_id(), is_parity=True, is_first=False)
    file.stripes.append(parity)
    save_temp_stripe(parity.id, parity_data)
    return file


def append_to_file(file_id: str, data: bin, path=BACKUP_PATH):
    """APPENDS DATA (BYTES) TO FILE IN BACKUPS FOLDER"""
    with open(path + file_id, "ab") as f:
        f.write(data)


def encode_for_json(data: bytes) -> str:
    """ENCODES DATA TO BASE64 STRING"""
    return str(base64.b64encode(data), encoding="ASCII")


def decode_from_json(data: str) -> bytes:
    """DECODES BASE64 STRING TO BYTES"""
    return base64.b64decode(data)


def remove_temp_stripes(*ids: str, path="temp/stripes/"):
    """REMOVES ANY AMOUNT OF TEMP STRIPES (FROM THE SAME DIRECTORY) BY ID"""
    for stripe_id in ids:
        try:
            os.remove(path + stripe_id)
        except FileNotFoundError:
            raise FileNotFoundError(f"No such temp stripe {stripe_id} in {path}")


def update_stripe_location(file: File, stripe_id: str, location: str):
    """UPDATES STRIPE LOCATION (PEER NAME) BY FILE AND STRIPE ID"""
    for stripe in file.stripes:
        if stripe.id == stripe_id:
            stripe.location = location
            return


def find_file_by_name(files: List[File], filename: str) -> File | None:
    """FINDS AND RETURNS FILE (DATACLASS REPRESENTATION) FROM LIST OF FILES BY FILENAME, IF NOT FOUND RETURNS NONE"""
    for file in files:
        if file.name == filename:
            return file
    return None


def get_data_from_parity_with_ids(stripe_id: str, parity_id: str, is_first: bool) -> bytes:
    """ " GETS DATA STRIPE ID AND PARITY ID, RETURNS ORIGINAL (DEFRAGMENTED) DATA
    IS_FIRST MUST BE TRUE IF STRIPE IS FIRST IN ORDER (EVEN BYTES). OTHER WISE FALSE."""
    with open(RESTORE_TEMP_PATH + stripe_id, "rb") as f:
        stripe_data = f.read()
    with open(RESTORE_TEMP_PATH + parity_id, "rb") as f:
        parity_data = f.read()
    other_stripe = get_stripe_with_parity(stripe_data, parity_data)
    if is_first:
        return defragment_data(stripe_data, other_stripe)
    return defragment_data(other_stripe, stripe_data)


def get_data_from_stripe_ids(id_first: str, id_second: str, dir_path=RESTORE_STRIPE_FINISHED_PATH, ordered=True):
    """ " GETS TWO DATA STRIPE IDS, RETURNS ORIGINAL (DEFRAGMENTED DATA). IF IDS ARE IN
    INCORRECT ORDER (SECOND ID IS FIRST STRIPE/ EVEN BYTES), ORDERED SHOULD BE FALSE"""
    with open(dir_path + id_first, "rb") as f:
        first_data = f.read()
    with open(dir_path + id_second, "rb") as f:
        second_data = f.read()
    if ordered:
        return defragment_data(first_data, second_data)
    return defragment_data(second_data, first_data)


def move_stripe(stripe_id: str, origin_path: str, destination_path: str):
    """ " MOVES STRIPE BY FILENAME (ID) FROM ONE PATH TO ANOTHER"""
    print(f"{origin_path=}")
    with open(origin_path + stripe_id, "rb") as f:
        data = f.read()
    with open(destination_path + stripe_id, "wb") as f:
        f.write(data)
    remove_temp_stripes(stripe_id, path=origin_path)
