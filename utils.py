import os
from pathlib import Path

from Crypto.Cipher import ChaCha20

import settings
from settings import *
from typing import Tuple, List
import uuid
from hashlib import md5
from client_dataclasses import File, FileStripe
from server_dataclasses import UserFile
import base64


USERNAME = str
PASSWORD = str


def get_unique_id() -> str:
    """Returns (str) hex representation of a unique ID using UUID."""
    return str(uuid.uuid1().hex)


def get_hash(data: bytes) -> str:
    """Returns (str) hex representation of hash."""
    return md5(data).digest().hex()


def get_parity(data1: bytes, *other_data: bytes) -> bytes:
    """Returns the result of the repeated xor operation on all given (separate) data stripes."""
    length = len(data1)
    p = int.from_bytes(data1, BYTEORDER)
    for data in other_data:
        if len(data) > length:
            length = len(data)
        data = int.from_bytes(data, BYTEORDER)
        p = p ^ data
    return p.to_bytes(length, BYTEORDER)


def fragment_data(data: bytes) -> Tuple[bytes, bytes]:
    """Returns tuple of (even_bytes, uneven_bytes)."""
    return data[::2], data[1::2]


def defragment_data(data1: bytes, data2: bytes) -> bytes:
    """Defragments data stripes and returns the original data."""
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
    """
    Uses parity data and a data stripe to return the other missing data stripe.
    This is essentially virtual RAID 5.
    """
    return (int.from_bytes(parity, BYTEORDER) ^ int.from_bytes(stripe, BYTEORDER)).to_bytes(len(parity), BYTEORDER)


def save_temp_stripe(id: str, data: bytes, temppath="temp/stripes/"):
    # NEEDS REFACTORING (SAME FUNCTIONALITY AS save_file_in_restore
    with open(temppath + id, "wb") as f:
        f.write(data)


def save_file_in_restore(name: str, data, path=RESTORE_PATH):
    """Writes data to file and saves it in restore path, unless specified otherwise."""
    with open(path + name, "wb") as f:
        f.write(data)


def abstract_file(absolute_path: str, key: bytes) -> File:
    """
    Reads file and creates matching dataclass representation of it.
    Additionally, it encrypts and saves all stripes of file (including parity) in temp folder.
    """
    with open(absolute_path, "rb") as f:
        data = f.read()
    data, nonce = encrypt_file_data(data, key=key)
    name = os.path.basename(absolute_path)
    file_hash = get_hash(data)
    file = File(name=name, hash=file_hash, len=len(data), absolute_path=absolute_path, nonce=nonce)
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
    """Appends data (bytes) to file in backups folder."""
    with open(path + file_id, "ab") as f:
        f.write(data)


def encode_for_json(data: bytes) -> str:
    """ " Encodes data to base64 string."""
    return str(base64.b64encode(data), encoding="ASCII")


def decode_from_json(data: str) -> bytes:
    """Decodes base64 string to bytes."""
    return base64.b64decode(data)


def remove_temp_stripes(*ids: str, path="temp/stripes/"):
    """Removes any amount of temp stripes, as long as they're in the same directory, by id (name)."""
    for stripe_id in ids:
        try:
            os.remove(path + stripe_id)
        except FileNotFoundError:
            raise FileNotFoundError(f"No such temp stripe {stripe_id} in {path}")


def update_stripe_location(file: File, stripe_id: str, location: str):
    """Updates stripe location (peer name) by file and stripe id."""
    for stripe in file.stripes:
        if stripe.id == stripe_id:
            stripe.location = location
            return


def find_file_by_name(files: List[File] | List[UserFile], filename: str) -> File | UserFile | None:
    """Finds and returns file (dataclass representation) from list of files by filename. If not found returns None."""
    for file in files:
        if file.name == filename:
            return file
    return None


def get_data_from_parity_with_ids(stripe_id: str, parity_id: str, is_first: bool) -> bytes:
    """
    Returns original (defragmented) data. If the non-parity stripe is first (contains the even bytes),
    is_first must be True. If the stripe contains the uneven bytes, is_first should be False.
    """
    with open(RESTORE_TEMP_PATH + stripe_id, "rb") as f:
        stripe_data = f.read()
    with open(RESTORE_TEMP_PATH + parity_id, "rb") as f:
        parity_data = f.read()
    other_stripe = get_stripe_with_parity(stripe_data, parity_data)
    if is_first:
        return defragment_data(stripe_data, other_stripe)
    return defragment_data(other_stripe, stripe_data)


def get_data_from_stripe_ids(id_first: str, id_second: str, dir_path=RESTORE_STRIPE_FINISHED_PATH, ordered=True):
    """
    Returns original (defragmented) using two stripe ids. If ids are in the incorrect (positional) order,
    meaning the first stripe contains the uneven bytes, ordered should be set to False.
    """
    with open(dir_path + id_first, "rb") as f:
        first_data = f.read()
    with open(dir_path + id_second, "rb") as f:
        second_data = f.read()
    if ordered:
        return defragment_data(first_data, second_data)
    return defragment_data(second_data, first_data)


def move_stripe(stripe_id: str, origin_dir: str, destination_dir: str):
    """Moves stripe by id and from one directory to another."""
    with open(origin_dir + stripe_id, "rb") as f:
        data = f.read()
    with open(destination_dir + stripe_id, "wb") as f:
        f.write(data)
    remove_temp_stripes(stripe_id, path=origin_dir)


def get_chacha_key() -> bytes:
    """Returns suitable key for the ChaCha20 algorithm; 32 random bytes."""
    return os.urandom(32)


def encrypt_file_data(plaintext: bytes, key: bytes) -> Tuple[bytes, bytes]:
    """Encrypts plaintext using the ChaCha20 algorithm. Returns nonce which is required for decrypting the file."""
    cipher = ChaCha20.new(key=key)
    return cipher.encrypt(plaintext), cipher.nonce


def decrypt_file_data(ciphertext: bytes, key: bytes, nonce: bytes) -> bytes:
    """Decrypts ChaCha20 ciphertext. The nonce which was used for encryption is required."""
    cipher = ChaCha20.new(key=key, nonce=nonce)
    return cipher.decrypt(ciphertext)


def store_login_information(username: str, password: str, in_multi_user=False):
    """Stores login information in login info folder."""
    try:
        path = Path(settings.LOGIN_INFO_PATH)
        if in_multi_user:
            path = path / "multiuser" / username
            if not path.is_dir():
                os.makedirs(path)
            path /= "info.txt"
        else:
            path = path / "default.txt"
        with open(path, 'w') as f:
            data = f"{username}\n{password}"
            f.write(data)

    except Exception as e:
        print(f"Couldn't store login information\n{username=}\n{password=}\n{e=}")
        raise e


def get_login_information(username: str = None) -> Tuple[USERNAME, PASSWORD] | None:
    """Gets user information from login info folder. If not found, returns None."""
    if username is None:
        try:
            path = Path(LOGIN_INFO_PATH) / "default.txt"
            if not path.is_file():
                return None
            with open (path, "r") as f:
                username = f.readline()
                password = f.readline()
                return username, password
        except Exception as e:
            print(f"Couldn't get login information for default path\n{e=}")
        return None
    try:
        path = Path(LOGIN_INFO_PATH) / "multiuser" / username / "info.txt"
        if not path.is_file():
            return None
        with open(path, "r") as f:
            username = f.readline()
            password = f.readline()
            return username, password
    except Exception as e:
        print(f"Couldn't get login information for default path\n{e=}")
    return None


def gb_from_amount__bytes(amount_bytes: int) -> float:
    """Returns size in GB from an amount of bytes."""
    return amount_bytes / (1024 * 1024 * 1024)

