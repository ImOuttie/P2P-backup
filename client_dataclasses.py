import os
from dataclasses import dataclass, field
from typing import List, Dict


@dataclass(slots=True)
class FileStripe:
    id: str
    is_parity: bool
    is_first: bool
    hash: str = field(default_factory=str)
    location: str = field(default_factory=str)  # name of peer who stores file


@dataclass(frozen=True, slots=True)
class File:
    name: str
    hash: str
    len: int
    absolute_path: str
    nonce: bytes
    stripes: List[FileStripe] = field(default_factory=list)


@dataclass(slots=True)
class TempStripe:
    id: str
    peer_name: str
    peer_addr: tuple
    is_parity: bool
    parent_file: str
    is_first: bool
    cur_seq: int = -1  # init sequence
    complete: bool = False
    max_seq: int = field(default_factory=int)


@dataclass(slots=True)
class TempFile:
    name: str
    stripes: List[TempStripe] = field(default_factory=list)
