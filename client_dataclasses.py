from dataclasses import dataclass, field
from typing import List, Dict


def return_false():
    return False


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
    stripes: List[FileStripe] = field(default_factory=list)


@dataclass(slots=True)
class TempStripe:
    id: str
    peer_name: str
    peer_addr: tuple
    is_parity: bool
    parent_file: str
    is_first: bool
    max_seq: int = field(default_factory=list)
    complete: bool = field(default_factory=return_false)


@dataclass(slots=True)
class TempFile:
    name: str
    stripes: List[TempStripe] = field(default_factory=list)
