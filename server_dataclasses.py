from dataclasses import dataclass, field
from utils import *
from typing import List, Dict
from enum import Enum, auto

STRIPE_ID = str


@dataclass(slots=True)
class FileStripe:
    hash: str
    is_parity: bool
    is_first: bool
    id: STRIPE_ID = str
    location: str = field(default_factory=str)  # name of user who stores file


@dataclass(frozen=True, slots=True)
class UserFile:
    owner: str
    name: str
    hash: str
    len: int
    nonce: str
    stripes: List[FileStripe] = field(default_factory=list)


@dataclass(slots=True)
class User:
    name: str
    current_addr: tuple
    storing_gb: float = 0
    owned_files: List[UserFile] = field(default_factory=list)
    stripes_saved: Dict[STRIPE_ID, FileStripe] = field(default_factory=dict)
