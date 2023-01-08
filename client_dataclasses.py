from dataclasses import dataclass, field
from utils import *
from typing import List, Dict


@dataclass(slots=True)
class FileStripe:
    hash: str
    is_parity: bool
    location: str = field(default_factory=str)  # name of peer who stores file


@dataclass(frozen=True, slots=True)
class File:
    name: str
    hash: str
    len: int
