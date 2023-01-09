from dataclasses import dataclass, field
from utils import *
from typing import List, Dict

STRIPE_ID = str


@dataclass(slots=True)
class FileStripe:
    hash: str
    is_parity: bool
    id: STRIPE_ID = field(default_factory=get_unique_id)
    location: str = field(default_factory=str)  # name of user who stores file


@dataclass(frozen=True, slots=True)
class File:
    owner: str
    name: str
    hash: str
    len: int
    stripes: List[FileStripe] = field(default_factory=list)


@dataclass(slots=True)
class User:
    name: str
    current_addr: tuple
    storing_gb: float = 0
    owned_files: List[File] = field(default_factory=list)
    stripes_saved: Dict[STRIPE_ID, FileStripe] = field(default_factory=dict)
