from dataclasses import dataclass, field
from utils import *
from typing import List


@dataclass(frozen=True, slots=True)
class FileStripe:
    hash: str
    is_parity: bool
    id: str = field(default_factory=get_unique_id)
    location: str = field(default_factory=str)  # name of user who stores file


@dataclass(frozen=True, slots=True)
class File:
    owner: str
    name: str
    hash: str
    stripes: List[FileStripe] = field(default_factory=list)
