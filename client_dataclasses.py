from dataclasses import dataclass, field
from typing import List, Dict


@dataclass(slots=True)
class FileStripe:
    hash: str
    id: str
    is_parity: bool
    is_first: bool
    location: str = field(default_factory=str)  # name of peer who stores file


@dataclass(frozen=True, slots=True)
class File:
    name: str
    hash: str
    len: int
    absolute_path: str
    stripes: List[FileStripe] = field(default_factory=list)
