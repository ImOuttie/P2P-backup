from dataclasses import dataclass, field
from typing import List, Dict

STRIPE_ID = str


@dataclass(slots=True)
class UserFileStripe:
    hash: str
    is_parity: bool
    is_first: bool
    id: STRIPE_ID
    stripe_db_id: int = -1
    file_db_id: int = -1
    location: str = field(default_factory=str)  # name of user who stores file


@dataclass(frozen=True, slots=True)
class UserFile:
    owner: str
    name: str
    hash: str
    len: int
    nonce: str
    file_db_id: int = -1
    stripes: List[UserFileStripe] = field(default_factory=list)


@dataclass(slots=True)
class User:
    name: str
    current_addr: tuple
    storing_gb: float = 0
    user_db_id: int = -1
    owned_files: List[UserFile] = field(default_factory=list)
    stripes_saved: Dict[STRIPE_ID, UserFileStripe] = field(default_factory=dict)
