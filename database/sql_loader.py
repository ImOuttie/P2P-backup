import os
import sqlite3
from pathlib import Path
import protocol
import utils
from database.database_creator import DatabaseCreator
from server_dataclasses import User, UserFile, FileStripe
from typing import List, Iterable
from threading import Lock

FILENAME = str


class SQLLoader:
    def __init__(self, db_file_path: str):
        if not Path(db_file_path).exists():
            DatabaseCreator.create_database(db_file_path)

        self.conn = self._create_connection(db_file_path)
        self.mutex = Lock()

    def load_user_data(self, name: str, addr: tuple) -> User | None:
        """Loads and returns user data if user found. If user doesn't exist, returns None."""
        user = self._get_user_by_name(name)
        if user is None:
            return None
        user.current_addr = addr
        user.owned_files = self._get_user_files_by_user_id(user)
        return user

    def check_user_password(self, user: User, password: str):
        query = "SELECT password_hash FROM user_password WHERE user_id == ?"
        resp = self._execute_and_fetch(query, [user.user_db_id])
        if not resp:
            print(resp)
            raise Exception(f"No password in database of user: {user.name}\npassword given: {password}")
        user_password = resp[0][0]
        if password == user_password:
            return True
        return False

    def get_user_file_key(self, user: User) -> str:
        query = "SELECT key FROM user_file_key WHERE user_id == ?"
        resp = self._execute_and_fetch(query, [user.user_db_id])
        if not resp:
            raise Exception(f"User file key doesn't exist: {user.name}")
        return resp[0][0]

    def add_user(self, name: str, addr: tuple, password: str, file_key: str) -> User:
        if self.check_if_user_exist_by_name(name):
            raise Exception(f"Username {name} already exists")
        insert_message_sql = "INSERT INTO user_info(name, storing_gb) VALUES(?, ?)"
        data = (name, 0)
        message_id = self._insert_row(insert_message_sql, data)
        if message_id == -1:
            raise Exception(f"unable to insert user {name}")
        user_id = message_id

        insert_message_sql = "INSERT INTO user_password(password_hash, user_id) VALUES(?, ?)"
        message_id = self._insert_row(insert_message_sql, [password, user_id])
        if message_id == -1:
            raise Exception(f"unable to insert user password {name=}\n{password=}")

        insert_message_sql = "INSERT INTO user_file_key(key, user_id) VALUES(?, ?)"
        message_id = self._insert_row(insert_message_sql, [file_key, user_id])
        if message_id == -1:
            raise Exception(f"unable to insert user file key {name=}\n{file_key=}")

        user = self._get_user_by_name(name)
        user.current_addr = addr
        return user

    def check_if_user_exist_by_name(self, name: str) -> bool:
        query = "SELECT * FROM user_info WHERE name == ?"
        user = self._execute_and_fetch(query, [name])
        if not user:
            return False
        return True

    def is_file_exist_by_name(self, user: User, filename: str):
        query = "SELECT * FROM user_file WHERE user_id == ? AND name == ?"
        resp = self._execute_and_fetch(query, [user.user_db_id, filename])
        if not resp:
            return False
        return True

    def add_file(
        self, filename: str, file_hash: str, file_len: int, nonce: str, user: User, user_file_stripes: List[protocol.GetFileRespStripe]
    ) -> UserFile:
        insert_message_sql = "INSERT INTO user_file(name, hash, len, nonce, user_id) VALUES(?, ?, ?, ?, ?)"
        data = (filename, file_hash, file_len, nonce, user.user_db_id)
        message_id = self._insert_row(insert_message_sql, data)
        if message_id == -1:
            raise Exception("unable to insert user file")
        file_db_id = message_id
        user_file = UserFile(owner=user.name, name=filename, hash=file_hash, len=file_len, nonce=nonce)
        for file_stripe in user_file_stripes:
            stripe_db_id = self._insert_file_stripe(file_stripe, file_db_id)
            stripe = FileStripe(
                hash=file_stripe["hash"],
                is_parity=file_stripe["is_parity"],
                is_first=file_stripe["is_first"],
                id=file_stripe["id"],
                file_db_id=file_db_id,
                stripe_db_id=stripe_db_id,
                location=file_stripe["peer"],
            )
            user_file.stripes.append(stripe)

        user.owned_files.append(user_file)
        new_storing_gb = user.storing_gb + utils.gb_from_amount__bytes(file_len)
        self._update_user_storing_gb(user, new_storing_gb)
        print(f"add_file {message_id=}")
        return user_file

    def _update_user_storing_gb(self, user: User, new_storing_gb: float):
        insert_message_sql = f"UPDATE user_info SET storing_gb = ? WHERE user_id == ?"
        message_id = self._update_row(insert_message_sql, [new_storing_gb, user.user_db_id])
        if message_id == -1:
            raise Exception("unable to update user storing_gb file")
        user.user_db_id = new_storing_gb

    def _insert_file_stripe(self, file_stripe: protocol.GetFileRespStripe, file_db_id: int):
        insert_message_sql = (
            "INSERT INTO file_stripe(client_stripe_id, hash, is_parity, is_first, location, file_id) VALUES(?, ?, ?, ?, ?, ?)"
        )
        data = (file_stripe["id"], file_stripe["hash"], file_stripe["is_parity"], file_stripe["is_first"], file_stripe["peer"], file_db_id)
        message_id = self._insert_row(insert_message_sql, data)
        if message_id == -1:
            raise Exception("unable to insert user file")
        return message_id

    def _get_user_file_id_by_filename(self, user: User, filename: str):
        query = "SELECT file_id FROM user_file where user_id == ? AND name == ?"
        file_db_id = self._execute_and_fetch(query, [user.user_db_id, filename])
        return file_db_id

    def _get_user_files_by_user_id(self, user: User) -> List[UserFile]:
        query = "SELECT * FROM user_file where user_id == ?"
        user_data = self._execute_and_fetch(query, [user.user_db_id])
        files: List[UserFile] = []
        for row in user_data:
            user_file = UserFile(
                owner=user.name,
                file_db_id=row[0],
                name=row[1],
                hash=row[2],
                len=row[3],
                nonce=row[4],
            )
            query = "SELECT * FROM file_stripe WHERE file_id == ?"
            stripe_info = self._execute_and_fetch(query, [user_file.file_db_id])
            for stripe_row in stripe_info:
                file_stripe = FileStripe(
                    stripe_db_id=stripe_row[0],
                    id=stripe_row[1],
                    hash=stripe_row[2],
                    is_parity=bool(stripe_row[3]),
                    is_first=bool(stripe_row[4]),
                    location=stripe_row[5],
                    file_db_id=stripe_row[6],
                )
                user_file.stripes.append(file_stripe)
            files.append(user_file)
        return files

    def _get_user_by_name(self, name: str) -> User | None:
        query = "SELECT * FROM user_info where name == ?"
        resp = self._execute_and_fetch(query, [name])
        if not resp:
            return None
        user_data = resp[0]
        user = User(user_db_id=user_data[0], name=user_data[1], storing_gb=user_data[2], current_addr=())
        return user

    def _execute_and_fetch(self, query: str, data: Iterable) -> list | None:
        try:
            self.mutex.acquire()
            c = self.conn.cursor()
            c.execute(query, data)
            data = c.fetchall()
        except Exception as e:
            self.mutex.release()
            print(f"couldn't execute query: {query=}\n{data=}\n{e=}")
            return None
        self.mutex.release()
        return data

    def _update_row(self, update_sql: str, data: Iterable):
        try:
            self.mutex.acquire()
            c = self.conn.cursor().execute(update_sql, data)
            self.conn.commit()
        except Exception as e:
            print(f"Exception while trying to open the database:\n{e}")
            self.mutex.release()
            return -1

        ret = c.lastrowid
        self.mutex.release()
        print(f"update_row last id: {ret}")
        return ret

    def _insert_row(self, insert_sql: str, data: Iterable) -> int | None:
        try:
            self.mutex.acquire()
            c = self.conn.cursor().execute(insert_sql, data)
            self.conn.commit()
        except Exception as e:
            print(f"Exception while trying to open the database:\n{e}")
            self.mutex.release()
            return -1

        ret = c.lastrowid
        self.mutex.release()
        print(f"insert_row last id: {ret}")
        return ret

    @staticmethod
    def _create_connection(db_file_path: str) -> sqlite3.connect:
        try:
            return sqlite3.connect(db_file_path, check_same_thread=False, timeout=20)
        except Exception as e:
            print(f"Exception while trying to open the database {e}")


if __name__ == "__main__":
    db_path = "./server.db"
    if Path(db_path).is_file():
        os.remove(db_path)
    sql = SQLLoader("./server.db")

    user1 = sql.add_user("poncho", ("localhost", 12), password="lalalala")

    peer_name = "lolo"
    # stripe1:
    hash1 = "abaaa"

    is_parity1 = False
    is_first1 = True
    id1 = "stripe1"

    # stripe2:
    hash2 = "aabaa"

    is_parity2 = False
    is_first2 = True
    id2 = "stripe1"

    # stripe3:
    hash3 = "abaaa"
    is_parity3 = False
    is_first3 = True
    id3 = "stripe1"

    user_file_stripes1: List[protocol.GetFileRespStripe] = [
        {"id": id1, "hash": hash1, "peer": peer_name, "addr": (), "is_first": is_first1, "is_parity": is_parity1},
        {"id": id2, "hash": hash2, "peer": peer_name, "addr": (), "is_first": is_first2, "is_parity": is_parity2},
        {"id": id3, "hash": hash3, "peer": peer_name, "addr": (), "is_first": is_first3, "is_parity": is_parity3},
    ]

    sql.add_file(
        filename="file1", file_hash="filehash", file_len=126, nonce=str(os.urandom(16)), user=user1, user_file_stripes=user_file_stripes1
    )

    result_user = sql.load_user_data("poncho", ())
    print(result_user)
