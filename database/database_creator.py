import logging
import sqlite3


class DatabaseCreator:
    @staticmethod
    def create_database(db_file_path: str):
        logging.info(f"Creating database in path: {db_file_path}")
        with sqlite3.connect(db_file_path) as conn:
            conn.execute("PRAGMA foreign_keys = ON;")
            DatabaseCreator.create_user_table(conn)
            DatabaseCreator.create_user_file_table(conn)
            DatabaseCreator.create_stripe_table(conn)
            DatabaseCreator.create_user_password_table(conn)
            DatabaseCreator.create_user_file_key_table(conn)

    @staticmethod
    def create_table(conn, create_table_sql):
        """create a table from the create_table_sql statement
        :param conn: Connection object
        :param create_table_sql: a CREATE TABLE statement
        :return:
        """
        try:
            c = conn.cursor()
            c.execute(create_table_sql)
        except Exception as e:
            raise Exception(e)
            # print(e)

    @staticmethod
    def create_user_table(conn):
        create_user_info = """CREATE TABLE IF NOT EXISTS user_info(
                                            user_id INTEGER PRIMARY KEY,
                                            name varchar(50),
                                            storing_gb REAL
                                          ); """

        DatabaseCreator.create_table(conn, create_user_info)

    @staticmethod
    def create_user_file_table(conn):
        create_user_file = """CREATE TABLE IF NOT EXISTS user_file(
                                            file_id INTEGER PRIMARY KEY,
                                            name varchar(50),
                                            hash varchar(50),
                                            len int,
                                            nonce varchar(50),
                                            user_id int
                                                 ); """
        DatabaseCreator.create_table(conn, create_user_file)

    @staticmethod
    def create_stripe_table(conn):
        create_stripes = """CREATE TABLE IF NOT EXISTS file_stripe(
                                            stripe_id INTEGER PRIMARY KEY,
                                            client_stripe_id varchar(50),
                                            hash varchar(50),
                                            is_parity int,
                                            is_first int,
                                            location varchar(50),
                                            file_id int
                                                 ); """
        DatabaseCreator.create_table(conn, create_stripes)

    @staticmethod
    def create_user_password_table(conn):
        create_user_passwords = """CREATE TABLE IF NOT EXISTS user_password(
                                                password_id INTEGER PRIMARY KEY,
                                                password_hash varchar(50),
                                                user_id int
                                                     ); """
        DatabaseCreator.create_table(conn, create_user_passwords)

    @staticmethod
    def create_user_file_key_table(conn):
        create_user_passwords = """CREATE TABLE IF NOT EXISTS user_file_key(
                                                key_id INTEGER PRIMARY KEY,
                                                key varchar(50),
                                                user_id int
                                                     ); """
        DatabaseCreator.create_table(conn, create_user_passwords)
