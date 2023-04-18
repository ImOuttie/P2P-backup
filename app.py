import logging
import os
import threading
import time
from pathlib import Path
from tkinter import *
from tkinter import filedialog
from typing import List, Callable, Any

import encryption_utils
import protocol
import settings
import utils
from client import Client
from settings import *


class Application:
    def __init__(self):
        self.client = None
        self.root_on = False
        self.root = Tk()
        self.remember_login = False

    def change_remember_login(self):
        self.remember_login = not self.remember_login
        logging.debug(f"Remember login: {self.remember_login}")

    def start(self, name: str, port: int):
        logging.basicConfig(level=LOGLEVEL)
        self.client = Client(name, port)
        if not LOCALHOST:
            self.client._server_addr = (input("enter ip \r\n"), SERVER_PORT)
        logging.debug(f"Client {name} up and running on port {port}")

        private_key = encryption_utils.load_private_ecdh_key(rf"{CLIENT_KEYS_PATH}{name}\private.pem")
        public_key = encryption_utils.load_public_ecdh_key(rf"{CLIENT_KEYS_PATH}{name}\public.pem")
        f = encryption_utils.HandshakeWithServerTask(
            private_key=private_key, public_key=public_key, server_addr=SERVER_ADDR, sock=self.client.sock
        ).begin()
        self.client.server_fernet = f

        self.first_screen()

    def first_screen(self):
        self.root.title("P2P-backup™")
        self.root.resizable(True, True)
        self.root.geometry("925x500+200+300")
        self.root.config(background="white")

        register_button = Button(self.root,
                                 text="Register",
                                 width=25,
                                 pady=36,
                                 font=("Helvetica Light", 15, "bold"),
                                 bg="#57a1f8",
                                 border=0,
                                 command=lambda: self.register_screen(self.root))
        register_button.place(x=500, y=150)

        login_button = Button(self.root,
                              text="Login",
                              width=25,
                              pady=36,
                              font=("Helvetica Light", 15, "bold"),
                              bg="#57a1f8", border=0,
                              command=lambda: self.login_screen(self.root))
        login_button.place(x=100, y=150)

        heading = Label(self.root, text="P2P-backup™", fg="#57a1f8", bg="white", font=("Microsoft YaHei UI Light", 40, "bold"))
        heading.place(x=100, y=5)
        self.root.mainloop()

    def login_screen(self, prev: Tk, bad_resp=None):
        prev.destroy()
        window = Tk()
        window.title("Log-in")
        window.geometry("550x500")
        window.config(background="white")
        frm = Frame(window, width=300, height=400, bg="white")
        frm.place(x=100, y=70)
        if bad_resp is not None:
            if bad_resp == protocol.ServerLoginResponse.NAME_INVALID:
                name_taken = Label(frm, text="Name invalid", fg="red", bg="white", font=("Microsoft YaHei UI Light", 9))
                name_taken.place(x=25, y=107)
            elif bad_resp == protocol.ServerLoginResponse.INCORRECT_PASSWORD:
                incorrect_password = Label(frm, text="Incorrect password", fg="red", bg="white", font=("Microsoft YaHei UI Light", 9))
                incorrect_password.place(x=25, y=178)
            else:
                raise Exception(f"Unknown login response: {bad_resp}")

        label2 = Label(frm, text="Remember me?", fg="black", bg="white", font=("Microsoft YaHei UI Light", 9))
        label2.place(x=25, y=225)

        var_flag = IntVar()
        stay_in = Checkbutton(frm, width=1, height=1, cursor="hand2", bg="white", fg="#57a1f8", variable=var_flag,
                              command=self.change_remember_login, activebackground="white", activeforeground="white")
        stay_in.place(x=120, y=225)

        def_username, def_password = "username", "password"
        if settings.GET_LOGIN_INFO:
            x = utils.get_login_information(self.client.name)
            if x is not None:
                def_username, def_password = x
                def_username = def_username.strip()
                var_flag.set(1)
                self.change_remember_login()

        heading = Label(frm, text="Log-in", fg="#57a1f8", bg="white", font=("Microsoft YaHei UI Light", 23, "bold"))
        heading.place(x=100, y=5)



        user = Entry(frm, width=25, fg="black", border=0, font=("Microsoft YaHei UI Light", 11))
        user.place(x=30, y=80)
        user.insert(0, def_username)
        Frame(frm, width=295, height=2, bg="black").place(x=25, y=107)

        passcode = Entry(frm, width=25, fg="black", border=0, font=("Microsoft YaHei UI Light", 11), show="*")
        passcode.place(x=30, y=150)
        passcode.insert(0, def_password)
        Frame(frm, width=295, height=2, bg="black").place(x=25, y=177)

        Button(frm, width=39, pady=7, text="Log-in", fg="white", bg="#57a1f8", border=0,
               command=lambda: self.login(user.get(), passcode.get(), prev=window)).place(x=35, y=264)

        label = Label(frm, text="Don't have an account?", fg="black", bg="white", font=("Microsoft YaHei UI Light", 9))
        label.place(x=75, y=300)

        register_button = Button(frm, width=6, text="Register", border=0, bg="white", cursor="hand2", fg="#57a1f8",
                                 command=lambda: self.register_screen(window))
        register_button.place(x=215, y=300)

        window.mainloop()

    def register_screen(self, prev: Tk, bad_resp: protocol.ServerRegisterResponse = None):
        prev.destroy()
        window = Tk()
        window.title("Register")
        window.geometry("550x500")
        window.config(background="white")

        frm = Frame(window, width=300, height=400, bg="white")
        frm.place(x=100, y=70)
        if bad_resp is not None:
            if bad_resp == protocol.ServerRegisterResponse.NAME_TAKEN:
                name_taken = Label(frm, text="Name already taken", fg="red", bg="white", font=("Microsoft YaHei UI Light", 9))
                name_taken.place(x=25, y=107)
            else:
                raise Exception(f"Unknown login response: {bad_resp}")

        heading = Label(frm, text="Register", fg="#57a1f8", bg="white", font=("Microsoft YaHei UI Light", 23, "bold"))
        heading.place(x=100, y=5)

        label2 = Label(frm, text="Remember me?", fg="black", bg="white", font=("Microsoft YaHei UI Light", 9))
        label2.place(x=25, y=225)

        var_flag = IntVar()
        stay_in = Checkbutton(frm, width=1, height=1, cursor="hand2", bg="white", fg="#57a1f8", variable=var_flag,
                              activebackground="white", activeforeground="white")
        stay_in.place(x=120, y=225)

        user = Entry(frm, width=25, fg="black", border=0, font=("Microsoft YaHei UI Light", 11))
        user.place(x=30, y=80)
        user.insert(0, "username")
        Frame(frm, width=295, height=2, bg="black").place(x=25, y=107)

        passcode = Entry(frm, width=25, fg="black", border=0, font=("Microsoft YaHei UI Light", 11), show="*")
        passcode.place(x=30, y=150)
        passcode.insert(0, "password")
        Frame(frm, width=295, height=2, bg="black").place(x=25, y=177)

        Button(frm, width=39, pady=7, text="Register", fg="white", bg="#57a1f8", border=0,
               command=lambda: self.register(user.get(), passcode.get(), prev=window)).place(x=35, y=264)

        label = Label(frm, text="Already have an account?", fg="black", bg="white", font=("Microsoft YaHei UI Light", 9))
        label.place(x=75, y=300)

        register_button = Button(frm, width=6, text="Log-in", border=0, bg="white", cursor="hand2", fg="#57a1f8",
                                 command=lambda: self.login_screen(window))
        register_button.place(x=215, y=300)

        window.mainloop()

    def start_client(self):
        receive_thread = threading.Thread(target=self.client.receive_data)
        task_thread = threading.Thread(target=self.client.handle_tasks)
        receive_thread.start()
        task_thread.start()

    def login(self, username: str, password: str, prev: Tk):
        hashed_password = encryption_utils.hash_password(password)

        login_task = encryption_utils.LoginToServerTask(
            name=username,
            password_hash=hashed_password,
            sock=self.client.sock,
            fernet=self.client.server_fernet,
        )
        resp = login_task.begin()
        if resp == protocol.ServerLoginResponse.SUCCESS:
            utils.store_login_information(username, password, self.client.name is not None)
            self.client.name = username
            self.start_client()
            self.regular_screen(prev)
        elif resp == protocol.ServerLoginResponse.NAME_INVALID:
            self.login_screen(prev=prev, bad_resp=resp)
            prev.destroy()
        elif resp == protocol.ServerLoginResponse.INCORRECT_PASSWORD:
            self.login_screen(prev=prev, bad_resp=resp)
            pass

    def register(self, username: str, password: str, prev: Tk):
        hashed_password = encryption_utils.hash_password(password)
        file_encryption_key = os.urandom(32)
        register_task = encryption_utils.RegisterToServerTask(
            name=username,
            password_hash=hashed_password,
            sock=self.client.sock,
            file_encryption_key=file_encryption_key,
            fernet=self.client.server_fernet,
        )
        resp = register_task.begin()
        if resp == protocol.ServerRegisterResponse.SUCCESS:
            self.client.name = username
            self.start_client()
            self.regular_screen(prev)
        elif resp == protocol.ServerRegisterResponse.NAME_TAKEN:
            self.register_screen(prev=prev, bad_resp=resp)

    def regular_screen(self, prev: Tk = None, req_file=None):
        if prev is not None:
            prev.destroy()

        root = Tk()
        root.title("P2P-backup™")
        root.geometry("925x500+200+300")
        root.resizable(True, True)
        root.config(background="white")

        if req_file is not None:
            retrieving_file_label = Label(root, text="Retrieving file, check restore folder soon", fg="green", bg="white",
                                          font=("Microsoft YaHei UI Light", 12, "bold"))
            retrieving_file_label.place(x=285, y=365)
            retrieving_file_label.after(3500, retrieving_file_label.destroy)

        backup_file = Button(root,
                             text="Backup file",
                             width=20,
                             pady=36,
                             font=("Helvetica Light", 15, "bold"),
                             bg="#57a1f8", border=0,
                             command=lambda: self.backup_file(root))
        backup_file.place(x=25, y=70)

        file_list_button = Button(root,
                                  text="Get file list",
                                  width=20,
                                  pady=36,
                                  font=("Helvetica Light", 15, "bold"),
                                  bg="#57a1f8", border=0,
                                  command=lambda: self.show_file_list(root))
        file_list_button.place(x=25, y=200)

        retrieve_file_button = Button(root,
                                      text="Retrieve file",
                                      width=20,
                                      pady=36,
                                      font=("Helvetica Light", 15, "bold"),
                                      bg="#57a1f8", border=0,
                                      command=lambda: self.retrieve_file_screen(root))
        retrieve_file_button.place(x=25, y=330)

        heading = Label(root, text="P2P-backup™", fg="#57a1f8", bg="white", font=("Microsoft YaHei UI Light", 40, "bold"))
        heading.place(x=285, y=5)

    def backup_file(self, prev: Tk):
        filename = self.browse_files()
        if filename is None:
            invalid_file_label = Label(prev, text="Invalid file", fg="red", bg="white", font=("Microsoft YaHei UI Light", 12, "bold"))
            invalid_file_label.place(x=285, y=105)
            invalid_file_label.after(1500, invalid_file_label.destroy)
            return
        self.client.req_send_file(filename)
        sending_file_label = Label(prev, text="File selected successfully, sending file in background", fg="green", bg="white",
                                   font=("Microsoft YaHei UI Light", 12, "bold"))
        sending_file_label.place(x=285, y=105)
        sending_file_label.after(2500, sending_file_label.destroy)

    def show_file_list(self, prev: Tk):
        files = self.get_file_list_from_server()
        prev.destroy()
        root = Tk()
        root.title("P2P-backup™")
        root.geometry("925x500+200+300")
        root.resizable(True, True)
        root.config(background="white")

        heading = Label(root, text="File list:", fg="#57a1f8", bg="white", font=("Microsoft YaHei UI Light", 40, "bold"))
        heading.place(x=50, y=5)

        Button(root, width=25, pady=7, text="Back", fg="white", bg="#57a1f8", border=0,
               command=lambda: self.regular_screen(root)).place(x=700, y=20)
        max_x = 925
        cur_y = 85
        cur_x = 30
        for file in files:
            f_label = Label(root, text=file, fg="black", bg="white", font=("Microsoft YaHei UI Light", 15, "bold"))
            if cur_x + 15 * len(file) > max_x:
                cur_y += 50
                cur_x = 30
                f_label.place(x=cur_x, y=cur_y)
            else:
                f_label.place(x=cur_x, y=cur_y)
                cur_x += 15 * len(file)

    def retrieve_file_screen(self, prev: Tk):
        files = self.get_file_list_from_server()
        prev.destroy()
        root = Tk()
        root.title("P2P-backup™")
        root.geometry("925x500+200+300")
        root.resizable(True, True)
        root.config(background="white")

        heading = Label(root, text="Press file to retrieve", fg="#57a1f8", bg="white", font=("Microsoft YaHei UI Light", 40, "bold"))
        heading.place(x=50, y=5)

        Button(root, width=25, pady=7, text="Back", fg="white", bg="#57a1f8", border=0,
               command=lambda: self.regular_screen(root)).place(x=700, y=20)
        max_x = 925
        cur_y = 85
        cur_x = 30

        def get_cmd(filename: str, window: Tk) -> Callable:
            return lambda: self.retrieve_file(filename, window)

        for file in files:
            f_button = Button(root, text=file, fg="black", bg="#57a1f8", font=("Microsoft YaHei UI Light", 15, "bold"),
                              command=get_cmd(file, root))
            if cur_x + 15 * len(file) > max_x:
                cur_y += 50
                cur_x = 30
                f_button.place(x=cur_x, y=cur_y)
            else:
                f_button.place(x=cur_x, y=cur_y)

                cur_x += 15 * len(file)

    def retrieve_file(self, filename: str, prev: Tk):
        self.client.request_file(filename)
        self.regular_screen(prev=prev, req_file=True)
        pass

    def get_file_list_from_server(self) -> List[str] | None:
        files = self.client.get_file_list()
        if not files:
            return None
        return files

    @staticmethod
    def browse_files() -> str | None:
        filename = filedialog.askopenfilename(initialdir="/",
                                              title="Select a File",
                                              filetypes=[("All files", "*.*")]
                                              )
        print(filename)
        if not filename:
            return None
        return filename if Path(filename).is_file() else None


def main():
    if len(sys.argv) < 3:
        name = None
        port = 30001
    else:
        name = sys.argv[1]
        port = int(sys.argv[2])
    app = Application()
    app.start(name=name, port=port)


if __name__ == '__main__':
    main()