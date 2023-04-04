import logging

import settings
from protocol import *
from collections import deque
import time
import threading
import utils
from client_dataclasses import *

STRIPE_ID = str


def init_file_by_size(path: str, size: int):
    """ Creates sparse (empty) file of specified size. size is in bytes. """
    with open(path, "ab") as f:
        f.seek(size)
        f.write(b"")


def write_to_position(path: str, data: bytes, pos: int):
    """ Writes data to specified position in file. pos is in bytes. """
    with open(path, "ab") as f:
        f.seek(pos)
        f.write(data)


def calculate_timeout(msg_count: int) -> float:
    """ Calculates and returns expected max timeout for an entire sequence of messages. """
    return msg_count * settings.MAX_PACKET_TIMEOUT + 10


def calculate_pos(seq, data_size: int) -> int:
    """ Calculates position in file to (seek and) write to using sequence number. """
    return seq * settings.MAX_DATA_SIZE


class RecvStripeHandler:
    """ Handler for receiving a single stripe from peer. Handles all appends and writes to specified folder"""

    def __init__(self, msg: NewStripe | GetStripeResp, temp_dir_path: str, final_dir_path: str):
        self.id = msg.stripe_id
        self.size = msg.size
        self.amount = msg.amount
        self.temp_path = temp_dir_path
        self.final_path = final_dir_path
        self.start_count = time.perf_counter()
        self.received_list = [0 for _ in range(0, msg.amount)]
        self.amount_received = 0
        self._timeout = calculate_timeout(msg.amount)
        self.timeout_timer = threading.Timer(self._timeout, self.handle_timeout)
        self.timeout_timer.start()
        self.finished = False
        init_file_by_size(temp_dir_path + msg.stripe_id, msg.size)

    def is_valid_data(self, data: bytes, seq: int) -> bool:
        data_size = len(data)
        if data_size > settings.MAX_DATA_SIZE:
            raise ValueError(f"Message contained raw data size too large: {data_size}")
        if seq != self.amount - 1 and data_size != settings.MAX_DATA_SIZE:
            raise ValueError(f"Message contained improper raw data size: {data_size}")
        return True

    def new_append(self, msg: AppendStripe | AppendGetStripe) -> bool:
        """ Handles append of stripe. returns true if stripe has been completely received. """
        data = utils.decode_from_json(msg.raw)
        if not self.is_valid_data(data, msg.seq):
            raise ValueError(f"Message contained improper raw data size: {len(msg.raw)}")
        position = calculate_pos(msg.seq, len(msg.raw))
        write_to_position(path=self.temp_path + self.id, data=data, pos=position)
        self.received_list[msg.seq] = 1
        self.amount_received += 1
        if self.amount_received == self.amount:
            self.handle_complete()
            return True
        return False

    def handle_complete(self):
        utils.move_stripe(self.id, self.temp_path, self.final_path)
        self.timeout_timer.cancel()
        self.finished = True
        logging.debug(f"RecvStripeHandler has finished, stripe id: {self.id}")

    def handle_timeout(self):
        # TODO: handle retries
        raise TimeoutError("stripe timeout exceeded")


class RecvFileHandler:
    """
    Handler for receiving a file. Contains all RecvStripeHandlers for each of the file's stripes.
    Forwards appends directly to the RecvStripeHandlers
    """
    def __init__(self, msg: GetFileResp, key: bytes):
        self.file_name = msg.file_name
        self.stripes: List[Dict] = msg.stripes
        self.temp_stripes: List[TempStripe] = []
        self.init_temp_stripes(msg)
        self.temp_file = TempFile(msg.file_name, stripes=self.temp_stripes)
        self.stripe_handlers: Dict[STRIPE_ID, RecvStripeHandler] = {}
        self.finished = False
        self._daemon_interval = 10
        # TODO: CALCULATE TIMEOUT
        self.timeout = 1000
        self.daemon_thread = threading.Thread(target=self.run_daemon)
        self.daemon_thread.start()
        self.key = key
        self.nonce = utils.decode_from_json(msg.nonce)

    def is_handlers_finished(self) -> bool:
        """ Returns true if all RecvStripeHandlers have finished. """
        for handler in self.stripe_handlers.values():
            if not handler.finished:
                return False
        for temp_stripe in self.temp_stripes:
            temp_stripe.complete = True
        return True

    def run_daemon(self):
        """ Sleeps for constant interval and checks if all RecvStripeHandlers have finished. """
        # TODO: add timeout
        while True:
            time.sleep(self._daemon_interval)
            if self.is_handlers_finished():
                self.combine_stripes()
                self.finished = True
                return

    def init_temp_stripes(self, msg: GetFileResp):
        """ Initializes TempStripe representation of stripes. """
        for msg_stripe in msg.stripes:
            temp_stripe = TempStripe(
                id=msg_stripe["id"],
                is_parity=msg_stripe["is_parity"],
                peer_name=msg_stripe["peer"],
                peer_addr=msg_stripe["addr"],
                is_first=msg_stripe["is_first"],
                parent_file=msg.file_name,
            )
            self.temp_stripes.append(temp_stripe)

    def new_recv_handler(self, msg: GetStripeResp):
        """ Creates individual RecvStripeHandler that's responsible for receiving a single stripe. """
        self.stripe_handlers[msg.stripe_id] = RecvStripeHandler(
            msg, temp_dir_path=settings.RESTORE_TEMP_PATH, final_dir_path=settings.RESTORE_STRIPE_FINISHED_PATH
        )

    def append_stripe(self, msg: AppendGetStripe):
        """ Forwards append to appropriate RecvStripeHandler. """
        self.stripe_handlers[msg.stripe_id].new_append(msg)

    def combine_stripes(self):
        temp_stripes = self.temp_file.stripes
        for temp_stripe in self.temp_file.stripes:
            if not temp_stripe.complete:
                raise Exception(f"combine_stripes() was called with temp file containing incomplete temp stripes {temp_stripes=}")
            if temp_stripe.is_parity:
                self.handle_parity(temp_stripe)
                return
        combined_ciphertext = utils.get_data_from_stripe_ids(
            *[temp_stripe.id for temp_stripe in temp_stripes], ordered=temp_stripes[0].is_first
        )
        original_data = utils.decrypt_file_data(combined_ciphertext, key=self.key, nonce=self.nonce)
        utils.remove_temp_stripes(
            *[file_stripe.id for file_stripe in temp_stripes], path=settings.RESTORE_STRIPE_FINISHED_PATH
        )
        utils.save_file_in_restore(self.temp_file.name, original_data)

    def handle_parity(self, parity: TempStripe):
        temp_stripes = self.temp_file.stripes
        for temp_stripe in self.temp_file.stripes:
            if not temp_stripe.is_parity:
                combined_ciphertext = utils.get_data_from_parity_with_ids(temp_stripe.id, parity.id, temp_stripe.is_first)
                original_data = utils.decrypt_file_data(combined_ciphertext, key=self.key, nonce=self.nonce)
                utils.remove_temp_stripes(
                    *[file_stripe.id for file_stripe in temp_stripes], path=settings.RESTORE_TEMP_PATH
                )
                utils.save_file_in_restore(self.temp_file.name, original_data)
                return
        raise Exception("Couldn't find non parity stripe while attempting restore")
