import struct
import socket
import hashlib
import os
import time
from dotenv import load_dotenv
from enum import Enum
from typing import Optional

# App Constants
SYNC = 0xDCC023C2
SYNC_BYTES = struct.pack("!I", SYNC)
MAX_PAYLOAD = 4096
HEADER_SIZE = 15
MAX_FRAME_SIZE = MAX_PAYLOAD + HEADER_SIZE
RETRY_LIMIT = 16
RETRY_INTERVAL = 1

CONNECTION_MAX_RETRIES = RETRY_LIMIT


# Flags
class Flags(Enum):
    FLAG_ACK = 0x80
    FLAG_END = 0x40
    FLAG_RST = 0x20


def compute_checksum(frame_bytes):
    b = bytearray(frame_bytes)
    b[8:10] = b"\x00\x00"
    s = 0

    for i in range(0, len(b), 2):
        if i + 1 < len(b):
            word = b[i] << 8 | b[i + 1]
        else:
            word = b[i] << 8
        s += word
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF


class DCCNETFrame:
    def __init__(self, checksum=0, length=0, frame_id=0, flags=0, data=b""):
        self.sync = SYNC
        self.checksum = checksum
        self.length = length
        self.frame_id = frame_id
        self.flags = flags
        self.data = data

    def pack(self):
        header_with_zeroed_checksum = struct.pack(
            "!IIHHHB",
            self.sync,
            self.sync,
            0,
            self.length,
            self.frame_id,
            self.flags,
        )

        data_as_bytes = bytes(self.data, encoding="ascii") if self.data else b""

        if len(data_as_bytes) > MAX_PAYLOAD:
            raise ValueError("Data exceeds maximum payload size")

        self.checksum = compute_checksum(header_with_zeroed_checksum + data_as_bytes)
        header = struct.pack(
            "!IIHHHB",
            self.sync,
            self.sync,
            self.checksum,
            self.length,
            self.frame_id,
            self.flags,
        )
        return header + data_as_bytes

    @classmethod
    def unpack(cls, frame_bytes):
        # minimum length for header: SYNC's (2 * 4 bytes) + checksum (2) + length (2) + frame_id (2) + flags (1)
        if len(frame_bytes) < HEADER_SIZE:
            raise ValueError("Frame too short to unpack")
        sync1, sync2, checksum, length, frame_id, flags = struct.unpack(
            "!IIHHHB", frame_bytes[:HEADER_SIZE]
        )
        if sync1 != SYNC or sync2 != SYNC:
            raise ValueError("SYNC mismatch while unpacking frame")
        data = frame_bytes[HEADER_SIZE : HEADER_SIZE + length]
        # Verify checksum: compute over the whole frame with checksum field zeroed.
        frame_header_without_checksum = struct.pack(
            "!IIHHHB",
            sync1,
            sync2,
            0,
            length,
            frame_id,
            flags,
        )
        computed = compute_checksum(frame_header_without_checksum + data)
        if computed != checksum:
            raise ValueError("Checksum mismatch while unpacking frame")
        return cls(checksum, length, frame_id, flags, data)


class DCCNETTransmitter:
    def __init__(self, socket, mode="md5"):
        self.socket = socket
        self.mode = mode

    def send_frame(self, frame: DCCNETFrame):
        print(f"Transmitting frame [{frame.frame_id}]")
        packed_frame = frame.pack()
        self.socket.sendall(packed_frame)

    def send_ack_frame(self, frame_id: int):
        print(f"Transmitting ACK frame [{frame_id}]")
        ack_frame = DCCNETFrame(
            length=0,
            frame_id=frame_id,
            flags=Flags.FLAG_ACK.value,
        )
        self.send_frame(ack_frame)


class DCCNETReceiver:
    def __init__(self, socket, mode="md5"):
        self.socket = socket
        self.mode = mode

    def receive_frame(self, retry=False) -> DCCNETFrame:
        response_data: bytes = None

        retry_amount = RETRY_LIMIT if retry else 1

        for attempt in range(retry_amount):
            print(f"Receiving frame ({attempt + 1}/{retry_amount})")
            try:
                response_data = self.socket.recv(MAX_FRAME_SIZE)
                if not response_data:
                    raise Exception("No data received")
                break
            except Exception:
                print(f"Failed to receive ({attempt + 1}/{retry_amount})")
                time.sleep(RETRY_INTERVAL)

        return self.__get_frame_from_raw_data(response_data) if response_data else None

    def __get_frame_from_raw_data(self, data: bytes) -> Optional[DCCNETFrame]:
        data_aux = data
        frame: Optional[DCCNETFrame] = None

        while not frame and len(data_aux) >= HEADER_SIZE:
            pos = data_aux.find(SYNC_BYTES)
            potential_frame = data_aux[pos:]
            frame = DCCNETFrame.unpack(potential_frame)

            if (
                frame is None
                or pos == -1
                or len(data_aux) - pos < HEADER_SIZE
                or data_aux[pos + 4 : pos + 8] != SYNC_BYTES
            ):
                print("Incomplete or corrupted frame, tring to re-sync...")
                data_aux = data_aux[pos + 8 :]
                continue

        return frame


class DCCNETEmulator:
    def __init__(self, ip, port, gas=None, mode="md5", infile=None, outfile=None):
        self.ip = ip
        self.port = port
        self.gas = gas
        self.mode = mode  # 'md5' or 'xfer'
        self.infile = infile
        self.outfile = outfile
        self.sock = None
        self.current_frame_id = 0
        self.last_recv_id = None
        self.last_recv_checksum = None
        self.stop_flag = False

    def try_connect(self):
        for attempt in range(CONNECTION_MAX_RETRIES):
            try:
                print(
                    f"Trying to connect to {self.ip}:{self.port} (attempt {attempt + 1}/{CONNECTION_MAX_RETRIES})"
                )

                addrinfo = socket.getaddrinfo(self.ip, None)
                family = addrinfo[0][0]
                self.sock = socket.socket(family, socket.SOCK_STREAM)
                self.sock.settimeout(RETRY_INTERVAL)

                self.sock.connect((self.ip, self.port))
                print("Connected!")
                return True

            except (socket.timeout, ConnectionRefusedError, OSError) as e:
                print(f"Connection failed: {e}")

        print(f"Failed to connect after {CONNECTION_MAX_RETRIES} attempts.")
        return False

    def start(self):
        if not self.try_connect():
            return

        self.transmitter = DCCNETTransmitter(self.sock, self.mode)
        self.receiver = DCCNETReceiver(self.sock, self.mode)

        formatted_gas = self.gas + "\n"
        gas_frame = DCCNETFrame(
            length=len(formatted_gas),
            frame_id=self.current_frame_id,
            flags=0,
            data=formatted_gas,
        )

        print("SENDING GAS frame")
        self.send_data_frame_with_retransmit(gas_frame)

        if self.mode == "md5":
            self.receiver_func()

        print("Closing connection...")
        self.sock.close()

    def toggle_frame_id(self):
        self.current_frame_id = 1 - self.current_frame_id

    def send_data_frame_with_retransmit(self, frame: DCCNETFrame) -> DCCNETFrame:
        ack_received = False
        response_frame: DCCNETFrame = None

        for attempt in range(RETRY_LIMIT):
            print(
                f"Sending data frame [{frame.frame_id}] ({attempt + 1}/{RETRY_LIMIT})"
            )
            try:
                self.transmitter.send_frame(frame)
                response_frame = self.receiver.receive_frame()
                if response_frame is None:
                    print("No response received")
                    continue
                if response_frame.flags & Flags.FLAG_ACK.value:
                    if response_frame.frame_id == frame.frame_id:
                        print(f"ACK received for frame [{frame.frame_id}]")
                        ack_received = True
                        self.toggle_frame_id()
                        break
                    else:
                        print(
                            f"ACK received for unexpected frame [{response_frame.frame_id}]"
                        )
                        continue
                else:
                    print(f"Unexpected frame type received.")
                    time.sleep(RETRY_INTERVAL)
                    continue
            except Exception as e:
                print(f"Failed transmission: {e}")
                time.sleep(RETRY_INTERVAL)

        if not ack_received:
            self.stop_flag = True
            raise ValueError("Transmission failed after maximum retries.")

        return response_frame

    def receiver_func(self):
        message_buffer = ""
        while not self.stop_flag:
            try:
                frame = self.receiver.receive_frame(retry=True)

                if not frame:
                    print("No frame found, SYNC failed.")
                    break

                if frame.flags & Flags.FLAG_ACK.value:
                    print("ACK frame received out of order")
                    continue
                elif frame.flags & Flags.FLAG_RST.value:
                    print("Reset frame received. Shutting down connection.")
                    self.stop_flag = True
                    break
                elif frame.flags & Flags.FLAG_END.value:
                    print("End frame received. For now, will be treated as a data one.")
                    self.stop_flag = True
                else:
                    print("Data frame received")

                if (
                    self.last_recv_id == frame.frame_id
                    and self.last_recv_checksum == frame.checksum
                ):
                    print("Duplicate frame received. Re-sending ACK...")
                    self.transmitter.send_ack_frame(frame.frame_id)
                    continue

                self.transmitter.send_ack_frame(frame.frame_id)
                self.last_recv_id = frame.frame_id
                self.last_recv_checksum = frame.checksum

                if self.mode == "md5":
                    text = frame.data.decode("ascii", errors="ignore")
                    message_buffer += text
                    print("message buffer:", message_buffer)

                    if message_buffer.find("\n") != -1:
                        lines = message_buffer.split("\n")[:-1]
                        for line in lines:
                            if line:
                                md5_hash = hashlib.md5(line.encode("ascii")).hexdigest()
                                md5_frame_data = md5_hash + "\n"
                                md5_frame = DCCNETFrame(
                                    length=len(md5_frame_data),
                                    frame_id=self.current_frame_id,
                                    flags=0,
                                    data=md5_frame_data,
                                )
                                self.send_data_frame_with_retransmit(md5_frame)
                        # elif self.mode == "xfer":
                        #     TODO: write the data to the output file
                        message_buffer = message_buffer.split("\n")[-1]
            except Exception as e:
                print("[receiver] Exception:", e)
                import traceback

                traceback.print_exc()
                continue

    # def transmitter_func(self):
    #     if self.mode == "md5":
    #         # In MD5 mode, no data is sent from our side except the authentication and MD5 responses.
    #         return
    #     elif self.mode == "xfer":
    #         # For file transfer, read file and send in frames
    #         with open(self.infile, "rb") as f:
    #             while True:
    #                 chunk = f.read(MAX_FRAME_SIZE)
    #                 if not chunk:
    #                     frame = DCCNETFrame(
    #                         length=0,
    #                         frame_id=self.current_frame_id,
    #                         flags=Flags.FLAG_END.value,
    #                     )
    #                     self.send_frame_with_retransmit(frame)
    #                     break
    #                 # Build and send frame
    #                 frame = DCCNETFrame(
    #                     length=len(chunk),
    #                     frame_id=self.current_frame_id,
    #                     flags=0,
    #                     data=chunk,
    #                 )
    #                 self.send_frame_with_retransmit(frame)
    #                 # Toggle frame id for next frame
    #                 self.current_frame_id = 1 - self.current_frame_id


if __name__ == "__main__":
    load_dotenv(".env")

    # TODO: process args
    emulator = DCCNETEmulator(
        os.getenv("SERVER_ADDRESS_NAME"),
        int(os.getenv("PORT")),
        gas=os.getenv("GAS"),
        mode="md5",
    )

    emulator.start()
