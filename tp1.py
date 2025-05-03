import struct
import socket
import hashlib
import sys
import time
import argparse
from enum import IntEnum
from typing import Optional, Literal

import asyncio
from pathlib import Path
import aiofiles

# App Constants
SYNC = 0xDCC023C2
SYNC_BYTES = struct.pack("!I", SYNC)
MAX_PAYLOAD = 4096
HEADER_SIZE = 15
MAX_FRAME_SIZE = MAX_PAYLOAD + HEADER_SIZE
RETRY_LIMIT = 16
RETRY_INTERVAL = 1

CONNECTION_MAX_RETRIES = RETRY_LIMIT

THROTTLE_DELAY = 0.05  # Seconds. Used to simulate network delay.


# Flags
class Flags(IntEnum):
    FLAG_ACK = 0x80
    FLAG_END = 0x40
    FLAG_RST = 0x20


class Utils:
    @staticmethod
    def compute_checksum(frame_bytes: bytes) -> int:
        b = bytearray(frame_bytes)
        b[8:10] = b"\x00\x00"
        s = 0
        for i in range(0, len(b), 2):
            word = b[i] << 8 | (b[i + 1] if i + 1 < len(b) else 0)
            s += word
            s = (s & 0xFFFF) + (s >> 16)
        return ~s & 0xFFFF

    @staticmethod
    def parse_address(ip_port: str):
        if ":" not in ip_port:
            raise ValueError("Expected format <IP>:<PORT>")
        ip, port = ip_port.rsplit(":", 1)
        return ip, int(port)


class DCCNETFrame:
    def __init__(self, length=0, frame_id=0, flags=0, data=b"", checksum=0):
        self.length = length
        self.frame_id = frame_id
        self.flags = flags
        self.data = data
        self.checksum = checksum

    def pack(self):
        header = struct.pack(
            "!IIHHHB", SYNC, SYNC, 0, self.length, self.frame_id, self.flags
        )
        self.checksum = Utils.compute_checksum(header + self.data)
        header = struct.pack(
            "!IIHHHB", SYNC, SYNC, self.checksum, self.length, self.frame_id, self.flags
        )
        return header + self.data

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
        computed = Utils.compute_checksum(frame_header_without_checksum + data)
        if computed != checksum:
            raise ValueError("Checksum mismatch while unpacking frame")
        return cls(length, frame_id, flags, data, checksum)


class DCCNETTransmitter:
    def __init__(self, socket):
        self.socket = socket

    def send_frame(self, frame: DCCNETFrame):
        print(f"Transmitting frame [{frame.frame_id}]")
        packed_frame = frame.pack()
        self.socket.sendall(packed_frame)

    def send_ack_frame(self, frame_id: int):
        print(f"Transmitting ACK frame [{frame_id}]")
        ack_frame = DCCNETFrame(
            length=0,
            frame_id=frame_id,
            flags=Flags.FLAG_ACK,
        )
        self.send_frame(ack_frame)


class DCCNETReceiver:
    def __init__(self, socket):
        self.socket = socket

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


class DCCNETEmulatorMd5:
    def __init__(self, ip, port, gas=None):
        self.ip = ip
        self.port = port
        self.gas = gas

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

        self.transmitter = DCCNETTransmitter(self.sock)
        self.receiver = DCCNETReceiver(self.sock)

        formatted_gas = self.gas + "\n"
        gas_frame = DCCNETFrame(
            length=len(formatted_gas),
            frame_id=self.current_frame_id,
            flags=0,
            data=formatted_gas.encode("ascii"),
        )

        print("SENDING GAS frame")
        self.send_data_frame_with_retransmit(gas_frame)

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
                if response_frame.flags & Flags.FLAG_ACK:
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

                if frame.flags & Flags.FLAG_ACK:
                    print("ACK frame received out of order")
                    continue
                elif frame.flags & Flags.FLAG_RST:
                    print("Reset frame received. Shutting down connection.")
                    self.stop_flag = True
                    break
                elif frame.flags & Flags.FLAG_END:
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

                text = frame.data.decode("ascii", errors="ignore")
                message_buffer += text
                print("message buffer:", message_buffer)

                if message_buffer.find("\n") != -1:
                    lines = message_buffer.split("\n")[:-1]
                    for line in lines:
                        if line:
                            md5_hash = hashlib.md5(line.encode("ascii")).hexdigest()
                            md5_frame_data = (md5_hash + "\n").encode("ascii")
                            md5_frame = DCCNETFrame(
                                length=len(md5_frame_data),
                                frame_id=self.current_frame_id,
                                flags=0,
                                data=md5_frame_data,
                            )
                            self.send_data_frame_with_retransmit(md5_frame)

                    message_buffer = message_buffer.split("\n")[-1]
            except Exception as e:
                print("[receiver] Exception:", e)
                import traceback

                traceback.print_exc()
                continue


class DCCNETEmulatorXfer:
    def __init__(
        self,
        ip: None,
        port,
        mode: Literal["server", "client"],
        infile=None,
        outfile=None,
    ):
        self.ip = ip
        self.port = port
        self.mode = mode
        self.infile = infile
        self.outfile = outfile

    def start(self):
        try:
            if self.mode == "server":
                asyncio.run(self.__run_server(self.port, self.infile, self.outfile))
            elif self.mode == "client":
                asyncio.run(
                    self.__run_client(self.ip, self.port, self.infile, self.outfile)
                )
        except Exception as e:
            print(f"[ERROR] {e}")
            sys.exit(1)

    async def __reader_loop(
        self, reader: asyncio.StreamReader, frame_queue: asyncio.Queue
    ):
        buffer = b""
        try:
            while True:
                chunk = await reader.read(4096)
                if not chunk:
                    break
                buffer += chunk
                while True:
                    pos = buffer.find(SYNC_BYTES)
                    if pos < 0 or len(buffer) - pos < HEADER_SIZE:
                        break
                    if buffer[pos + 4 : pos + 8] != SYNC_BYTES:
                        buffer = buffer[pos + 1 :]
                        continue
                    length = struct.unpack("!H", buffer[pos + 10 : pos + 12])[0]
                    total = HEADER_SIZE + length
                    if len(buffer) - pos < total:
                        break
                    raw = buffer[pos : pos + total]
                    buffer = buffer[pos + total :]
                    try:
                        frame = DCCNETFrame.unpack(raw)
                        if frame:
                            await frame_queue.put(frame)
                    except Exception as e:
                        print(f"[WARN] Frame parse error: {e}")
        except Exception as e:
            print(f"[ERROR] Reader loop failed: {e}")

    async def __demux(self, frame_queue, ack_queue, data_queue):
        try:
            while True:
                frame = await frame_queue.get()
                if frame.flags & Flags.FLAG_ACK:
                    await ack_queue.put(frame)
                else:
                    await data_queue.put(frame)
        except asyncio.CancelledError:
            pass

    async def __send_file(
        self, writer: asyncio.StreamWriter, ack_queue: asyncio.Queue, infile: Path
    ):
        frame_id = 0
        try:
            async with aiofiles.open(infile, "rb") as f:
                while True:
                    chunk = await f.read(MAX_PAYLOAD)
                    is_last = not chunk
                    data = chunk if chunk else b""
                    flags = Flags.FLAG_END if is_last else 0

                    frame = DCCNETFrame(
                        length=len(data), frame_id=frame_id, flags=flags, data=data
                    )
                    print(
                        f"[SEND] Frame ID={frame_id}, len={len(data)}, END={bool(flags & Flags.FLAG_END)}"
                    )

                    retry = 0
                    while retry < RETRY_LIMIT:
                        writer.write(frame.pack())
                        await writer.drain()
                        await asyncio.sleep(THROTTLE_DELAY)

                        try:
                            ack = await asyncio.wait_for(
                                ack_queue.get(), timeout=RETRY_INTERVAL * 2
                            )
                            if ack.frame_id == frame_id:
                                print(f"[SEND] ACK received for frame {frame_id}")
                                break
                            else:
                                print(
                                    f"[WARN] Unexpected ACK (got {ack.frame_id}, expected {frame_id})"
                                )
                        except asyncio.TimeoutError:
                            retry += 1
                            print(
                                f"[RETRY] Timeout waiting for ACK (retry {retry}/{RETRY_LIMIT})"
                            )

                    if retry == RETRY_LIMIT:
                        raise Exception(f"Max retries reached for frame {frame_id}")

                    if is_last:
                        print("[SEND] All data sent and END acknowledged")
                        break

                    frame_id ^= 1
        except Exception as e:
            print(f"[ERROR] Sending failed: {e}")
            raise

    async def __recv_file(
        self, writer: asyncio.StreamWriter, data_queue: asyncio.Queue, outfile: Path
    ):
        last_id = None
        last_checksum = None
        try:
            async with aiofiles.open(outfile, "ab") as f:
                while True:
                    frame = await data_queue.get()
                    print(
                        f"[RECV] Frame ID={frame.frame_id}, len={len(frame.data)}, END={bool(frame.flags & Flags.FLAG_END)}"
                    )

                    if frame.frame_id == last_id and frame.checksum == last_checksum:
                        print(f"[RECV] Duplicate frame {frame.frame_id}, resending ACK")
                        ack = DCCNETFrame(
                            length=0, frame_id=frame.frame_id, flags=Flags.FLAG_ACK
                        )
                        writer.write(ack.pack())
                        await writer.drain()
                        await asyncio.sleep(THROTTLE_DELAY)
                        continue

                    await f.write(frame.data)
                    ack = DCCNETFrame(
                        length=0, frame_id=frame.frame_id, flags=Flags.FLAG_ACK
                    )
                    writer.write(ack.pack())
                    await writer.drain()
                    await asyncio.sleep(THROTTLE_DELAY)
                    print(f"[RECV] ACK sent for frame {frame.frame_id}")

                    if frame.flags & Flags.FLAG_END:
                        print(f"[RECV] END frame received and acknowledged")
                        break

                    last_id = frame.frame_id
                    last_checksum = frame.checksum
        except Exception as e:
            print(f"[ERROR] Receiving failed: {e}")
            raise

    async def __handle_connection(self, reader, writer, infile, outfile):
        frame_queue = asyncio.Queue()
        ack_queue = asyncio.Queue()
        data_queue = asyncio.Queue()

        reader_task = asyncio.create_task(self.__reader_loop(reader, frame_queue))
        demux_task = asyncio.create_task(
            self.__demux(frame_queue, ack_queue, data_queue)
        )
        send_task = asyncio.create_task(
            self.__send_file(writer, ack_queue, Path(infile))
        )
        recv_task = asyncio.create_task(
            self.__recv_file(writer, data_queue, Path(outfile))
        )

        try:
            await asyncio.gather(send_task, recv_task)
        except Exception:
            print("[ERROR] File transfer failed")
        finally:
            demux_task.cancel()
            reader_task.cancel()
            writer.close()
            await writer.wait_closed()

    async def __run_server(self, port: int, infile: str, outfile: str):
        async def handler(reader, writer):
            print(f"[INFO] Nova conexão recebida")
            await self.__handle_connection(reader, writer, infile, outfile)

        server = await asyncio.start_server(handler, host="::", port=port)
        print(f"[INFO] Servidor ouvindo na porta {port}...")
        async with server:
            await server.serve_forever()

    async def __run_client(self, ip: str, port: int, infile: str, outfile: str):
        try:
            reader, writer = await asyncio.open_connection(ip, port)
            await self.__handle_connection(reader, writer, infile, outfile)
        except Exception as e:
            print(f"[ERROR] Falha ao conectar-se ao servidor: {e}")
            raise


def main():
    parser = argparse.ArgumentParser(description="DCCNET Emulator CLI")
    group = parser.add_mutually_exclusive_group()

    group.add_argument(
        "-s",
        "--server",
        action="store_true",
        help="Passive server mode (file receiver)",
    )
    group.add_argument(
        "-c", "--client", action="store_true", help="Active client mode (file sender)"
    )

    parser.add_argument("addr", help="Address or port. Format depends on mode.")
    parser.add_argument("arg1", help="GAS (md5 mode) or input file (xfer mode)")
    parser.add_argument("arg2", nargs="?", help="output file (only in xfer mode)")

    args = parser.parse_args()

    if args.server:
        port = int(args.addr)
        emulator = DCCNETEmulatorXfer(
            ip=None, port=port, mode="server", infile=args.arg1, outfile=args.arg2
        )
    elif args.client:
        ip, port = Utils.parse_address(args.addr)
        emulator = DCCNETEmulatorXfer(
            ip=ip, port=port, mode="client", infile=args.arg1, outfile=args.arg2
        )
    else:
        ip, port = Utils.parse_address(args.addr)
        emulator = DCCNETEmulatorMd5(ip=ip, port=port, gas=args.arg1)

    emulator.start()


if __name__ == "__main__":
    main()
