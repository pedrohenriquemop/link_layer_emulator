import struct
import socket
import hashlib
import os
from dotenv import load_dotenv

# App Constants
SYNC = 0xDCC023C2
SYNC_BYTES = struct.pack("!I", SYNC)
MAX_PAYLOAD = 4096
RETRY_LIMIT = 4
RETRY_INTERVAL = 1

CONNECTION_MAX_RETRIES = 3

# Flags
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
        if len(frame_bytes) < 15:
            raise ValueError("Frame too short to unpack")
        sync1, sync2, checksum, length, frame_id, flags = struct.unpack(
            "!IIHHHB", frame_bytes[:15]
        )
        if sync1 != SYNC or sync2 != SYNC:
            raise ValueError("SYNC mismatch while unpacking frame")
        data = frame_bytes[15 : 15 + length]
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


class DCCNETEmulator:
    def __init__(self, ip, port, gas=None, mode="md5", infile=None, outfile=None):
        self.ip = ip
        self.port = port
        self.gas = gas
        self.mode = mode  # 'md5' or 'xfer'
        self.infile = infile
        self.outfile = outfile

        addrinfo = socket.getaddrinfo(ip, None)
        family = addrinfo[0][0]
        self.sock = socket.socket(family, socket.SOCK_STREAM)
        self.sock.settimeout(RETRY_INTERVAL)

        self.last_sent_id = 0
        self.last_recv_id = None
        self.stop_flag = False

    def start(self):
        # TODO: retry connection
        self.sock.connect((self.ip, self.port))

        formatted_gas = self.gas + "\n"
        gas_frame = DCCNETFrame(
            length=len(formatted_gas),
            frame_id=self.last_sent_id,
            flags=0,
            data=formatted_gas,
        )

        self.send_frame_with_retransmit(gas_frame)

        if self.mode == "md5":
            self.receiver()

        self.sock.close()

    def toggle_frame_id(self):
        self.last_sent_id = 1 - self.last_sent_id

    def send_frame_with_retransmit(self, frame) -> DCCNETFrame:
        packed = frame.pack()
        ack_received = False
        response_frame: DCCNETFrame

        for attempt in range(RETRY_LIMIT):
            try:
                self.sock.sendall(packed)
                response = self.sock.recv(MAX_PAYLOAD)
                response_frame = self.get_frame_from_response(response)
                if response_frame is None:
                    print("No response received")
                    continue
                if response_frame.flags & FLAG_ACK:
                    print("ACK received for frame ID:", frame.frame_id)
                    ack_received = True
                    self.toggle_frame_id()
                    break
                elif response_frame.flags & FLAG_RST:
                    print("Reset frame received. Shutting down connection.")
                    self.stop_flag = True
                    break
                elif response_frame.flags & FLAG_END:
                    print("End frame received.")
                    self.toggle_frame_id()
                    ack_received = True
                    break
            except socket.timeout:
                print(f"Timed out. Attempt {attempt + 1} of {RETRY_LIMIT}")
            except socket.error as e:
                print(f"Socket error: {e}")

        if not self.stop_flag and not ack_received:
            self.stop_flag = True
            raise ValueError("Transmission failed after maximum retries.")

        return response_frame

    def get_frame_from_response(self, response: bytes) -> DCCNETFrame:
        if not response:
            raise ValueError("Empty response received")

        pos = response.find(SYNC_BYTES)
        if pos == -1 or len(response) - pos < 15:
            raise ValueError("Invalid response received: no SYNC pattern found")
        if response[pos + 4 : pos + 8] != SYNC_BYTES:
            raise ValueError("Invalid response received: no SYNC pattern found")

        return DCCNETFrame.unpack(response[pos:])

    def receiver(self):
        buffer = b""
        while not self.stop_flag:
            try:
                data = self.sock.recv(MAX_PAYLOAD)
                if not data:
                    break
                buffer += data
                # Attempt to parse frames from the buffer by searching for two SYNC patterns.
                while True:
                    # Look for the first occurrence of SYNC pattern
                    pos = buffer.find(SYNC_BYTES)
                    if pos == -1 or len(buffer) - pos < 15:
                        break  # not enough data for a frame header
                    # Check if next 4 bytes are SYNC again
                    if buffer[pos + 4 : pos + 8] != SYNC_BYTES:
                        # Not valid; drop one byte and continue searching
                        buffer = buffer[pos + 1 :]
                        continue
                    # Assume header is at pos
                    # For simplicity, we assume the frame is fully in the buffer.
                    # In practice, you may need to check if the complete frame is present.
                    potential_frame = buffer[pos:]
                    # Try unpacking frame (assuming header is 15 bytes minimum)
                    frame = DCCNETFrame.unpack(potential_frame)
                    if frame is None:
                        # Incomplete or corrupted frame; try to re-sync
                        buffer = buffer[pos + 8 :]
                        continue
                    # Process the frame based on its type
                    if frame.flags & FLAG_ACK:
                        # ACK received for the last sent frame.
                        # (In a complete implementation, notify the transmitter thread.)
                        print("ACK received for frame ID:", frame.frame_id)
                    elif frame.flags & FLAG_RST:
                        print("Reset frame received. Shutting down connection.")
                        self.stop_flag = True
                        break
                    else:
                        # Data frame received.
                        if self.mode == "md5":
                            # In MD5 mode, accumulate data until a newline is found.
                            text = frame.data.decode("ascii", errors="ignore")
                            lines = text.split("\n")
                            for line in lines:
                                if line:
                                    md5_hash = hashlib.md5(
                                        line.encode("ascii")
                                    ).hexdigest()
                                    md5_frame_data = md5_hash + "\n"
                                    md5_frame = DCCNETFrame(
                                        length=len(md5_frame_data),
                                        frame_id=self.last_sent_id,
                                        flags=0,
                                        data=md5_frame_data,
                                    )
                                    self.send_frame_with_retransmit(md5_frame)
                                    print("MD5 for line:", md5_hash)
                            # If END flag is set, finish the connection.
                            if frame.flags & FLAG_END:
                                self.stop_flag = True
                        # elif self.mode == "xfer":
                        #     TODO: write the data to the output file
                    # Remove the processed frame from the buffer.
                    # (For demonstration, we simply clear the buffer; a production system would handle partial frames.)
                    buffer = b""
            except ValueError:
                break

    def transmitter(self):
        if self.mode == "md5":
            # In MD5 mode, no data is sent from our side except the authentication and MD5 responses.
            return
        elif self.mode == "xfer":
            # For file transfer, read file and send in frames
            with open(self.infile, "rb") as f:
                while True:
                    chunk = f.read(MAX_PAYLOAD)
                    if not chunk:
                        # Send an empty frame with END flag set to signal end-of-transmission
                        frame = DCCNETFrame(
                            length=0, frame_id=self.last_sent_id, flags=FLAG_END
                        )
                        self.send_frame_with_retransmit(frame)
                        break
                    # Build and send frame
                    frame = DCCNETFrame(
                        length=len(chunk),
                        frame_id=self.last_sent_id,
                        flags=0,
                        data=chunk,
                    )
                    self.send_frame_with_retransmit(frame)
                    # Toggle frame id for next frame
                    self.last_sent_id = 1 - self.last_sent_id


if __name__ == "__main__":
    load_dotenv(".env")

    emulator = DCCNETEmulator(
        os.getenv("SERVER_ADDRESS_NAME"),
        int(os.getenv("PORT")),
        gas=os.getenv("GAS"),
        mode="md5",
    )

    emulator.start()
