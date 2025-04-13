import struct

# App Constants
SYNC = 0xDCC023C2
SYNC_BYTES = struct.pack("!I", SYNC)
MAX_PAYLOAD = 4096
RETRY_LIMIT = 16
RETRY_INTERVAL = 1

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
        self.checksum = compute_checksum(
            header_with_zeroed_checksum + bytes(self.data, encoding="ascii")
        )
        header = struct.pack(
            "!IIHHHB",
            self.sync,
            self.sync,
            self.checksum,
            self.length,
            self.frame_id,
            self.flags,
        )
        return header + bytes(self.data, encoding="ascii")

    @classmethod
    def unpack(cls, frame_bytes):
        print(len(b"\xdc\xc0#\xc2\xdc\xc0#\xc2\xe5\x0c\x00\x04\x00\x01@test"))
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
