import unittest
from tp1 import DCCNETFrame, compute_checksum, SYNC_BYTES, SYNC, FLAG_END


class TestDCCNET(unittest.TestCase):
    def test_checksum_known(self):
        # Test checksum of a known byte pattern
        data = b"hello"
        header = (
            SYNC_BYTES + SYNC_BYTES + b"\x00\x00" + b"\x00\x05" + b"\x00\x01" + b"\x00"
        )
        frame_bytes = header + data
        chksum = compute_checksum(frame_bytes)
        self.assertIsInstance(chksum, int)
        self.assertGreaterEqual(chksum, 0)
        self.assertLessEqual(chksum, 0xFFFF)

    def test_pack_and_unpack(self):
        # Frame with ID = 1, flags = 0x40 (END), data = "test"
        frame = DCCNETFrame(length=4, frame_id=1, flags=0x40, data="test")
        packed = frame.pack()
        unpacked = DCCNETFrame.unpack(packed)

        self.assertIsNotNone(unpacked)
        self.assertEqual(unpacked.length, 4)
        self.assertEqual(unpacked.frame_id, 1)
        self.assertEqual(unpacked.flags, 0x40)
        self.assertEqual(unpacked.data, b"test")

    def test_unpack_invalid_checksum(self):
        # Pack a frame, corrupt it, and ensure unpack fails
        frame = DCCNETFrame(length=3, frame_id=0, flags=0x00, data="abc")
        packed = bytearray(frame.pack())
        packed[10] ^= 0xFF  # corrupt part of the checksum
        self.assertRaises(ValueError, DCCNETFrame.unpack, bytes(packed))

    def test_unpack_invalid_sync(self):
        # Invalid SYNC values
        frame = DCCNETFrame(length=3, frame_id=0, flags=0x00, data="abc")
        packed = bytearray(frame.pack())
        packed[0:4] = b"\x00\x00\x00\x00"
        self.assertRaises(ValueError, DCCNETFrame.unpack, bytes(packed))

    def test_empty_payload_with_end_flag(self):
        # Test a frame that has length 0 and END flag set
        frame = DCCNETFrame(length=0, frame_id=0, flags=FLAG_END, data="")
        packed = frame.pack()
        unpacked = DCCNETFrame.unpack(packed)

        self.assertIsNotNone(unpacked)
        self.assertEqual(unpacked.length, 0)
        self.assertEqual(unpacked.flags, 0x40)
        self.assertEqual(unpacked.data, b"")

    def test_binary_data_payload_with_non_ascii_bytes(self):
        # Non-ASCII bytes
        payload = bytes([0x00, 0xFF, 0x10, 0x20])
        frame = DCCNETFrame(
            length=len(payload), frame_id=0, flags=0x00, data=payload.decode("latin1")
        )
        self.assertRaises(UnicodeEncodeError, frame.pack)


if __name__ == "__main__":
    unittest.main()
