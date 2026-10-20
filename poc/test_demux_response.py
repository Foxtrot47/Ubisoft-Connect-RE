"""Offline framing tests for proto3 service response defaults."""
import unittest

import ubisoft_gui as protocol


class SocketBuffer:
    def __init__(self, data):
        self.data = data

    def recv(self, n):
        chunk, self.data = self.data[:n], self.data[n:]
        return chunk


class ResponseTests(unittest.TestCase):
    def test_proto3_omitted_zero_request_id_matches(self):
        response = protocol._ld(3, protocol._ld(1, b"synthetic-answer"))
        service = protocol._frame(protocol._ld(1, response))
        packet = protocol._frame(protocol._ld(2, protocol._ld(1,
            protocol._field(1, 0, protocol._varint(3)) + protocol._ld(2, service))))
        self.assertEqual(protocol._demux_await_response(SocketBuffer(packet), 0, 3, timeout=0.01), response)

    def test_explicit_request_id_matches(self):
        response = protocol._field(1, 0, protocol._varint(1)) + protocol._ld(3, protocol._ld(1, b"answer"))
        service = protocol._frame(protocol._ld(1, response))
        packet = protocol._frame(protocol._ld(2, protocol._ld(1,
            protocol._field(1, 0, protocol._varint(3)) + protocol._ld(2, service))))
        self.assertEqual(protocol._demux_await_response(SocketBuffer(packet), 1, 3, timeout=0.01), response)


if __name__ == "__main__":
    unittest.main()
