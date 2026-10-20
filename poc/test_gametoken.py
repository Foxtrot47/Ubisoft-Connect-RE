"""Offline tests with synthetic tokens; no credentials or network access."""
import unittest
from unittest.mock import patch

import ubisoft_gui as protocol


class OwnershipTokenTests(unittest.TestCase):
    def exchange(self, ticket=b"", session_id=b""):
        # Valid synthetic InitializeRsp and OwnershipTokenRsp.
        initialize = bytes.fromhex("080012020801")
        ownership = bytes.fromhex("0801da01110801120d73796e7468657469632d6f776e")
        with patch.object(protocol, "demux_open_connection", return_value=2), \
             patch.object(protocol, "_demux_await_response", side_effect=[initialize, ownership]), \
             patch.object(protocol, "demux_push") as push:
            result = protocol.demux_ownership_token(object(), 2688, 1, ticket, session_id)
        self.assertEqual(result, "synthetic-own")
        return push.call_args_list

    def test_initialize_uses_varints_like_official_capture(self):
        calls = self.exchange()
        self.assertEqual(calls[0].args[3], bytes.fromhex("1206100118072800"))

    def test_product_id_uses_varint_like_official_capture(self):
        calls = self.exchange()
        self.assertEqual(calls[1].args[3], bytes.fromhex("e20103088015"))

    def test_ticket_and_session_fields_are_preserved(self):
        calls = self.exchange(b"synthetic-ticket", b"synthetic-session")
        self.assertEqual(calls[1].args[3], bytes.fromhex("e20103088015")
                         + protocol._ld(30, b"synthetic-ticket")
                         + protocol._ld(31, b"synthetic-session"))


class SessionProductsTests(unittest.TestCase):
    def test_session_products_filter_ownership_types_states_and_preserve_order(self):
        def game(pid, owned=1, product_type=0, state=3):
            raw = protocol._field(1, 0, protocol._varint(pid))
            for field, value in ((20, owned), (8, product_type), (13, state)):
                raw += protocol._field(field, 0, protocol._varint(value))
            return protocol._ld(1, raw)
        catalog = (game(2688) + game(999, owned=0) + game(10, product_type=5)
                   + game(11, product_type=11) + game(12, state=4)
                   + game(13, state=1) + game(14, product_type=1) + game(15, state=0))
        response = protocol._ld(2, protocol._field(1, 0, protocol._varint(1)) + protocol._ld(2, catalog))
        self.assertEqual(protocol.ownership_session_products(response), [2688, 14, 15])


class PCTicketTests(unittest.TestCase):
    def test_pc_ticket_request_matches_capture_shape(self):
        initialize = bytes.fromhex("080012020801")
        response = protocol._field(1, 0, protocol._varint(1)) + protocol._ld(13,
            protocol._field(1, 0, protocol._varint(1)) + protocol._ld(2, b"synthetic-pc-ticket"))
        with patch.object(protocol, "demux_open_connection", return_value=2), \
             patch.object(protocol, "_demux_await_response", side_effect=[initialize, response]), \
             patch.object(protocol, "demux_push") as push:
            self.assertEqual(protocol.demux_pc_ticket(object(), 2688, 1, b"ticket", b"session"), b"synthetic-pc-ticket")
        self.assertEqual(push.call_args.args[3], bytes.fromhex("72080880151000188015")
                         + protocol._ld(30, b"ticket") + protocol._ld(31, b"session"))

    def test_rejected_ticket_raises(self):
        initialize = bytes.fromhex("080012020801")
        response = bytes.fromhex("08016a0408001802")
        with patch.object(protocol, "demux_open_connection", return_value=2), \
             patch.object(protocol, "_demux_await_response", side_effect=[initialize, response]), \
             patch.object(protocol, "demux_push"), \
             self.assertRaisesRegex(RuntimeError, "code=2"):
            protocol.demux_pc_ticket(object(), 2688, 1, b"ticket", b"session")


class GameTokenTests(unittest.TestCase):
    def exchange(self, result):
        request_token = b"c3ludGhldGljLXJlcXVlc3Q="
        reply = bytes.fromhex("0801")
        if result is not None:
            reply += protocol._field(2, 0, protocol._varint(result))
        reply += protocol._ld(3, protocol._ld(1, b"synthetic-answer"))
        with patch.object(protocol, "demux_open_connection", return_value=3), \
             patch.object(protocol, "_demux_await_response", return_value=reply), \
             patch.object(protocol, "demux_push") as push:
            token = protocol.demux_game_token(object(), "synthetic-own", request_token, 3)
        self.assertEqual(push.call_args.args[2], 1)
        self.assertEqual(token, b"synthetic-answer")
        return push.call_args.args[3], request_token

    def test_proto3_omitted_result_means_success(self):
        self.exchange(None)

    def test_explicit_zero_result_means_success(self):
        self.exchange(0)

    def test_request_token_is_forwarded_without_base64_decoding(self):
        message, request_token = self.exchange(0)
        body = dict(protocol._fields(message))[2]
        self.assertEqual(dict(protocol._fields(body))[2], request_token)

    def test_explicit_server_errors_are_not_accepted(self):
        for result in range(1, 6):
            with self.subTest(result=result), self.assertRaisesRegex(RuntimeError, f"result={result}"):
                self.exchange(result)

    def test_success_without_token_is_rejected(self):
        with patch.object(protocol, "demux_open_connection", return_value=3), \
             patch.object(protocol, "_demux_await_response", return_value=bytes.fromhex("0800")), \
             patch.object(protocol, "demux_push"), \
             self.assertRaisesRegex(RuntimeError, "no gameToken"):
            protocol.demux_game_token(object(), "synthetic-own", b"request", 3)


if __name__ == "__main__":
    unittest.main()
