import base64
import unittest
from unittest.mock import Mock, patch

import cloudsave as c
import ubisoft_gui as g

PROFILE = '00000000-0000-0000-0000-000000000001'


def response(status=1, slot='1', host='ubisoft-uplay-savegames.s3.us-east-1.amazonaws.com'):
    url = f'https://{host}/{PROFILE}/2688/{slot}.savegame?synthetic=yes'
    return g._ld(2, g._field(1, 0, g._varint(status)) + g._ld(2, g._ld(2, url.encode())))


class CloudsaveTests(unittest.TestCase):
    def test_get_request_contains_ownership_token_and_method(self):
        payload = c.cloudsave_url_request(2688, 2, [('1', None, None)], 'synthetic-owner')
        body = dict(g._fields(dict(g._fields(payload))[2]))
        self.assertEqual(body[1], b'synthetic-owner')
        self.assertEqual(body[2], 2688)
        self.assertEqual(body[3], 2)
        self.assertEqual(dict(g._fields(body[4]))[1], b'1')

    def test_put_contains_compressed_size_and_md5(self):
        md5 = base64.b64encode(bytes(16)).decode()
        payload = c.cloudsave_url_request(2688, 1, [('1', 123, md5)], 'synthetic-owner')
        body = dict(g._fields(dict(g._fields(payload))[2]))
        optional = dict(g._fields(dict(g._fields(body[4]))[2]))
        self.assertEqual(optional, {1: 123, 2: md5.encode()})

    def test_invalid_slot_and_missing_token_are_rejected(self):
        for slots, token in [([('../1', None, None)], 'owner'),
                             ([('1', None, None)], ''),
                             ([('1', None, None), ('1', None, None)], 'owner')]:
            with self.assertRaises(ValueError):
                c.cloudsave_url_request(2688, 2, slots, token)

    def test_default_url_status_is_not_success(self):
        with self.assertRaises(RuntimeError):
            c.parse_cloudsave_urls(b'', PROFILE, 2688, ['1'])

    def test_wrong_host_or_slot_is_rejected_without_url_in_error(self):
        for raw in [response(host='example.com'), response(slot='2')]:
            with self.assertRaisesRegex(RuntimeError, '^Unexpected cloud object destination$'):
                c.parse_cloudsave_urls(raw, PROFILE, 2688, ['1'])

    def test_expected_url_is_accepted(self):
        self.assertEqual(set(c.parse_cloudsave_urls(response(), PROFILE, 2688, ['1'])), {'1'})

    def test_dynamic_connection_and_request_ids_and_close(self):
        sock = Mock()
        with patch.object(g, 'demux_open_janus', return_value=(sock, 7)), \
             patch.object(g, 'demux_ownership_token', return_value='synthetic-owner'), \
             patch.object(g, 'demux_open_connection', return_value=42) as connect, \
             patch.object(g, 'demux_push') as push, \
             patch.object(g, '_demux_await_response', return_value=response()):
            with c.CloudSaveClient(b'ticket', b'sid', PROFILE, 2688) as client:
                client.urls(2, [('1', None, None)])
                client.urls(3, [('1', None, None)])
        connect.assert_called_once_with(sock, c.CLOUDSAVE_SERVICE, 8)
        self.assertEqual([call.args[1:3] for call in push.call_args_list], [(42, 1), (42, 2)])
        sock.close.assert_called_once()

    def test_setup_failure_closes_socket(self):
        sock = Mock()
        with patch.object(g, 'demux_open_janus', return_value=(sock, 1)), \
             patch.object(g, 'demux_ownership_token', side_effect=RuntimeError('synthetic failure')):
            with self.assertRaises(RuntimeError):
                with c.CloudSaveClient(b'ticket', b'sid', PROFILE, 2688):
                    self.fail('must not enter')
        sock.close.assert_called_once()


if __name__ == '__main__':
    unittest.main()
