"""Synthetic aux tests: no games, credentials, registry writes or network."""
import os
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import fake_launcher as launcher


class FreshActivationTests(unittest.TestCase):
    def setUp(self):
        self.client = SimpleNamespace(ticket="synthetic-ticket", session_id="synthetic-session", user_id="synthetic-user",
                                      game_app_id="00000000-0000-0000-0000-000000000001")
        self.patches = [
            patch.object(launcher, "default_session_push", side_effect=AssertionError("session replay reached")),
            patch.object(launcher, "denuvo_token", side_effect=AssertionError("captured PC ticket reached")),
            patch.object(launcher, "captured_uplay_followups", side_effect=AssertionError("follow-up replay reached")),
            patch.object(launcher, "captured_game_token", side_effect=AssertionError("disk-token fallback reached")),
            patch.object(launcher.Path, "write_bytes", side_effect=AssertionError("challenge exported")),
            patch.dict(os.environ, {}, clear=True),
        ]
        for item in self.patches:
            item.start()
        self.addCleanup(lambda: [item.stop() for item in reversed(self.patches)])
        self.server = launcher.FakeLauncher(self.client, 2688, log=Mock(), fresh_activation=True)
        self.activate = launcher.ld(2, launcher.ld(2, b"synthetic-challenge"))

    def test_aux_relays_current_challenge_to_server_and_closes_socket(self):
        socket = Mock()
        with patch.object(launcher, "demux_open_janus", return_value=(socket, 1)), \
             patch.object(launcher, "demux_ownership_token", return_value="synthetic-own") as own, \
             patch.object(launcher, "demux_game_token", return_value=b"synthetic-answer") as game:
            self.assertEqual(self.server._activate(self.activate), b"synthetic-answer")
        own.assert_called_once_with(socket, 2688, 1, b"synthetic-ticket", b"synthetic-session")
        game.assert_called_once_with(socket, "synthetic-own", b"synthetic-challenge", 11)
        socket.close.assert_called_once()

    def test_identical_ipc_retry_does_not_issue_twice(self):
        with patch.object(launcher, "demux_open_janus", return_value=(Mock(), 1)), \
             patch.object(launcher, "demux_ownership_token", return_value="own"), \
             patch.object(launcher, "demux_game_token", return_value=b"answer") as game:
            self.assertEqual(self.server._activate(self.activate), b"answer")
            self.assertEqual(self.server._activate(self.activate), b"answer")
        game.assert_called_once()

    def test_new_challenge_does_not_reuse_prior_answer(self):
        with patch.object(launcher, "demux_open_janus", return_value=(Mock(), 1)), \
             patch.object(launcher, "demux_ownership_token", return_value="own"), \
             patch.object(launcher, "demux_game_token", side_effect=[b"answer1", b"answer2"]) as game:
            self.assertEqual(self.server._activate(self.activate), b"answer1")
            self.assertEqual(self.server._activate(launcher.ld(2, launcher.ld(2, b"new-challenge"))), b"answer2")
        self.assertEqual(game.call_count, 2)

    def test_rejection_never_falls_back_to_old_token(self):
        socket = Mock()
        with patch.object(launcher, "demux_open_janus", return_value=(socket, 1)), \
             patch.object(launcher, "demux_ownership_token", side_effect=RuntimeError("not owned")) as own:
            self.assertIsNone(self.server._activate(self.activate))
        own.assert_called_once()
        socket.close.assert_called_once()

    def test_transport_retry_is_bounded_and_delayed(self):
        self.server._stop = Mock()
        self.server._stop.wait.return_value = False
        with patch.object(launcher, "demux_open_janus", side_effect=TimeoutError) as connect:
            self.assertIsNone(self.server._activate(self.activate))
        self.assertEqual(connect.call_count, 2)
        self.server._stop.wait.assert_called_once_with(3)

    def test_live_pc_ticket_setup_and_cleanup(self):
        socket = Mock()
        with patch.object(launcher, "demux_open_janus", return_value=(socket, 1)), \
             patch.object(launcher, "demux_pc_session", return_value=(b"synthetic-live-pc-ticket", [2688])):
            self.server._prepare_fresh_session()
        self.assertTrue(self.server.demux_ready.is_set())
        self.assertEqual(self.server._ticket_field(), b"synthetic-live-pc-ticket")
        socket.close.assert_called_once()

    def test_missing_live_pc_ticket_has_no_capture_fallback(self):
        with self.assertRaisesRegex(RuntimeError, "not ready"):
            self.server._ticket_field()

    def test_generated_session_uses_live_ticket_without_password(self):
        self.client.me = Mock(return_value={"userId": "synthetic-user", "username": "synthetic-name"})
        self.client.library = Mock(return_value=[])
        self.server.fresh_token = b"synthetic-live-pc-ticket"
        self.server._session_owned_ids = [2688]
        with patch.dict(os.environ, {"UPLAY_PASSWORD": "must-not-be-forwarded"}), \
             patch.object(self.server, "_savegames_dir", return_value="C:/synthetic-saves/"):
            message = self.server._session_message()
        inner = dict(launcher.parse_fields(dict(launcher.parse_fields(message))[1]))
        self.assertEqual(inner[8], b"synthetic-live-pc-ticket")
        profile = dict(launcher.parse_fields(inner[2]))
        self.assertEqual(profile[1], b"synthetic-user")
        self.assertEqual(profile[5], b"")
        self.assertNotIn(b"must-not-be-forwarded", message)

    def test_fresh_mode_never_replays_followups(self):
        self.server._push_followups(Mock())

    def test_explicit_session_compatibility_still_replaces_old_ticket(self):
        template = launcher.frame(launcher.ld(1, launcher.vint(1, 1)
            + launcher.ld(8, b"synthetic-old-ticket")
            + launcher.ld(17, launcher.ld(1, b"old-save-path/"))
            + launcher.ld(22, launcher.ld(1, b"old-session-id"))))
        server = launcher.FakeLauncher(self.client, 2688, log=Mock(), fresh_activation=True,
                                       session_template=template)
        server.fresh_token = b"synthetic-live-ticket"
        with patch.object(server, "_savegames_dir", return_value="new-save-path/"):
            body = server._session_message()
        inner = dict(launcher.parse_fields(dict(launcher.parse_fields(body))[1]))
        self.assertEqual(inner[8], b"synthetic-live-ticket")
        self.assertNotIn(b"synthetic-old-ticket", body)
        self.assertNotIn(b"old-save-path/", body)
        # This field is an application ID, not a per-launch session UUID.
        self.assertEqual(dict(launcher.parse_fields(inner[22]))[1], b"old-session-id")

    def test_compatibility_stream_does_not_reframe_split_chunks(self):
        self.server.session_followups = [b"first-fragment", b"second-fragment"]
        handle = Mock()
        with patch.object(launcher.win32file, "WriteFile") as write, patch.object(launcher.time, "sleep"):
            self.server._push_followups(handle)
        self.assertEqual([c.args for c in write.call_args_list],
                         [(handle, b"first-fragment"), (handle, b"second-fragment")])

    def test_real_game_pid_is_taken_from_game_ipc(self):
        request = launcher.frame(launcher.ld(2, launcher.vint(1, 2688) + launcher.vint(2, 12345)))
        with patch.object(self.server, "_read", return_value=request), \
             patch.object(self.server, "_write"), patch.object(self.server, "_signal_launch"), \
             patch.object(self.server, "_hold_open"), patch.object(self.server, "_watch_active_game") as watch:
            self.server._handle_api_process(Mock())
        watch.assert_called_once_with(12345)
        self.assertEqual(self.server.active_game_pid, 12345)
        self.assertIsNone(self.server.child_pid)

    def test_child_exit_code_is_retained_and_handle_closed(self):
        handle = Mock()
        with patch.object(launcher.win32event, "WaitForSingleObject", return_value=launcher.win32event.WAIT_OBJECT_0), \
             patch.object(launcher.win32process, "GetExitCodeProcess", return_value=0xC0000005), \
             patch.object(launcher.win32api, "CloseHandle") as close:
            self.server._watch_child(handle)
        self.assertEqual(self.server.child_exit_code, 0xC0000005)
        close.assert_called_once_with(handle)

    def test_signed_windows_exit_code_is_normalized(self):
        self.server.active_game_pid = 12345
        with patch.object(launcher.win32event, "WaitForSingleObject", return_value=launcher.win32event.WAIT_OBJECT_0), \
             patch.object(launcher.win32process, "GetExitCodeProcess", return_value=-1073741819), \
             patch.object(launcher.win32api, "CloseHandle"):
            self.server._watch_child(Mock(), 12345)
        self.assertEqual(self.server.active_game_exit_code, 0xC0000005)

    def test_application_id_comes_from_metadata_not_a_random_uuid(self):
        self.assertEqual(self.server._game_application_id(), self.client.game_app_id)
        del self.client.game_app_id
        self.client.library = lambda: [{'productId': 2688, 'applicationId': '00000000-0000-0000-0000-000000000002'}]
        self.assertEqual(self.server._game_application_id(), '00000000-0000-0000-0000-000000000002')
        self.client.library = lambda: []
        with self.assertRaises(RuntimeError):
            self.server._game_application_id()

    def test_installer_request_gets_installer_response_not_a_session(self):
        request = launcher.frame(launcher.ld(13, launcher.ld(1, b'')))
        with patch.object(self.server, '_read', side_effect=[request, b'']), \
             patch.object(self.server, '_write') as write, \
             patch.object(self.server, '_session_message', side_effect=AssertionError('wrong response type')):
            self.server._handle_uplay(Mock())
        reply = dict(launcher.parse_fields(write.call_args.args[1]))
        self.assertEqual(set(reply), {10})
        installer = dict(launcher.parse_fields(dict(launcher.parse_fields(reply[10]))[1]))
        self.assertEqual(installer[1], 1)
        self.assertEqual(installer[3], b'en-US')

    def test_real_game_exit_is_separate_from_startup_exit(self):
        handle = Mock()
        self.server.active_game_pid = 12345
        with patch.object(launcher.win32event, "WaitForSingleObject", return_value=launcher.win32event.WAIT_OBJECT_0), \
             patch.object(launcher.win32process, "GetExitCodeProcess", return_value=0xC0000005), \
             patch.object(launcher.win32api, "CloseHandle") as close:
            self.server._watch_child(handle, 12345)
        self.assertEqual(self.server.active_game_exit_code, 0xC0000005)
        self.assertEqual(self.server.game_exit_codes, {12345: 0xC0000005})
        self.assertIsNone(self.server.child_exit_code)
        close.assert_called_once_with(handle)

    def test_old_real_process_exit_does_not_mark_new_process_exited(self):
        self.server.active_game_pid = 54321
        with patch.object(launcher.win32event, "WaitForSingleObject", return_value=launcher.win32event.WAIT_OBJECT_0), \
             patch.object(launcher.win32process, "GetExitCodeProcess", return_value=0), \
             patch.object(launcher.win32api, "CloseHandle"):
            self.server._watch_child(Mock(), 12345)
        self.assertIsNone(self.server.active_game_exit_code)
        self.assertEqual(self.server.game_exit_codes[12345], 0)

    def test_independent_mode_rejects_every_replay_input(self):
        for options in ({'fresh_activation': False}, {'replay': 'synthetic.bin'},
                        {'session_template': b'synthetic'}, {'session_followups': []}):
            kwargs = {'fresh_activation': True, 'independent_session': True, **options}
            with self.assertRaises(ValueError):
                launcher.FakeLauncher(self.client, 2688, **kwargs)

    def test_independent_mode_rejects_replay_mutation(self):
        server = launcher.FakeLauncher(self.client, 2688, fresh_activation=True, independent_session=True)
        server.replay = b'synthetic'
        with self.assertRaises(RuntimeError):
            server._session_message()
        server.session_followups = []
        with self.assertRaises(RuntimeError):
            server._push_followups(Mock())

    def test_independent_mode_uses_explicit_install_root(self):
        server = launcher.FakeLauncher(self.client, 2688, fresh_activation=True, independent_session=True,
                                      launch_spec_override=('explicit.exe', [], 'explicit-root'))
        self.assertEqual(server._install_dir('ignored.exe', 'ignored-cwd'), 'explicit-root')

    def test_independent_mode_requires_explicit_launch_path(self):
        server = launcher.FakeLauncher(self.client, 2688, fresh_activation=True, independent_session=True)
        with self.assertRaises(RuntimeError):
            server.launch()

    def test_replay_override_is_rejected(self):
        with patch.dict(os.environ, {"UPLAY_AUX_REPLAY": "1"}), self.assertRaisesRegex(ValueError, "cannot be combined"):
            launcher.FakeLauncher(self.client, 2688, fresh_activation=True)


if __name__ == "__main__":
    unittest.main()
