"""Offline collector regression tests. Never attaches to Ubisoft processes."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

import activation_capture as capture


class CollectorTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.collector = capture.Collector(Path(self.directory.name))

    def tearDown(self):
        self.collector.close()
        self.directory.cleanup()

    def test_payload_persisted_before_ack(self):
        script = Mock()
        def ack(message):
            self.assertEqual((Path(self.directory.name) / "payloads.bin").read_bytes(), b"test")
            self.assertEqual(message["payload"]["sequence"], 1)
        script.post.side_effect = ack
        self.collector.message(1, script, {"type": "send", "payload": {"kind": "test", "sequence": 1}}, b"test")
        script.post.assert_called_once()

    def test_capture_budget_stops_without_ack(self):
        script = Mock()
        with patch.object(capture, "MAX_CAPTURE_BYTES", 3):
            self.collector.message(1, script, {"type": "send", "payload": {"kind": "test", "sequence": 1}}, b"test")
        self.assertTrue(self.collector.stopped.is_set())
        self.assertEqual(self.collector.blobs.tell(), 0)
        script.post.assert_not_called()

    def test_detach_releases_session_references(self):
        self.collector.sessions[1] = (Mock(), Mock(), "test")
        self.collector.target_baselines[1] = 123
        self.collector.health[1] = {}
        self.collector.detached(1, "process-terminated")
        self.assertEqual(self.collector.sessions, {})
        self.assertEqual(self.collector.target_baselines, {})
        self.assertEqual(self.collector.health, {})

    def test_drop_counts_are_not_silently_ignored_or_double_counted(self):
        script = Mock()
        event = {"type": "send", "payload": {"kind": "health", "sequence": 1,
                 "counts": {"dropped_events": 5, "send_errors": 1}}}
        self.collector.message(1, script, event, None)
        self.collector.message(1, script, event, None)
        self.assertEqual(self.collector.errors, 6)

    def test_singleton_blocks_another_process(self):
        with capture.SingleCollector():
            code = "from activation_capture import SingleCollector\nwith SingleCollector():\n print('unexpected acquisition')"
            result = subprocess.run([sys.executable, "-c", code], cwd=Path(__file__).parent,
                                    capture_output=True, text=True, timeout=10)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("refusing duplicate", result.stderr)
        # Closing the last handle releases the guard; no stale lock file remains.
        with capture.SingleCollector():
            pass

    def test_memory_watchdog_detaches_capture(self):
        session = Mock()
        session.is_detached = False
        self.collector.sessions[1] = (session, Mock(), "fixture")
        with patch.object(capture, "private_bytes", return_value=capture.MAX_COLLECTOR_BYTES + 1):
            self.collector.watchdog()
        self.assertTrue(self.collector.stopped.is_set())
        self.assertEqual(self.collector.failure, "collector-memory-limit")
        session.detach.assert_called_once()
        self.collector.sessions.clear()

    def test_target_growth_watchdog_detaches_capture(self):
        session = Mock()
        session.is_detached = False
        self.collector.sessions[1] = (session, Mock(), "fixture")
        self.collector.target_baselines[1] = 100
        def memory(pid):
            return 1024 if pid == capture.os.getpid() else 101 + capture.MAX_TARGET_GROWTH
        with patch.object(capture, "private_bytes", side_effect=memory):
            self.collector.watchdog()
        self.assertTrue(self.collector.stopped.is_set())
        self.assertEqual(self.collector.failure, "target-memory-growth-limit: 1")
        session.detach.assert_called_once()
        self.collector.sessions.clear()

    def test_memory_counter_is_available(self):
        self.assertGreater(capture.private_bytes(capture.os.getpid()), 0)


if __name__ == "__main__":
    unittest.main()
