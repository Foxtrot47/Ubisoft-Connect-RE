import tempfile
from pathlib import Path
import unittest

from run_independent_launcher import input_guard


class InputGuardTests(unittest.TestCase):
    def test_forbidden_reads_and_directory_scans_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            forbidden = Path(directory) / 'evidence'
            violations = []
            guard = input_guard([forbidden], violations)
            for event in ('open', 'os.listdir', 'os.scandir'):
                with self.assertRaises(RuntimeError):
                    guard(event, (str(forbidden / 'private.bin'),))
            self.assertEqual(len(violations), 3)

    def test_owned_runtime_and_output_are_allowed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            violations = []
            guard = input_guard([root / 'evidence'], violations)
            for path in (root / 'runtime/test.dll', root / 'independent-runs/status.json', root / 'evidence-other/file'):
                guard('open', (str(path),))
            self.assertEqual(violations, [])

    def test_normalized_paths_cannot_escape_the_guard(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            guard = input_guard([root / 'evidence'], [])
            with self.assertRaises(RuntimeError):
                guard('open', (str(root / 'output/../evidence/private.bin'),))

    def test_non_file_events_and_file_descriptors_are_ignored(self):
        guard = input_guard([], [])
        guard('open', (1,))
        guard('import', ('example',))


if __name__ == '__main__':
    unittest.main()
