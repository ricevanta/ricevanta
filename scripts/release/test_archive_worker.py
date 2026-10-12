"""Archive supervision works without importing the caller's main module."""
import dataclasses
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

import archives
from test_archives import IDENTITY, tar_bytes


class ArchiveWorkerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='ricevanta-worker-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.path = self.root / 'fixture.tar'
        self.path.write_bytes(tar_bytes([]))

    def test_stdin_and_unguarded_main_callers(self):
        source = (
            'import sys\n'
            f'sys.path.insert(0, {str(Path(archives.__file__).parent)!r})\n'
            'from pathlib import Path\n'
            'import archives\n'
            f'archives.check(Path({str(self.path)!r}), "tar", [], {IDENTITY!r})\n'
            'print("accepted")\n'
        )
        caller = self.root / 'caller.py'
        caller.write_text(source, encoding='utf-8')
        for args, input_text in ((['-'], source), ([str(caller)], None)):
            with self.subTest(caller=args[0]):
                result = subprocess.run([sys.executable, '-I', '-B', *args],
                                        input=input_text, text=True, capture_output=True,
                                        cwd=self.root, timeout=5)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout, 'accepted\n')

    def run_control(self, source, error, seconds=2):
        launched = []

        def launch(request_path, result):
            child = subprocess.Popen([sys.executable, '-I', '-B', '-c', source,
                                      str(request_path), str(result)],
                                     stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                     stderr=subprocess.DEVNULL)
            launched.append(child)
            return child

        with patch.object(archives, '_launch_worker', launch, create=True):
            with self.assertRaisesRegex(ValueError, error):
                archives.check(self.path, 'tar', [], IDENTITY,
                               dataclasses.replace(archives.Limits(), seconds=seconds))
        self.assertEqual(len(launched), 1)
        self.assertIsNotNone(launched[0].poll(), 'supervisor must reap its child')
        return launched[0]

    def test_supervisor_terminates_a_stalled_parser(self):
        started = time.monotonic()
        child = self.run_control('import time; time.sleep(30)',
                                 'supervisor deadline exceeded', seconds=0.1)
        self.assertNotEqual(child.returncode, 0)
        self.assertLess(time.monotonic() - started, 3)

    def test_supervisor_rejects_crash_without_timeout(self):
        child = self.run_control('raise SystemExit(17)', 'parser failed')
        self.assertEqual(child.returncode, 17)

    def test_result_does_not_bypass_child_deadline(self):
        self.run_control('import pathlib, sys, time; '
                         'pathlib.Path(sys.argv[2]).write_bytes(b\'{"error":null}\'); '
                         'time.sleep(30)', 'supervisor deadline exceeded', seconds=0.1)

    def test_supervisor_rejects_missing_invalid_and_oversized_results(self):
        self.run_control('pass', 'exited without result')
        results = (repr(b'not JSON'), repr(b'{"error":null,"extra":true}'),
                   repr(b'{"error":3}'), repr(b'{"error":null,"error":null}'),
                   "b'x' * 65537")
        for result in results:
            with self.subTest(result=result):
                self.run_control('import pathlib, sys; '
                                 f'pathlib.Path(sys.argv[2]).write_bytes({result})',
                                 'invalid parser result')

    def test_real_worker_returns_parser_rejection(self):
        self.path.write_bytes(b'not an archive')
        with self.assertRaisesRegex(ValueError, 'truncated stream'):
            archives.check(self.path, 'tar', [], IDENTITY)

    def test_real_worker_does_not_inherit_unrelated_environment(self):
        trusted = Path(archives.__file__).resolve().parent
        probe = self.root / 'environment-probe.json'
        worker = self.root / 'archive_worker.py'
        instrumentation = (
            'import json, os, sys\n'
            'from pathlib import Path\n'
            f'sys.path.insert(0, {str(trusted)!r})\n'
            f'Path({str(probe)!r}).write_text(json.dumps({{\n'
            '    "unrelated": os.environ.get("RICEVANTA_WORKER_TEST_UNRELATED"),\n'
            '    "isolated": sys.flags.isolated,\n'
            '}), encoding="utf-8")\n'
        )
        worker.write_text(instrumentation + (trusted / 'archive_worker.py').read_text(
            encoding='utf-8'), encoding='utf-8')
        with patch.dict(os.environ, {'RICEVANTA_WORKER_TEST_UNRELATED': 'synthetic-only'}), \
                patch.object(archives, '__file__', str(self.root / 'archives.py')):
            archives.check(self.path, 'tar', [], IDENTITY)
        self.assertEqual(json.loads(probe.read_text(encoding='utf-8')),
                         {'unrelated': None, 'isolated': 1})

    def test_worker_environment_allows_only_interpreter_requirements(self):
        unrelated = {
            'RICEVANTA_WORKER_TEST_UNRELATED': 'synthetic-only',
            'PATH': 'synthetic-bin', 'HOME': 'synthetic-home',
            'TEMP': 'synthetic-temp', 'TMP': 'synthetic-tmp',
            'WINDIR': 'synthetic-windows', 'VIRTUAL_ENV': 'synthetic-venv',
            'PYTHONHOME': 'synthetic-python', 'PYTHONPATH': 'synthetic-imports',
            'LD_LIBRARY_PATH': 'synthetic-libraries', 'LD_PRELOAD': 'synthetic-preload',
            'DYLD_LIBRARY_PATH': 'synthetic-libraries',
            'DYLD_INSERT_LIBRARIES': 'synthetic-preload',
        }
        cases = (
            ('linux', 'SYSTEMROOT', {}), ('darwin', 'SystemRoot', {}),
            ('win32', 'SYSTEMROOT', {'SYSTEMROOT': r'C:\SyntheticWindows'}),
            ('win32', 'SystemRoot', {'SystemRoot': r'C:\SyntheticWindows'}),
            ('win32', 'systemroot', {'systemroot': r'C:\SyntheticWindows'}),
            ('win32', None, {}), ('unknown', 'SYSTEMROOT', {}),
        )
        for platform, system_root, expected in cases:
            environment = dict(unrelated)
            if system_root is not None:
                environment[system_root] = r'C:\SyntheticWindows'
            with self.subTest(platform=platform, system_root=system_root), \
                    patch.object(sys, 'platform', platform), \
                    patch.object(os, 'environ', environment):
                self.assertEqual(archives._worker_environment(), expected)


if __name__ == '__main__':
    unittest.main()
