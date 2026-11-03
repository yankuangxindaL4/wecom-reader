"""CLI integration tests against a real synthetic WXWork.exe process.

Run with: uv run --no-project --with pycryptodomex python -m unittest discover -s tests/integration -v
"""
from contextlib import closing, contextmanager
import csv
import io
import json
import os
from pathlib import Path
import queue
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import threading
import unittest

from fixtures import create_source, fingerprints

REPOSITORY = Path(__file__).resolve().parents[2]


def compile_fake(output):
    source = Path(__file__).with_name('fake_wxwork.c')
    if sys.platform == 'linux':
        command = ['gcc', '-std=c11', '-D_GNU_SOURCE', '-O2', '-Wall', '-Wextra', str(source), '-o', str(output)]
    elif sys.platform == 'win32':
        # Use the Visual Studio compiler already installed on GitHub Windows runners.
        locator = Path(os.environ.get('ProgramFiles(x86)', r'C:\Program Files (x86)')) / 'Microsoft Visual Studio/Installer/vswhere.exe'
        found = subprocess.run([str(locator), '-latest', '-products', '*', '-requires',
                                'Microsoft.VisualStudio.Component.VC.Tools.x86.x64', '-property', 'installationPath'],
                               check=True, capture_output=True, text=True).stdout.strip()
        if not found:
            raise RuntimeError('Visual Studio C++ build tools are required')
        batch = output.parent / 'compile.cmd'
        vcvars = Path(found) / 'VC/Auxiliary/Build/vcvars64.bat'
        batch.write_text(f'@echo off\ncall "{vcvars}" >nul\nif errorlevel 1 exit /b 1\n'
                         f'cl /nologo /W4 /O2 "{source}" /Fe:"{output}"\n', encoding='utf-8')
        command = ['cmd', '/d', '/c', str(batch)]
    else:
        raise RuntimeError('The fake process supports Windows and Linux')
    subprocess.run(command, cwd=output.parent, check=True, capture_output=True, text=True, timeout=120)


class IntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.build = tempfile.TemporaryDirectory(prefix='wecom-fake-build-')
        cls.addClassCleanup(cls.build.cleanup)
        cls.executable = Path(cls.build.name) / 'WXWork.exe'
        compile_fake(cls.executable)
        uv = shutil.which('uv')
        if not uv:
            raise RuntimeError('Install uv before running these integration tests')
        # `uv tool run` is the long form of uvx. No source imports or PYTHONPATH.
        # Local-source builds write egg-info. Keep those artifacts in a disposable
        # source copy so running tests never changes the developer's checkout.
        package = Path(cls.build.name) / 'package'
        package.mkdir()
        for name in ('pyproject.toml', 'README.md', 'LICENSE'):
            if (REPOSITORY / name).exists():
                shutil.copy2(REPOSITORY / name, package / name)
        shutil.copytree(REPOSITORY / 'wecom_reader', package / 'wecom_reader',
                        ignore=shutil.ignore_patterns('__pycache__', '*.pyc'))
        cls.command = [uv, 'tool', 'run', '--python', sys.executable,
                       '--from', str(package), 'wecom-reader']
        env = os.environ.copy()
        env.pop('PYTHONPATH', None)
        env['UV_TOOL_DIR'] = str(Path(cls.build.name) / 'uv-tools')
        env['PYTHONIOENCODING'] = 'utf-8'
        env['PYTHONUTF8'] = '1'
        warmup = subprocess.run([*cls.command, '--help'], cwd=cls.build.name, env=env,
                       capture_output=True, text=True, encoding='utf-8', timeout=180)
        if warmup.returncode:
            raise RuntimeError(f'uvx installation failed: {warmup.stdout} {warmup.stderr}')

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='wecom-integration-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.key = os.urandom(16)
        self.source, self.expected = create_source(self.root, self.key)
        # Exercise portable paths independently of the source checkout and CLI cwd.
        self.snapshot = self.root / '快照 with spaces #'
        self.cwd = self.root / 'unrelated working directory'
        self.cwd.mkdir()
        self.original = fingerprints(self.source)

    @contextmanager
    def fake(self, mode='hex', key=None, name=None):
        executable = self.executable
        if name:
            executable = self.root / name
            shutil.copy2(self.executable, executable)
        process = subprocess.Popen([str(executable), mode], stdin=subprocess.PIPE,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   text=True, encoding='utf-8')
        ready = queue.Queue()
        reader = threading.Thread(target=lambda: ready.put(process.stdout.readline()), daemon=True)
        reader.start()
        try:
            process.stdin.write((key if key is not None else self.key).hex() + '\n')
            process.stdin.flush()
            try:
                line = ready.get(timeout=15)
            except queue.Empty as error:
                raise AssertionError('Fake process did not become ready within 15 seconds') from error
            if line.strip() != 'READY':
                process.wait(timeout=5)
                self.fail(f'Fake process failed: {process.stderr.read()}')
            yield process
            self.assertIsNone(process.poll(), 'CLI must not terminate the fake process')
        finally:
            if process.stdin and not process.stdin.closed:
                try:
                    process.stdin.close()
                except BrokenPipeError:
                    pass
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
            reader.join(timeout=5)
            process.stdout.close()
            process.stderr.close()

    def cli(self, *arguments, output=None, env=None, code=0, parse=True, source=False):
        environment = os.environ.copy()
        for name in ('PYTHONPATH', 'WXWORK_DB_DIR'):
            environment.pop(name, None)
        environment['UV_TOOL_DIR'] = str(Path(self.build.name) / 'uv-tools')
        environment['PYTHONIOENCODING'] = 'utf-8'
        environment['PYTHONUTF8'] = '1'
        environment.update(env or {})
        paths = ['--decrypted-dir', str(output if output is not None else self.snapshot)]
        if source:
            paths += ['--db-dir', str(self.source)]
        result = subprocess.run([*self.command, *paths, *map(str, arguments)], cwd=self.cwd,
                                env=environment, capture_output=True, text=True,
                                encoding='utf-8', timeout=90)
        self.assertEqual(result.returncode, code, f'{result.args}\nstdout: {result.stdout}\nstderr: {result.stderr}')
        self.assertNotIn(self.key.hex(), result.stdout + result.stderr)
        return (json.loads(result.stdout) if parse else result.stdout), result

    def initialize(self, mode='hex', env_path=False):
        with self.fake(mode) as process:
            report, result = self.cli('init', '--verbose', '--timeout', 30,
                                      source=not env_path,
                                      env={'WXWORK_DB_DIR': str(self.source)} if env_path else None)
            self.assertTrue(report['success'])
            self.assertEqual((report['decrypted'], report['copied'], report['failed']), (3, 1, 0))
            self.assertIn(f'PID {process.pid}', result.stderr)
        self.assertEqual(fingerprints(self.source), self.original)
        for name, expected in self.expected.items():
            self.assertEqual((self.snapshot / name).read_bytes(), expected, name)
            with closing(sqlite3.connect(self.snapshot / name)) as conn:
                self.assertEqual(conn.execute('PRAGMA integrity_check').fetchone()[0], 'ok')

    def test_init_discovers_real_process_and_decrypts_all_databases(self):
        self.initialize()

    def test_environment_source_path(self):
        self.initialize(env_path=True)

    def test_hex_key_crosses_four_megabyte_boundary(self):
        self.initialize('boundary')

    def test_cipher_struct_has_pointer_targets_in_another_chunk(self):
        self.initialize('struct')

    def test_wrong_key_reports_failure_without_creating_snapshot(self):
        with self.fake(key=os.urandom(16)):
            report, _ = self.cli('init', '--timeout', 15, source=True, code=1)
            self.assertFalse(report['success'])
            self.assertIn('Failed to extract', report['error'])
        self.assertFalse(self.snapshot.exists())
        self.assertEqual(fingerprints(self.source), self.original)

    def test_web_process_is_not_mistaken_for_wxwork(self):
        with self.fake(name='WXWorkWeb.exe'):
            report, _ = self.cli('init', source=True, code=1)
            self.assertFalse(report['success'])
            self.assertIn('not running', report['error'])
        self.assertFalse(self.snapshot.exists())

    @unittest.skipUnless(sys.platform == 'linux', 'Linux process permission semantics')
    def test_memory_permission_denial_returns_json(self):
        # A root runner bypasses this discretionary permission restriction.
        if os.geteuid() == 0:
            self.skipTest('Requires an unprivileged test runner')
        with self.fake('denied'):
            report, _ = self.cli('init', source=True, code=1)
            self.assertIn('Permission denied', report['error'])
        self.assertFalse(self.snapshot.exists())

    def test_output_inside_source_is_rejected(self):
        with self.fake():
            for output in (self.source, self.source / 'nested'):
                with self.subTest(output=str(output)):
                    report, _ = self.cli('init', source=True, output=output, code=1)
                    self.assertIn('outside the source', report['error'])
        self.assertEqual(fingerprints(self.source), self.original)
        self.assertFalse((self.source / 'nested').exists())

    def test_queries_are_readonly_and_sessions_filter_correctly(self):
        self.initialize()
        before = fingerprints(self.snapshot)
        if sys.platform == 'linux':
            for file in self.snapshot.iterdir():
                file.chmod(0o444)
            self.snapshot.chmod(0o555)
        try:
            report, _ = self.cli('status')
            self.assertTrue(report['decrypted'])
            self.assertIn('conversation_table', report['databases']['session.db']['tables'])
            result, _ = self.cli('sessions', '--type', 'R', '--keyword', 'Test', '-n', 1)
            self.assertEqual(result['count'], 1)
            self.assertEqual(result['sessions'][0]['id'], 'R:1')
            messages, _ = self.cli('messages', 'R:1', '-n', 1)
            self.assertEqual(messages['messages'][0]['sender_name'], 'Contact two')
            self.cli('contacts')
            self.cli('group-members', 'R:1')
            self.cli('search', 'Hello')
            self.assertEqual(fingerprints(self.snapshot), before)
            self.assertFalse((self.cwd / 'wxwork_decrypted').exists())
        finally:
            self.snapshot.chmod(0o755)
            for file in self.snapshot.iterdir():
                file.chmod(0o644)

    def test_message_pagination_merges_tables_before_offset(self):
        self.initialize()
        actual = []
        for offset in range(0, 9, 2):
            result, _ = self.cli('messages', 'R:1', '--since', 70, '--until', 101,
                                 '-n', 2, '--offset', offset)
            self.assertEqual(result['count'], len(result['messages']))
            actual.extend(m['sequence'] for m in result['messages'])
        self.assertEqual(actual, [100, 95, 90, 85, 80, 75, 70])

    def test_search_binary_text_nul_chinese_and_literal_wildcards(self):
        self.initialize()
        cases = [('hELLo', [100,95,90,85,80,75,70]), ('中文', [50]),
                 ('%', [40]), ('_', [30]), ("' OR 1=1 --", [])]
        for keyword, expected in cases:
            with self.subTest(keyword=keyword):
                result, _ = self.cli('search', keyword, '--session', 'R:1', '-n', 100)
                self.assertEqual([m['sequence'] for m in result['results']], expected)
        result, _ = self.cli('messages', 'R:1', '--since', 60, '--until', 61)
        self.assertEqual(result['messages'][0]['content'], '1')
        result, _ = self.cli('search', 'hello', '-n', 2)
        self.assertEqual(result['count'], 2)
        result, _ = self.cli('search', 'hello', '--session', 'R:2')
        self.assertEqual(result['count'], 0)

    def test_contact_pagination_and_group_name_fallbacks(self):
        self.initialize()
        ids = []
        for offset in range(5):
            result, _ = self.cli('contacts', '-n', 1, '--offset', offset)
            self.assertLessEqual(result['count'], 1)
            ids.extend(c['id'] for c in result['contacts'])
        self.assertEqual(ids, [1,2,3,5])
        result, _ = self.cli('contacts', '--keyword', 'match', '-n', 2, '--offset', 1)
        self.assertEqual([c['id'] for c in result['contacts']], [3,5])
        result, _ = self.cli('group-members', 'R:1')
        self.assertEqual(result, {'count':4, 'members':{'1':'Group nickname','2':'Contact two','3':'match C','4':'4'}})
        (self.snapshot / 'user.db').unlink()
        result, _ = self.cli('group-members', 'R:1')
        self.assertEqual(result['members'], {'1':'Group nickname','2':'2','3':'3','4':'4'})

    def test_emoji_survive_binary_message_parsing(self):
        self.snapshot.mkdir()
        for name, data in self.expected.items():
            (self.snapshot / name).write_bytes(data)
        texts = ['hello🙂world', '🙂', '👍🏽', '❤️', '👨‍👩‍👧‍👦', '🇨🇳', '1️⃣ #️⃣ *️⃣']
        with closing(sqlite3.connect(self.snapshot / 'message.db')) as conn, conn:
            conn.execute('DELETE FROM message_table')
            for number, text in enumerate(texts, 1):
                body = text.encode('utf-8')
                payload = b'\x12' + bytes([len(body)]) + body
                conn.execute("INSERT INTO message_table VALUES (?,0,?,2,'R:emoji',0,?,0,?,0)",
                             (number, number, number, payload))
        report, _ = self.cli('messages', 'R:emoji', '-n', 100)
        contents = {message['message_id']: message['content'] for message in report['messages']}
        for number, text in enumerate(texts, 1):
            self.assertIn(text, contents[number])
        report, _ = self.cli('search', '🙂', '--session', 'R:emoji')
        self.assertEqual(report['count'], 2)
        self.assertTrue(all('🙂' in message['content'] for message in report['results']))

    def test_export_warns_only_when_messages_are_omitted(self):
        self.snapshot.mkdir()
        for name, data in self.expected.items():
            (self.snapshot / name).write_bytes(data)
        with closing(sqlite3.connect(self.snapshot / 'message.db')) as conn, conn:
            conn.execute('DELETE FROM message_table')
            conn.executemany("INSERT INTO message_table VALUES (?,0,?,2,'R:export',0,?,0,'hello',0)",
                             ((number, number, number) for number in range(1, 10002)))
        exported, result = self.cli('export', 'R:export')
        self.assertEqual(len(exported), 10000)
        self.assertEqual(exported[-1]['message_id'], 2)
        self.assertIn('truncated', result.stderr)
        self.assertIn('10,000', result.stderr)
        path = self.root / 'limited.csv'
        report, result = self.cli('export', 'R:export', '--format', 'csv', '--output', path)
        self.assertEqual(report['count'], 10000)
        self.assertIn('truncated', result.stderr)
        with path.open(encoding='utf-8', newline='') as file:
            self.assertEqual(len(list(csv.DictReader(file))), 10000)
        with closing(sqlite3.connect(self.snapshot / 'message.db')) as conn, conn:
            conn.execute('DELETE FROM message_table WHERE message_id=10001')
        exported, result = self.cli('export', 'R:export')
        self.assertEqual(len(exported), 10000)
        self.assertNotIn('truncated', result.stderr)
        with closing(sqlite3.connect(self.snapshot / 'message.db')) as conn, conn:
            conn.execute('DELETE FROM message_table WHERE message_id=10000')
        exported, result = self.cli('export', 'R:export')
        self.assertEqual(len(exported), 9999)
        self.assertNotIn('truncated', result.stderr)

    def test_exports_are_readable_json_and_csv(self):
        self.initialize()
        exported, _ = self.cli('export', 'R:1')
        self.assertEqual(len(exported), 13)
        text, _ = self.cli('export', 'R:1', '--format', 'csv', parse=False)
        self.assertEqual(len(list(csv.DictReader(io.StringIO(text)))), 13)
        path = self.root / 'export.json'
        report, _ = self.cli('export', 'R:1', '--output', path)
        self.assertTrue(report['success'])
        self.assertEqual(json.loads(path.read_text(encoding='utf-8')), exported)


if __name__ == '__main__':
    unittest.main()
