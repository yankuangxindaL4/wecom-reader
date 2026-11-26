"""Failure boundaries and API tests, using only synthetic databases."""
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import Mock, patch

from fixtures import create_source, encrypt_database, fingerprints
from wecom_reader import WeComReader
from wecom_reader import storage


class SnapshotTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.key = os.urandom(16)
        self.source, self.expected = create_source(self.root, self.key)
        env = patch.dict(os.environ, {'WXWORK_KEY_DIR': str(self.root / 'keys'),
                                     'WXWORK_DB_DIR': '', 'WXWORK_DECRYPTED_DIR': ''})
        env.start()
        self.addCleanup(env.stop)
        self.reader = WeComReader(str(self.source), str(self.root / 'snapshot'), {'key': self.key.hex()})
        self.reader.init()
        self.reader.refresh()

    @unittest.skipIf(sqlite3.sqlite_version_info < (3, 44, 0),
                     'Virtual-table integrity checks require SQLite 3.44+')
    def test_crm_missing_tokenizer_warns_and_publishes_without_changing_schema(self):
        # Only this disposable fixture's schema is edited to simulate a database
        # created by an application that registered a custom FTS tokenizer.
        from contextlib import closing
        plain = self.root / 'custom-tokenizer.db'
        with closing(sqlite3.connect(plain)) as conn, conn:
            conn.execute('PRAGMA page_size=4096')
            conn.execute("CREATE VIRTUAL TABLE search_index USING fts5(content, tokenize=unicode61)")
            conn.execute("INSERT INTO search_index VALUES ('test customer')")
            conn.execute('PRAGMA writable_schema=ON')
            conn.execute("UPDATE sqlite_master SET sql=replace(sql, 'unicode61', 'fts5word') "
                         "WHERE name='search_index'")
        expected = plain.read_bytes()
        (self.source / 'crm.db').write_bytes(encrypt_database(expected, self.key))
        before = fingerprints(self.source)
        # Some Python/SQLite combinations lose the tokenizer detail when
        # quick_check fails. A generic SQL error must not receive the exemption.
        from wecom_reader.db import connect_readonly
        with closing(connect_readonly(str(plain))) as conn:
            with self.assertRaises(sqlite3.OperationalError) as raised:
                conn.execute('PRAGMA quick_check').fetchall()
        if str(raised.exception) != 'no such tokenizer: fts5word':
            snapshot_before = fingerprints(self.root / 'snapshot')
            with self.assertRaises(sqlite3.OperationalError) as refreshed:
                self.reader.refresh()
            self.assertEqual(str(refreshed.exception), str(raised.exception))
            self.assertEqual(fingerprints(self.root / 'snapshot'), snapshot_before)
            self.assertEqual(fingerprints(self.source), before)
            return
        with self.assertLogs('wecom_reader.reader', level='WARNING') as logs:
            report = self.reader.refresh()
        self.assertTrue(report['success'])
        self.assertEqual(report['updated'], 1)
        self.assertIn('crm.db', logs.output[0])
        self.assertIn('not been fully validated', logs.output[0])
        self.assertEqual((self.root / 'snapshot/crm.db').read_bytes(), expected)
        self.assertEqual(fingerprints(self.source), before)
        self.assertTrue(self.reader.search_messages('hello'))

    def test_exact_crm_tokenizer_error_is_exempt_on_all_python_versions(self):
        from wecom_reader.db import connect_readonly
        (self.source / 'crm.db').write_bytes(encrypt_database(self.expected['plain.db'], self.key))
        def connect(path):
            if Path(path).name != 'crm.db':
                return connect_readonly(path)
            conn = Mock()
            conn.execute.side_effect = sqlite3.OperationalError('no such tokenizer: fts5word')
            return conn
        with patch('wecom_reader.reader.connect_readonly', side_effect=connect):
            with self.assertLogs('wecom_reader.reader', level='WARNING') as logs:
                report = self.reader.refresh()
        self.assertTrue(report['success'])
        self.assertIn('not been fully validated', logs.output[0])
        self.assertEqual((self.root / 'snapshot/crm.db').read_bytes(), self.expected['plain.db'])
        self.assertTrue(self.reader.search_messages('hello'))

    def test_integrity_exception_does_not_hide_other_errors_or_failed_results(self):
        from wecom_reader.db import connect_readonly
        cases = [
            ('message.db', sqlite3.OperationalError('no such tokenizer: fts5word')),
            ('crm.db', sqlite3.OperationalError('no such tokenizer: other')),
            ('crm.db', sqlite3.OperationalError('SQL logic error')),
            ('crm.db', sqlite3.DatabaseError('database disk image is malformed')),
            ('crm.db', [('no such tokenizer: fts5word',)]),
            ('crm.db', [('database disk image is malformed',)]),
        ]
        (self.source / 'crm.db').write_bytes(encrypt_database(self.expected['plain.db'], self.key))
        self.reader.refresh()
        before = fingerprints(self.root / 'snapshot')
        for name, failure in cases:
            with self.subTest(database=name, failure=str(failure)):
                stat = (self.source / name).stat()
                os.utime(self.source / name, ns=(stat.st_atime_ns, stat.st_mtime_ns + 1_000_000_000))
                def connect(path):
                    if Path(path).name != name:
                        return connect_readonly(path)
                    conn = Mock()
                    if isinstance(failure, Exception):
                        conn.execute.side_effect = failure
                    else:
                        conn.execute.return_value.fetchall.return_value = failure
                    return conn
                with patch('wecom_reader.reader.connect_readonly', side_effect=connect):
                    with self.assertRaises((sqlite3.Error, RuntimeError)):
                        self.reader.refresh()
                self.assertEqual(fingerprints(self.root / 'snapshot'), before)

    def test_source_changes_during_build_preserve_snapshot(self):
        from wecom_reader.snapshot import build_database
        before = fingerprints(self.root / 'snapshot')
        # Whole seconds remain distinguishable on Windows filesystems.
        os.utime(self.source / 'session.db', ns=(1_000_000_000, 1_000_000_000))
        def changing(source, output, keys):
            result = build_database(source, output, keys)
            os.utime(source, ns=(2_000_000_000, 2_000_000_000))
            return result
        with patch('wecom_reader.reader.build_database', side_effect=changing):
            with self.assertRaisesRegex(RuntimeError, 'Source changed'):
                self.reader.refresh()
        self.assertEqual(fingerprints(self.root / 'snapshot'), before)

    def test_metadata_write_failure_rolls_back_published_files(self):
        before = fingerprints(self.root / 'snapshot')
        (self.source / 'plain.db').write_bytes(self.expected['session.db'])
        with patch('wecom_reader.reader.write_json', side_effect=OSError('disk full')):
            with self.assertRaisesRegex(OSError, 'disk full'):
                self.reader.refresh()
        self.assertEqual(fingerprints(self.root / 'snapshot'), before)

    def test_expired_query_refreshes_changes_without_memory_scan(self):
        import sqlite3
        from contextlib import closing
        plain = self.root / 'modified.db'
        plain.write_bytes(self.expected['session.db'])
        with closing(sqlite3.connect(plain)) as conn, conn:
            conn.execute("UPDATE conversation_table SET name='Expired update' WHERE id='R:1'")
        (self.source / 'session.db').write_bytes(encrypt_database(plain.read_bytes(), self.key))
        self.assertFalse(self.reader.list_sessions(keyword='Expired update'))
        with patch.object(self.reader, 'FRESHNESS_SECONDS', 0), patch('wecom_reader.reader.extract_key', side_effect=AssertionError('must not scan')):
            self.assertEqual(len(self.reader.list_sessions(keyword='Expired update')), 1)

    def test_removed_source_database_is_removed_from_snapshot(self):
        (self.source / 'plain.db').unlink()
        report = self.reader.refresh()
        self.assertEqual(report['removed'], 1)
        self.assertFalse((self.root / 'snapshot/plain.db').exists())

    @unittest.skipUnless(os.name == 'posix', 'sudo is POSIX-specific')
    def test_sudo_defaults_use_invoking_home_and_chown_created_files(self):
        home = self.root / 'invoking-user'
        home.mkdir()
        with patch('wecom_reader.storage.owner', return_value=(1234, 2345, home)), patch('wecom_reader.storage.os.chown') as chown:
            with patch.dict(os.environ, {'XDG_CACHE_HOME': '/root/cache', 'XDG_DATA_HOME': '/root/data'}):
                self.assertEqual(storage.default_root('cache'), home / '.cache/wecom-reader')
                self.assertEqual(storage.default_root('data'), home / '.local/share/wecom-reader')
            path = home / 'keys/account.json'
            storage.write_json(path, {'keys': []})
            self.assertTrue(path.exists())
            self.assertTrue(chown.called)
            self.assertTrue(all(call.args[1:] == (1234, 2345) for call in chown.call_args_list))
