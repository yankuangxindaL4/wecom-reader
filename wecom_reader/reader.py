"""Main WeComReader class — unified interface for WeCom chat data access."""

from contextlib import closing
import logging
import os
from pathlib import Path
import sqlite3
import tempfile
import time
from typing import Optional
import uuid

from .crypto.key_extract import extract_key, _collect_db_files
from .crypto.decrypt import verify_key
from .db import connect_readonly
from .db.contact import build_user_map, get_group_members, list_contacts
from .db.message import get_message_count, get_messages, search_messages
from .db.session import get_session_count, list_sessions
from .snapshot import build_database, fingerprints, publish_files, snapshot_lock
from .storage import (account_id, accounts, default_root, key_directory,
                      private_directory, read_json, select_source, write_json)


class WeComReader:
    """Initialize keys once with init(); queries refresh snapshots as needed."""

    FRESHNESS_SECONDS = 300
    MANIFEST = '.wecom-snapshot.json'

    def __init__(
        self,
        db_dir: Optional[str] = None,
        decrypted_dir: Optional[str] = None,
        key_map: Optional[dict] = None,
    ):
        self._db_dir = db_dir or os.environ.get('WXWORK_DB_DIR')
        self._decrypted_dir = decrypted_dir or os.environ.get('WXWORK_DECRYPTED_DIR')
        self._key_map = key_map
        self._key_dir = key_directory()
        self._account_selector = None
        self._resolved = False
        self._user_map: Optional[dict] = None
        self._seen_generation = None

    def _resolve(self):
        if self._resolved:
            return
        explicit_output = self._decrypted_dir
        manifest = read_json(Path(explicit_output).expanduser() / self.MANIFEST) if explicit_output else {}
        source = self._db_dir or (self._key_map or {}).get('_db_dir')
        if not source and not self._account_selector and explicit_output:
            # A portable explicit snapshot remains usable without the original source.
            source = manifest.get('db_dir')
            standalone = not manifest and Path(explicit_output).is_dir() and any(Path(explicit_output).glob('*.db'))
        else:
            standalone = False
        if not standalone:
            source = select_source(source, self._key_dir, self._account_selector)
        if not source and not explicit_output and not self._account_selector:
            snapshots = list((default_root('data') / 'decrypted').glob('*/' + self.MANIFEST))
            records = [(read_json(p), p.parent) for p in snapshots]
            if records:
                manifest, output = max(records, key=lambda item: item[0].get('updated_at', 0))
                source, explicit_output = manifest.get('db_dir'), str(output)
        self._db_dir = os.path.realpath(source) if source else None
        self._account = account_id(self._db_dir) if self._db_dir else None
        output = Path(explicit_output).expanduser() if explicit_output else (
            default_root('data') / 'decrypted' / (self._account or 'unselected'))
        self._decrypted_dir = str(output.resolve())
        self._resolved = True
        self._check_paths()

    def _check_paths(self):
        if self._db_dir:
            try:
                inside = os.path.commonpath([self._db_dir, self._decrypted_dir]) in (self._db_dir, self._decrypted_dir)
            except ValueError:
                inside = False
            if inside:
                raise ValueError('Decrypted output directory must be outside the source Data directory and must not contain it')
        manifest = self._manifest()
        if manifest and self._account and manifest.get('account') != self._account:
            raise ValueError('Snapshot belongs to another account; choose a different --decrypted-dir')

    def _manifest(self):
        return read_json(Path(self._decrypted_dir) / self.MANIFEST)

    def _cache_path(self):
        return Path(self._key_dir) / f'{self._account}.json'

    def _cache(self):
        if not self._account:
            return {}
        record = read_json(self._cache_path())
        if record and record.get('db_dir') != self._db_dir:
            raise RuntimeError('Key cache source does not match selected account')
        return record

    @property
    def db_dir(self) -> Optional[str]:
        self._resolve()
        return self._db_dir

    @property
    def decrypted_dir(self) -> str:
        self._resolve()
        return self._decrypted_dir

    def status(self) -> dict:
        """Inspect metadata without scanning memory or refreshing snapshots."""
        self._resolve()
        manifest = self._manifest()
        cache = self._cache()
        result = {
            'account': self._account,
            'db_dir': self._db_dir,
            'decrypted_dir': self._decrypted_dir,
            'key_dir': str(self._key_dir),
            'key_cached': bool(cache.get('keys')),
            'key_updated_at': cache.get('updated_at'),
            'snapshot_updated_at': manifest.get('updated_at'),
            'snapshot_checked_at': manifest.get('checked_at'),
            'freshness_seconds': self.FRESHNESS_SECONDS,
            'decrypted': os.path.isdir(self._decrypted_dir),
            'accounts': accounts(self._key_dir),
            'databases': {},
        }
        for path in Path(self._decrypted_dir).glob('*.db'):
            try:
                with closing(connect_readonly(str(path))) as conn:
                    tables = [r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")]
            except Exception:
                tables = []
            result['databases'][path.name] = {'size_mb': round(path.stat().st_size / 1024 / 1024, 1), 'tables': tables}
        return result

    def init(self, timeout: int = 120, verbose: bool = False) -> dict:
        """Extract and persist verified keys; does not decrypt any database."""
        self._resolve()
        if timeout <= 0:
            raise ValueError('Memory scan timeout must be greater than zero')
        if not self._db_dir or not os.path.isdir(self._db_dir):
            raise RuntimeError('Cannot find WeCom data directory. Set --db-dir to the Data directory.')
        key_map = self._key_map if self._key_map is not None else extract_key(
            db_dir=self._db_dir, timeout=timeout, verbose=verbose)
        try:
            keys = sorted({bytes.fromhex(v) for k, v in key_map.items() if not k.startswith('_')})
        except (ValueError, TypeError):
            raise RuntimeError('Invalid key map') from None
        files, _ = _collect_db_files(self._db_dir)
        verified = [key for key in keys if any(verify_key(key, page) for *_, page in files)]
        if not verified:
            raise RuntimeError('No verified keys extracted; existing cache was preserved')
        record = {'account': self._account, 'db_dir': self._db_dir,
                  'keys': [key.hex() for key in verified], 'updated_at': time.time(),
                  'generation': uuid.uuid4().hex}
        write_json(self._cache_path(), record)
        # Cache generation invalidates every snapshot for this account without touching them.
        return {'success': True, 'account': self._account, 'db_dir': self._db_dir,
                'key_count': len(verified), 'key_file': str(self._cache_path()),
                'decrypted_dir': self._decrypted_dir}

    def _ensure_snapshot(self):
        self._resolve()
        manifest = self._manifest()
        if not self._db_dir or not os.path.isdir(self._db_dir):
            if any(Path(self._decrypted_dir).glob('*.db')):
                return  # Explicit legacy/imported snapshots and offline snapshots.
            raise RuntimeError('No source or snapshot found; run init with --db-dir first')
        cache = self._cache()
        generation = manifest.get('generation')
        if generation != self._seen_generation:
            self._user_map = None
            self._seen_generation = generation
        age = time.time() - manifest.get('checked_at', 0)
        if manifest and 0 <= age < self.FRESHNESS_SECONDS and manifest.get('key_generation') == cache.get('generation'):
            return
        self.refresh()

    def refresh(self) -> dict:
        """Immediately check source changes and refresh using cached keys only."""
        self._resolve()
        if not self._db_dir or not os.path.isdir(self._db_dir):
            raise RuntimeError('Source directory is unavailable; cannot refresh')
        self._check_paths()
        output = Path(self._decrypted_dir)
        private_directory(output)
        with snapshot_lock(output):
            self._check_paths()
            manifest = self._manifest()
            cache = self._cache()
            try:
                values = cache.get('keys', []) if self._key_map is None else [v for k, v in self._key_map.items() if not k.startswith('_')]
                keys = [bytes.fromhex(v) for v in values]
            except (ValueError, TypeError):
                raise RuntimeError('Invalid key cache; run init') from None
            before = fingerprints(self._db_dir)
            if not before:
                raise RuntimeError('No source databases found; snapshot was preserved')
            changed = [name for name, stats in before.items()
                       if manifest.get('files', {}).get(name) != stats or not (output / name).is_file()]
            # Revalidate keys after explicit init, even when source bytes did not change.
            if manifest.get('key_generation') != cache.get('generation'):
                changed = list(before)
            removed = set(manifest.get('files', {})) - set(before)
            counts = {'decrypted': 0, 'copied': 0, 'failed': 0}
            with tempfile.TemporaryDirectory(prefix='.refresh-', dir=output) as temporary:
                staging = Path(temporary)
                for name in changed:
                    kind = build_database(Path(self._db_dir) / name, staging / name, keys)
                    counts[kind] += 1
                    with closing(connect_readonly(str(staging / name))) as conn:
                        try:
                            check = conn.execute('PRAGMA quick_check').fetchall()
                        except sqlite3.OperationalError as error:
                            if name != 'crm.db' or str(error) != 'no such tokenizer: fts5word':
                                raise
                            logging.getLogger(__name__).warning(
                                'Skipping integrity check for crm.db: no such tokenizer: fts5word; '
                                'this database has not been fully validated'
                            )
                            continue
                        if check != [('ok',)]:
                            raise RuntimeError(f'Invalid decrypted database: {name}; old snapshot was preserved')
                if before != fingerprints(self._db_dir):
                    raise RuntimeError('Source changed during refresh; retry refresh (old snapshot preserved)')
                now = time.time()
                generation = uuid.uuid4().hex if changed or removed else manifest.get('generation', uuid.uuid4().hex)
                with publish_files(staging, output, changed, removed):
                    write_json(output / self.MANIFEST, {
                        'account': self._account, 'db_dir': self._db_dir, 'files': before,
                        'checked_at': now, 'updated_at': now if changed or removed else manifest.get('updated_at', now),
                        'key_generation': cache.get('generation'), 'generation': generation,
                    })
            self._user_map = None
            self._seen_generation = generation
            return {'success': True, 'account': self._account, 'db_dir': self._db_dir,
                    'decrypted_dir': self._decrypted_dir, 'updated': len(changed), 'removed': len(removed), **counts}

    def _get_db_path(self, name: str) -> Optional[str]:
        self._ensure_snapshot()
        path = os.path.join(self._decrypted_dir, name)
        return path if os.path.isfile(path) else None

    def _ensure_user_map(self):
        """Lazy-load user map for sender name resolution."""
        if self._user_map is not None:
            return
        user_db = self._get_db_path("user.db")
        if user_db:
            self._user_map = build_user_map(user_db)
        else:
            self._user_map = {}

    def list_sessions(
        self,
        limit: int = 50,
        offset: int = 0,
        keyword: Optional[str] = None,
        session_type: Optional[str] = None,
    ) -> list[dict]:
        """List WeCom sessions/conversations."""
        session_db = self._get_db_path("session.db")
        if not session_db:
            return []
        return list_sessions(session_db, limit=limit, offset=offset, keyword=keyword, session_type=session_type)

    def get_messages(
        self,
        conversation_id: str,
        limit: int = 50,
        offset: int = 0,
        since: Optional[int] = None,
        until: Optional[int] = None,
    ) -> list[dict]:
        """Get messages for a conversation."""
        msg_db = self._get_db_path("message.db")
        if not msg_db:
            return []

        self._ensure_user_map()
        messages = get_messages(
            msg_db, conversation_id, limit=limit, offset=offset, since=since, until=until
        )

        # Enrich with sender names
        for msg in messages:
            sender_id = msg.get("sender_id")
            if sender_id and isinstance(sender_id, int) and sender_id in self._user_map:
                msg["sender_name"] = self._user_map[sender_id]

        return messages

    def search_messages(
        self,
        keyword: str,
        conversation_id: Optional[str] = None,
        limit: int = 50,
    ) -> list[dict]:
        """Search messages by keyword."""
        msg_db = self._get_db_path("message.db")
        if not msg_db:
            return []

        self._ensure_user_map()
        results = search_messages(msg_db, keyword, conversation_id=conversation_id, limit=limit)

        for msg in results:
            sender_id = msg.get("sender_id")
            if sender_id and isinstance(sender_id, int) and sender_id in self._user_map:
                msg["sender_name"] = self._user_map[sender_id]

        return results

    def contacts(
        self,
        keyword: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict]:
        """List contacts."""
        user_db = self._get_db_path("user.db")
        if not user_db:
            return []
        return list_contacts(user_db, keyword=keyword, limit=limit, offset=offset)

    def group_members(self, conversation_id: str) -> dict[int, str]:
        """Get all members, preferring nicknames, then contact names, then IDs."""
        session_db = self._get_db_path("session.db")
        if not session_db:
            return {}
        members = get_group_members(session_db, conversation_id)
        if any(not nickname for nickname in members.values()):
            self._ensure_user_map()
            return {
                uid: nickname or self._user_map.get(uid) or str(uid)
                for uid, nickname in members.items()
            }
        return members

    def session_count(self) -> int:
        """Get total session count."""
        session_db = self._get_db_path("session.db")
        if not session_db:
            return 0
        return get_session_count(session_db)

    def message_count(self, conversation_id: str) -> int:
        """Get message count for a conversation."""
        msg_db = self._get_db_path("message.db")
        if not msg_db:
            return 0
        return get_message_count(msg_db, conversation_id)
