"""Database access layer for decrypted WeCom databases."""

from pathlib import Path
import sqlite3


def connect_readonly(db_path: str) -> sqlite3.Connection:
    """Open a decrypted snapshot without creating WAL/SHM files or taking locks.

    Decrypted .db files retain the original WAL-mode header but are standalone
    snapshots. They may be owned by root after key extraction with sudo.
    This connection is only for snapshots, not a live WeCom database; close it
    before replacing or refreshing the snapshot.
    """
    uri = Path(db_path).resolve().as_uri() + "?mode=ro&immutable=1"
    return sqlite3.connect(uri, uri=True)
