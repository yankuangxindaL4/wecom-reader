"""Build standalone snapshots without writing to the source database or WAL."""

from contextlib import contextmanager
import os
from pathlib import Path
import shutil
import struct
import time

from .crypto.decrypt import PAGE_SZ, decrypt_database, decrypt_page, is_plain_sqlite, verify_key


@contextmanager
def snapshot_lock(directory):
    path = Path(directory) / '.refresh.lock'
    if path.is_symlink():
        raise ValueError('Refusing symlink snapshot lock')
    with path.open('a+b') as stream:
        if os.name == 'nt':
            import msvcrt
            stream.seek(0, 2)
            if stream.tell() == 0:
                stream.write(b'0')
                stream.flush()
            deadline = time.monotonic() + 120
            while True:
                try:
                    stream.seek(0)
                    msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
                    break
                except OSError:
                    if time.monotonic() >= deadline:
                        raise RuntimeError('Timed out waiting for snapshot refresh')
                    time.sleep(0.1)
        else:
            import fcntl
            fcntl.flock(stream, fcntl.LOCK_EX)
        try:
            yield
        finally:
            if os.name == 'nt':
                stream.seek(0)
                msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(stream, fcntl.LOCK_UN)


def fingerprints(source):
    result = {}
    for root, directories, files in os.walk(source):
        directories[:] = [d for d in directories if d != '-journal']
        for name in sorted(files):
            if not name.endswith('.db'):
                continue
            path = Path(root) / name
            stats = []
            for part in (path, Path(str(path) + '-wal')):
                try:
                    stat = part.stat()
                    stats.append([stat.st_mtime_ns, stat.st_size])
                except FileNotFoundError:
                    stats.append(None)
            result[str(path.relative_to(source))] = stats
    return result


def checksum(data, endian, state=(0, 0)):
    s0, s1 = state
    for a, b in struct.iter_unpack(endian + 'II', data):
        s0 = (s0 + a + s1) & 0xffffffff
        s1 = (s1 + b + s0) & 0xffffffff
    return s0, s1


def apply_wal(wal_path, output, key):
    """Replay checksum-valid frames through the final commit (SQLite WAL format)."""
    if not wal_path.exists() or wal_path.stat().st_size == 0:
        return
    with wal_path.open('rb') as stream:
        header = stream.read(32)
        if len(header) != 32:
            raise RuntimeError('Incomplete WAL header; retry refresh')
        magic, version, size, _, salt1, salt2, c0, c1 = struct.unpack('>8I', header)
        if magic not in (0x377f0682, 0x377f0683) or version != 3007000 or size != PAGE_SZ:
            raise RuntimeError('Unsupported WAL format')
        endian = '<' if magic == 0x377f0682 else '>'
        state = checksum(header[:24], endian)
        if state != (c0, c1):
            raise RuntimeError('Invalid WAL header checksum')
        committed = {}
        pending = {}
        database_size = None
        while True:
            offset = stream.tell()
            frame = stream.read(24)
            page = stream.read(size) if len(frame) == 24 else b''
            if len(frame) != 24 or len(page) != size:
                break  # An incomplete tail is not a committed transaction.
            number, commit, s1, s2, c0, c1 = struct.unpack('>6I', frame)
            if (s1, s2) != (salt1, salt2):
                break  # Old frames left behind when SQLite reuses the WAL.
            state = checksum(frame[:8] + page, endian, state)
            if state != (c0, c1) or number == 0:
                if key and offset == 32:
                    raise RuntimeError('Unsupported or damaged encrypted WAL; snapshot was preserved')
                break
            pending[number] = offset + 24
            if commit:
                committed.update(pending)
                pending.clear()
                database_size = commit
                committed = {n: off for n, off in committed.items() if n <= commit}
        if database_size is not None:
            with open(output, 'r+b') as target:
                for number, offset in committed.items():
                    stream.seek(offset)
                    page = stream.read(size)
                    target.seek((number - 1) * size)
                    target.write(decrypt_page(key, page, number) if key else page)
                target.truncate(database_size * size)


def build_database(source, output, keys):
    with open(source, 'rb') as stream:
        page = stream.read(PAGE_SZ)
    output.parent.mkdir(parents=True, exist_ok=True)
    key = None
    if is_plain_sqlite(page):
        shutil.copyfile(source, output)
    else:
        key = next((k for k in keys if verify_key(k, page)), None)
        if key is None:
            raise RuntimeError(f'No valid cached key for {source.name}; run init')
        decrypt_database(str(source), str(output), key)
    apply_wal(Path(str(source) + '-wal'), output, key)
    return 'decrypted' if key else 'copied'


@contextmanager
def publish_files(staging, output, changed, removed):
    """Restore old files if publishing any database or its metadata fails."""
    import tempfile
    from .storage import owner, private_directory

    applied = []
    uid, gid, _ = owner()
    with tempfile.TemporaryDirectory(prefix='.rollback-', dir=output) as temporary:
        backup = Path(temporary)
        for name in set(changed) | set(removed):
            target = output / name
            if output.resolve() not in target.resolve().parents or target.is_symlink():
                raise RuntimeError('Snapshot path escapes output directory or is a symlink')
            private_directory(target.parent)
            if target.exists():
                saved = backup / name
                saved.parent.mkdir(parents=True, exist_ok=True)
                try:
                    os.link(target, saved)
                except OSError:
                    shutil.copy2(target, saved)
        try:
            for name in changed:
                if uid is not None:
                    os.chown(staging / name, uid, gid)
                os.replace(staging / name, output / name)
                applied.append(name)
            for name in removed:
                (output / name).unlink(missing_ok=True)
                applied.append(name)
            yield
        except BaseException:
            for name in reversed(applied):
                saved = backup / name
                if saved.exists():
                    os.replace(saved, output / name)
                else:
                    (output / name).unlink(missing_ok=True)
            raise
