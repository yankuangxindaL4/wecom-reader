"""User-owned paths, account discovery and private atomic JSON storage."""

import csv
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile


def owner():
    """Only trust sudo identity when actually running as root."""
    if os.name == 'posix' and os.geteuid() == 0 and os.environ.get('SUDO_UID'):
        import pwd
        user = pwd.getpwuid(int(os.environ['SUDO_UID']))
        return user.pw_uid, user.pw_gid, Path(user.pw_dir)
    return None, None, Path.home()


def default_root(kind):
    uid, _, home = owner()
    if os.name == 'nt':
        base = Path(os.environ.get('LOCALAPPDATA') or home / 'AppData/Local')
        return base / 'wecom-reader' / kind
    variable = 'XDG_CACHE_HOME' if kind == 'cache' else 'XDG_DATA_HOME'
    value = os.environ.get(variable, '')
    # sudo may supply root's XDG paths; always use the invoking user's home.
    base = Path(value) if uid is None and os.path.isabs(value) else home / ('.cache' if kind == 'cache' else '.local/share')
    return base / 'wecom-reader'


def key_directory():
    return Path(os.environ.get('WXWORK_KEY_DIR') or default_root('cache') / 'keys').expanduser().resolve()


def account_id(source):
    return hashlib.sha256(os.path.normcase(os.path.realpath(source)).encode()).hexdigest()[:24]


def private_directory(path):
    path = Path(path)
    if path.is_symlink():
        raise ValueError(f'Refusing symlink directory: {path}')
    missing = []
    parent = path
    while not parent.exists():
        missing.append(parent)
        parent = parent.parent
    uid, gid, _ = owner()
    for directory in reversed(missing):
        directory.mkdir(mode=0o700, exist_ok=True)
        if uid is not None:
            os.chown(directory, uid, gid)
    if os.name == 'nt':
        result = subprocess.run(['whoami', '/user', '/fo', 'csv', '/nh'],
                                check=True, capture_output=True, text=True)
        sid = next(csv.reader(io.StringIO(result.stdout.strip())))[1]
        subprocess.run(['icacls', str(path), '/inheritance:r', '/grant:r', f'*{sid}:(OI)(CI)F'],
                       check=True, capture_output=True)
    else:
        path.chmod(0o700)
        if uid is not None:
            os.chown(path, uid, gid)


def read_json(path):
    path = Path(path)
    if path.is_symlink():
        raise ValueError(f'Refusing symlink file: {path}')
    try:
        with path.open(encoding='utf-8') as stream:
            value = json.load(stream)
    except FileNotFoundError:
        return {}
    except (ValueError, UnicodeError):
        raise RuntimeError(f'Invalid metadata file: {path}') from None
    if not isinstance(value, dict) or value.get('version') != 1:
        raise RuntimeError(f'Unsupported metadata file: {path}')
    return value


def write_json(path, value):
    path = Path(path)
    private_directory(path.parent)
    descriptor, temporary = tempfile.mkstemp(prefix='.pending-', dir=path.parent)
    try:
        with os.fdopen(descriptor, 'w', encoding='utf-8') as stream:
            json.dump({'version': 1, **value}, stream, ensure_ascii=False)
            stream.flush()
            os.fsync(stream.fileno())
        uid, gid, _ = owner()
        if uid is not None:
            os.chown(temporary, uid, gid)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def activity(source):
    source = Path(source)
    times = [p.stat().st_mtime_ns for p in (source / 'session.db', source / 'session.db-wal') if p.is_file()]
    if not times:
        times = [p.stat().st_mtime_ns for p in source.glob('*.db') if p.is_file()]
    return max(times, default=0)


def accounts(key_dir):
    """Discover local accounts plus explicitly initialized source directories."""
    _, _, home = owner()
    profile = Path(os.environ.get('USERPROFILE') or home)
    sources = {str(p.resolve()) for p in (profile / 'Documents/WXWork').glob('*/Data') if p.is_dir()}
    for path in Path(key_dir).glob('*.json'):
        record = read_json(path)
        source = record.get('db_dir')
        if isinstance(source, str):
            sources.add(os.path.realpath(source))
    return [{'account': account_id(p), 'db_dir': p, 'activity': activity(p)} for p in sources]


def select_source(db_dir, key_dir, account=None):
    if db_dir:
        source = os.path.realpath(os.path.expanduser(db_dir))
        if account and account != account_id(source):
            raise ValueError('--account does not match --db-dir')
        return source
    candidates = accounts(key_dir)
    if account:
        candidates = [r for r in candidates if r['account'] == account]
        if not candidates:
            raise ValueError('Unknown account; run status to list accounts')
    else:
        candidates = [r for r in candidates if os.path.isdir(r['db_dir'])]
    selected = max(candidates, key=lambda r: (r['activity'], r['account']), default=None)
    return selected['db_dir'] if selected else None
