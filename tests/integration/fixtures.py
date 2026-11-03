"""Independent input fixtures. No imports from the application under test."""
from contextlib import closing
import hashlib
from pathlib import Path
import sqlite3
import struct

from Cryptodome.Cipher import AES


def encrypt_database(plain, key):
    """Encode the documented wxSQLite3 AES-128 format, independently of the reader."""
    result = bytearray()
    assert len(plain) % 4096 == 0
    for offset in range(0, len(plain), 4096):
        number = offset // 4096 + 1
        state = number + 1
        seed = bytearray()
        for _ in range(4):
            quotient = state // 52774
            state = 40692 * (state - 52774 * quotient) - 3791 * quotient
            if state < 0:
                state += 2147483399
            seed.extend(struct.pack('<I', state))
        iv = hashlib.md5(seed).digest()
        page_key = hashlib.md5(key + struct.pack('<I', number) + b'sAlT').digest()
        cipher = AES.new(page_key, AES.MODE_CBC, iv)
        page = plain[offset:offset + 4096]
        if number == 1:
            tail = cipher.encrypt(page[16:])
            result.extend(b'fixture!' + tail[:8] + page[16:24] + tail[8:])
        else:
            result.extend(cipher.encrypt(page))
    return bytes(result)


def make_database(path, sql):
    with closing(sqlite3.connect(path)) as conn:
        conn.execute('PRAGMA page_size=4096')
        conn.execute('PRAGMA journal_mode=WAL')
        conn.executescript(sql)
        conn.commit()
        conn.execute('PRAGMA wal_checkpoint(TRUNCATE)')
    return path.read_bytes()


def create_source(root, key):
    """Return encrypted inputs and byte-for-byte expected standalone snapshots."""
    source = root / 'Data'
    source.mkdir()
    plain_dir = root / 'fixture originals'
    plain_dir.mkdir()
    schema = '''(message_id INTEGER, server_id INTEGER, sequence INTEGER,
        sender_id INTEGER, conversation_id TEXT, content_type INTEGER,
        send_time INTEGER, flag INTEGER, content BLOB, from_app_id INTEGER)'''
    message_path = plain_dir / 'message.db'
    with closing(sqlite3.connect(message_path)) as conn:
        conn.execute('PRAGMA page_size=4096')
        conn.execute('PRAGMA journal_mode=WAL')
        for table, sequences in [('message_table', [100, 90, 80]),
                                 ('message_small_table', [95, 85, 75]),
                                 ('kf_message_tableV1', [70])]:
            conn.execute(f'CREATE TABLE {table} {schema}')
            for sequence in sequences:
                conn.execute(f'INSERT INTO {table} VALUES (?,0,?,2,\'R:1\',0,?,0,?,0)',
                             (sequence, sequence, sequence, b'\x08\x00\x12\x07Hello 1'))
        extras = [(60, b'\x0a\x011'), (50, b'\x08\x00\x12\x06' + '中文'.encode()),
                  (40, b'100% complete'), (30, b'under_score'), (20, None), (10, b'')]
        for sequence, content in extras:
            conn.execute('INSERT INTO message_table VALUES (?,0,?,2,\'R:1\',0,?,0,?,0)',
                         (sequence, sequence, sequence, content))
        conn.execute("INSERT INTO message_table VALUES (999,0,999,2,'R:2',0,999,0,'other room',0)")
        conn.commit()
        conn.execute('PRAGMA wal_checkpoint(TRUNCATE)')
    session = make_database(plain_dir / 'session.db', '''
        CREATE TABLE conversation_table(id TEXT,name TEXT,roomname_remark TEXT,
            last_message_time INTEGER,last_message_id INTEGER);
        INSERT INTO conversation_table VALUES ('R:1','Test room','',100,100),('S:2','Other','',50,50);
        CREATE TABLE conversation_user_table(conversation_id TEXT,user_id INTEGER,nick_name TEXT);
        INSERT INTO conversation_user_table VALUES ('R:1',1,'Group nickname'),('R:1',2,''),
            ('R:1',3,NULL),('R:1',4,''),('R:2',5,'Elsewhere');
    ''')
    users = make_database(plain_dir / 'user.db', '''
        CREATE TABLE user_table(id INTEGER,name TEXT,real_name TEXT,account TEXT,
            external_corp_name TEXT,external_job TEXT);
        INSERT INTO user_table VALUES (1,'match A','','','',''),(2,'Contact two','','','','');
        CREATE TABLE external_user_relation_v3(user_id INTEGER,remarks TEXT,real_remarks TEXT,corp_remark TEXT);
        INSERT INTO external_user_relation_v3 VALUES (3,'match C','',''),(1,'Duplicate A','',''),
            (3,'Duplicate C','',''),(5,'match E','','');
    ''')
    plain = make_database(plain_dir / 'plain.db', 'CREATE TABLE records(value TEXT); INSERT INTO records VALUES (\'plain copy\');')
    expected = {'message.db': message_path.read_bytes(), 'session.db': session, 'user.db': users, 'plain.db': plain}
    for name, data in expected.items():
        (source / name).write_bytes(data if name == 'plain.db' else encrypt_database(data, key))
    return source, expected


def fingerprints(directory):
    return {str(p.relative_to(directory)): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in Path(directory).rglob('*') if p.is_file()}
