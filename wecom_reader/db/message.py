"""Message (消息) queries for decrypted WeCom databases.

Actual schema (from decrypted message.db):
  message_table: message_id, server_id, sequence, sender_id, conversation_id,
                 content_type, send_time, flag, content, devinfo, from_app_id,
                 msg_from_devinfo, extra_content, local_extra_content, client_id, ...
  message_small_table: same schema
  kf_message_tableV1: same schema (客服消息)
"""

import re
import sqlite3
from typing import Optional

from . import connect_readonly

# Emoji bases, including supplementary symbols, flags and skin-tone modifiers.
_EMOJI_CHARS = (
    "\u00a9\u00ae\u203c\u2049\u2122\u2139\u2190-\u21ff"
    "\u2300-\u23ff\u24c2\u25a0-\u27bf\u2934-\u2935\u2b00-\u2bff"
    "\u3030\u303d\u3297\u3299\U0001f000-\U0001faff"
)

MESSAGE_TABLES = ("message_table", "message_small_table", "kf_message_tableV1")

MSG_TYPES = {
    0: "text",
    2: "text",
    4: "image",
    7: "voice",
    15: "image/file",
    38: "app_message",
    40: "call",
    503: "status",
    1011: "meeting",
}


def _table_exists(conn: sqlite3.Connection, table: str) -> bool:
    row = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)
    ).fetchone()
    return row is not None


def _parse_content(raw) -> str:
    """Parse message content, handling binary/protobuf data.

    WeCom message content is protobuf-encoded. The actual text is typically
    embedded as a length-delimited string after field tags like 0x12.
    We try multiple strategies to extract readable text.
    """
    if raw is None:
        return ""
    if isinstance(raw, str):
        return raw.strip()
    if isinstance(raw, bytes):
        # Strategy 1: Extract readable UTF-8 runs, preserving emoji sequences.
        try:
            s = raw.decode("utf-8", errors="ignore")
            # Keep emoji bases plus variation selectors, joiners and keycap marks.
            chunks = re.findall(
                r"[\u4e00-\u9fff\u3000-\u303f\uff00-\uffef"
                r"a-zA-Z0-9#*" + _EMOJI_CHARS + r"]"
                r"[\u4e00-\u9fff\u3000-\u303f\uff00-\uffef"
                + _EMOJI_CHARS + r"\u200d\ufe0e\ufe0f\u20e3"
                r'a-zA-Z0-9 .,;:!?，。！？、；：\u2018\u2019\u201c\u201d（）【】《》\\-_/\\@#*\n\r\t]*',
                s,
            )
            # Single-character replies such as "1" or "好" are valid content.
            texts = [c.strip() for c in chunks if c.strip()]
            if texts:
                # Join consecutive text fragments
                result = " ".join(texts)
                # Clean up: remove leading garbage bytes
                result = re.sub(r"^[\x00-\x1f]{1,10}", "", result)
                if result.strip():
                    return result.strip()
        except (UnicodeDecodeError, ValueError):
            pass

        # Strategy 2: Try latin1 decode (preserves all bytes)
        try:
            s = raw.decode("latin1")
            chunks = re.findall(
                r"[\u4e00-\u9fff]|[a-zA-Z0-9 .,;:!?]+",
                s,
            )
            texts = [c.strip() for c in chunks if len(c.strip()) >= 3]
            if texts:
                return " ".join(texts)
        except Exception:
            pass

        return f"[binary {len(raw)} bytes]"
    return str(raw).strip()


def get_messages(
    db_path: str,
    conversation_id: str,
    limit: int = 50,
    offset: int = 0,
    since: Optional[int] = None,
    until: Optional[int] = None,
    msg_type: Optional[int] = None,
) -> list[dict]:
    """Get messages for a specific conversation.

    Uses actual column names from decrypted WeCom schema:
      sender_id, conversation_id, content_type, send_time, content, message_id, server_id
    """
    conn = connect_readonly(db_path)
    conn.row_factory = sqlite3.Row
    try:
        queries = []
        all_params = []
        for table in MESSAGE_TABLES:
            if not _table_exists(conn, table):
                continue

            # Use explicit column names matching actual schema
            query = (
                f'SELECT message_id, server_id, sequence, sender_id, conversation_id, '
                f'content_type, send_time, flag, content, from_app_id '
                f'FROM "{table}" WHERE conversation_id = ?'
            )

            params: list = [conversation_id]

            if since is not None:
                query += " AND send_time >= ?"
                params.append(since)
            if until is not None:
                query += " AND send_time < ?"
                params.append(until)
            if msg_type is not None:
                query += " AND content_type = ?"
                params.append(msg_type)

            queries.append(query)
            all_params.extend(params)

        if not queries:
            return []

        # Merge matching rows before applying the offset once across all tables.
        query = " UNION ALL ".join(queries) + " ORDER BY sequence DESC LIMIT ? OFFSET ?"
        all_params.extend([limit, offset])
        messages = []
        for row in conn.execute(query, all_params):
            ct = row["content_type"]
            msg = {
                "message_id": row["message_id"],
                "server_id": row["server_id"],
                "sequence": row["sequence"],
                "sender_id": row["sender_id"],
                "conversation_id": row["conversation_id"],
                "content_type": ct,
                "type_name": MSG_TYPES.get(ct, f"type_{ct}"),
                "send_time": row["send_time"],
                "flag": row["flag"],
                "content": _parse_content(row["content"]),
                "from_app_id": row["from_app_id"],
            }
            messages.append(msg)

        return messages
    finally:
        conn.close()


def search_messages(
    db_path: str,
    keyword: str,
    conversation_id: Optional[str] = None,
    limit: int = 50,
) -> list[dict]:
    """Search TEXT or BLOB content for a literal substring, ignoring ASCII case."""
    conn = connect_readonly(db_path)
    conn.row_factory = sqlite3.Row
    try:
        messages = []
        for table in MESSAGE_TABLES:
            if not _table_exists(conn, table):
                continue

            # WeCom stores protobuf payloads as BLOBs. LIKE may never match a
            # BLOB, and even CAST(... AS TEXT) LIKE stops at an embedded NUL.
            # instr handles NULs and treats '%' and '_' as literal characters.
            query = (
                f'SELECT message_id, server_id, sequence, sender_id, conversation_id, '
                f'content_type, send_time, flag, content '
                f'FROM "{table}" WHERE instr(lower(CAST(content AS TEXT)), lower(?)) > 0'
            )
            params: list = [keyword]

            if conversation_id:
                query += " AND conversation_id = ?"
                params.append(conversation_id)

            query += " ORDER BY sequence DESC LIMIT ?"
            params.append(limit)

            for row in conn.execute(query, params):
                ct = row["content_type"]
                messages.append({
                    "message_id": row["message_id"],
                    "server_id": row["server_id"],
                    "sequence": row["sequence"],
                    "sender_id": row["sender_id"],
                    "conversation_id": row["conversation_id"],
                    "content_type": ct,
                    "type_name": MSG_TYPES.get(ct, f"type_{ct}"),
                    "send_time": row["send_time"],
                    "flag": row["flag"],
                    "content": _parse_content(row["content"]),
                })

        messages.sort(key=lambda m: m.get("sequence", 0), reverse=True)
        return messages[:limit]
    finally:
        conn.close()


def get_message_count(db_path: str, conversation_id: str) -> int:
    """Get total message count for a conversation."""
    conn = connect_readonly(db_path)
    try:
        total = 0
        for table in MESSAGE_TABLES:
            if not _table_exists(conn, table):
                continue
            row = conn.execute(
                f'SELECT COUNT(*) FROM "{table}" WHERE conversation_id = ?',
                (conversation_id,),
            ).fetchone()
            total += row[0] if row else 0
        return total
    finally:
        conn.close()
