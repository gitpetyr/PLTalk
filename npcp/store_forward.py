"""
Store-and-forward service for offline message relay.

When enabled, nodes store encrypted (opaque) packets for offline peers
and deliver them when those peers come back online.

All stored data is ciphertext — this node cannot read its content.
"""
import json
import logging
import os
import sqlite3
import time
from typing import List, Optional

logger = logging.getLogger(__name__)


class StoreAndForward:
    def __init__(self, db_path: str, enabled: bool = False):
        self.enabled  = enabled
        self._db_path = db_path
        self._conn    = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._create_table()

    def _create_table(self):
        self._conn.execute("""
            CREATE TABLE IF NOT EXISTS stored_packets (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                receiver_id TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                stored_at   INTEGER NOT NULL,
                ttl_seconds INTEGER NOT NULL DEFAULT 86400
            )
        """)
        self._conn.commit()

    def store(self, receiver_id: str, packet: dict, ttl_seconds: int = 86400):
        if not self.enabled:
            return
        self._conn.execute("""
            INSERT INTO stored_packets (receiver_id, payload_json, stored_at, ttl_seconds)
            VALUES (?, ?, ?, ?)
        """, (receiver_id, json.dumps(packet), int(time.time()), ttl_seconds))
        self._conn.commit()
        logger.debug("Stored packet for offline peer %s", receiver_id)

    def retrieve(self, receiver_id: str) -> List[dict]:
        """Fetch and delete all stored packets for a receiver."""
        now = int(time.time())
        cur = self._conn.execute("""
            SELECT id, payload_json, stored_at, ttl_seconds
            FROM stored_packets
            WHERE receiver_id = ?
        """, (receiver_id,))
        rows = cur.fetchall()
        result = []
        expired_ids = []
        valid_ids   = []
        for row in rows:
            if now - row["stored_at"] > row["ttl_seconds"]:
                expired_ids.append(row["id"])
            else:
                result.append(json.loads(row["payload_json"]))
                valid_ids.append(row["id"])
        all_ids = expired_ids + valid_ids
        if all_ids:
            placeholders = ",".join("?" * len(all_ids))
            self._conn.execute(f"DELETE FROM stored_packets WHERE id IN ({placeholders})", all_ids)
            self._conn.commit()
        return result

    def purge_expired(self):
        now = int(time.time())
        self._conn.execute("""
            DELETE FROM stored_packets
            WHERE (stored_at + ttl_seconds) < ?
        """, (now,))
        self._conn.commit()

    def close(self):
        self._conn.close()
