"""
Append-only DAG ledger backed by SQLite.

Stores:
  - nodes    : (node_id, public_key_hex, alias, x25519_ik_hex, x25519_spk_hex, first_seen)
  - trust_sigs: cross-signatures between nodes
  - msg_hashes: hash-chain of messages (no plaintext/ciphertext)

NO plaintext or ciphertext is ever written to this database.
"""
import sqlite3
import time
from typing import Dict, List, Optional


class Ledger:
    def __init__(self, db_path: str):
        self.db_path = db_path
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._create_tables()

    def _create_tables(self):
        cur = self._conn.cursor()
        cur.executescript("""
        CREATE TABLE IF NOT EXISTS nodes (
            node_id        TEXT PRIMARY KEY,
            public_key_hex TEXT NOT NULL,
            alias          TEXT,
            x25519_ik_hex  TEXT,
            x25519_spk_hex TEXT,
            first_seen     INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS trust_sigs (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            signer_id   TEXT NOT NULL,
            target_id   TEXT NOT NULL,
            signature   TEXT NOT NULL,
            timestamp   INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS msg_hashes (
            msg_id       TEXT PRIMARY KEY,
            sender_id    TEXT NOT NULL,
            receiver_id  TEXT NOT NULL,
            session_id   TEXT NOT NULL,
            prev_hash    TEXT,
            content_hash TEXT NOT NULL,
            timestamp    INTEGER NOT NULL
        );
        """)
        self._conn.commit()

    # ── Node registry ─────────────────────────────────────────────────────────

    def add_or_update_node(
        self,
        node_id: str,
        public_key_hex: str,
        alias: str = "",
        x25519_ik_hex: str = "",
        x25519_spk_hex: str = "",
    ):
        cur = self._conn.cursor()
        cur.execute("""
            INSERT INTO nodes (node_id, public_key_hex, alias, x25519_ik_hex, x25519_spk_hex, first_seen)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(node_id) DO UPDATE SET
                alias          = excluded.alias,
                x25519_ik_hex  = excluded.x25519_ik_hex,
                x25519_spk_hex = excluded.x25519_spk_hex
        """, (node_id, public_key_hex, alias, x25519_ik_hex, x25519_spk_hex, int(time.time())))
        self._conn.commit()

    def get_node(self, node_id: str) -> Optional[Dict]:
        cur = self._conn.cursor()
        cur.execute("SELECT * FROM nodes WHERE node_id = ?", (node_id,))
        row = cur.fetchone()
        return dict(row) if row else None

    def get_all_nodes(self) -> List[Dict]:
        cur = self._conn.cursor()
        cur.execute("SELECT * FROM nodes ORDER BY first_seen DESC")
        return [dict(r) for r in cur.fetchall()]

    def get_public_key_hex(self, node_id: str) -> Optional[str]:
        node = self.get_node(node_id)
        return node["public_key_hex"] if node else None

    # ── Trust signatures ──────────────────────────────────────────────────────

    def add_trust_sig(self, signer_id: str, target_id: str, signature: str):
        cur = self._conn.cursor()
        cur.execute("""
            INSERT INTO trust_sigs (signer_id, target_id, signature, timestamp)
            VALUES (?, ?, ?, ?)
        """, (signer_id, target_id, signature, int(time.time())))
        self._conn.commit()

    def get_trust_sigs_for(self, target_id: str) -> List[Dict]:
        cur = self._conn.cursor()
        cur.execute("SELECT * FROM trust_sigs WHERE target_id = ?", (target_id,))
        return [dict(r) for r in cur.fetchall()]

    # ── Message hash chain ────────────────────────────────────────────────────

    def add_message_hash(
        self,
        msg_id: str,
        sender_id: str,
        receiver_id: str,
        session_id: str,
        prev_hash: str,
        content_hash: str,
    ):
        cur = self._conn.cursor()
        cur.execute("""
            INSERT OR IGNORE INTO msg_hashes
            (msg_id, sender_id, receiver_id, session_id, prev_hash, content_hash, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (msg_id, sender_id, receiver_id, session_id, prev_hash, content_hash, int(time.time())))
        self._conn.commit()

    def get_last_hash(self, session_id: str) -> str:
        """Return the most recent content_hash for a session (for hash-chaining)."""
        cur = self._conn.cursor()
        cur.execute("""
            SELECT content_hash FROM msg_hashes
            WHERE session_id = ?
            ORDER BY timestamp DESC LIMIT 1
        """, (session_id,))
        row = cur.fetchone()
        return row["content_hash"] if row else "0" * 64

    def close(self):
        self._conn.close()
