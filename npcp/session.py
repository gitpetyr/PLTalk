"""
Session management and X3DH handshake coordination.

Session lifecycle:
  1. Initiator sends HANDSHAKE packet with ephemeral X25519 public key.
  2. Responder derives shared secret, replies with own ephemeral key.
  3. Both sides derive the same AES-256-GCM session key.
  4. session_id = SHA256(init_nonce | resp_nonce | init_id | resp_id)
"""
import hashlib
import os
import time
from dataclasses import dataclass, field
from typing import Dict, Optional

from . import crypto


def _make_session_id(initiator_nonce: bytes, responder_nonce: bytes,
                     initiator_id: str, responder_id: str) -> str:
    raw = (initiator_nonce + responder_nonce
           + initiator_id.encode() + responder_id.encode())
    return hashlib.sha256(raw).hexdigest()


@dataclass
class Session:
    session_id:   str
    peer_id:      str
    shared_key:   bytes          # 32-byte AES key
    prev_hash:    str = "0" * 64
    msg_counter:  int = 0
    created_at:   float = field(default_factory=time.time)
    is_group:     bool = False
    group_id:     str = ""


class SessionManager:
    def __init__(self,
                 my_node_id: str,
                 my_ik_priv: "crypto.X25519PrivateKey",
                 my_ik_pub: "crypto.X25519PublicKey",
                 my_spk_priv: "crypto.X25519PrivateKey",
                 my_spk_pub: "crypto.X25519PublicKey"):
        self.my_node_id  = my_node_id
        self.my_ik_priv  = my_ik_priv
        self.my_ik_pub   = my_ik_pub
        self.my_spk_priv = my_spk_priv
        self.my_spk_pub  = my_spk_pub

        self._sessions: Dict[str, Session] = {}  # session_id → Session
        self._peer_sessions: Dict[str, str] = {} # peer_id → session_id

    # ── Initiator ─────────────────────────────────────────────────────────────

    def initiate_session(self, peer_id: str,
                         their_ik_pub: "crypto.X25519PublicKey",
                         their_spk_pub: "crypto.X25519PublicKey") -> tuple:
        """
        Returns (session, init_nonce, ek_pub_hex) for sending in HANDSHAKE.
        """
        ek_priv, ek_pub = crypto.generate_x25519_keypair()
        init_nonce = os.urandom(16)

        shared_secret = crypto.x3dh_initiator(
            my_ik_priv   = self.my_ik_priv,
            my_ek_priv   = ek_priv,
            their_ik_pub = their_ik_pub,
            their_spk_pub= their_spk_pub,
        )

        # Temporary session_id; responder fills in resp_nonce later
        tmp_sid = _make_session_id(init_nonce, b"\x00" * 16,
                                   self.my_node_id, peer_id)
        sess = Session(
            session_id  = tmp_sid,
            peer_id     = peer_id,
            shared_key  = shared_secret,
        )
        self._sessions[tmp_sid] = sess
        self._peer_sessions[peer_id] = tmp_sid

        ek_pub_hex = crypto.serialize_x25519_public(ek_pub).hex()
        return sess, init_nonce, ek_pub_hex

    def finalize_session_initiator(self, peer_id: str,
                                   init_nonce: bytes, resp_nonce: bytes) -> Session:
        """Call after receiving responder's nonce to finalize session_id."""
        old_sid = self._peer_sessions.get(peer_id)
        sess = self._sessions.pop(old_sid, None)
        if not sess:
            raise ValueError(f"No pending session for {peer_id}")

        new_sid = _make_session_id(init_nonce, resp_nonce,
                                   self.my_node_id, peer_id)
        sess.session_id = new_sid
        self._sessions[new_sid] = sess
        self._peer_sessions[peer_id] = new_sid
        return sess

    # ── Responder ─────────────────────────────────────────────────────────────

    def respond_to_handshake(self, peer_id: str,
                             their_ik_pub: "crypto.X25519PublicKey",
                             their_ek_pub: "crypto.X25519PublicKey",
                             init_nonce: bytes) -> tuple:
        """
        Returns (session, resp_nonce).
        """
        resp_nonce = os.urandom(16)
        shared_secret = crypto.x3dh_responder(
            my_ik_priv  = self.my_ik_priv,
            my_spk_priv = self.my_spk_priv,
            their_ik_pub= their_ik_pub,
            their_ek_pub= their_ek_pub,
        )
        sid = _make_session_id(init_nonce, resp_nonce, peer_id, self.my_node_id)
        sess = Session(
            session_id = sid,
            peer_id    = peer_id,
            shared_key = shared_secret,
        )
        self._sessions[sid] = sess
        self._peer_sessions[peer_id] = sid
        return sess, resp_nonce

    # ── Encryption helpers ────────────────────────────────────────────────────

    def encrypt_message(self, session: Session, plaintext: bytes) -> tuple:
        """Returns (payload_b64, prev_hash)."""
        ct, nonce = crypto.aes_gcm_encrypt(session.shared_key, plaintext)
        payload_b64 = crypto.encode_payload(ct, nonce)
        prev_hash = session.prev_hash
        return payload_b64, prev_hash

    def decrypt_message(self, session: Session, payload_b64: str) -> bytes:
        ct, nonce = crypto.decode_payload(payload_b64)
        return crypto.aes_gcm_decrypt(session.shared_key, ct, nonce)

    def update_hash_chain(self, session: Session, new_hash: str):
        session.prev_hash = new_hash
        session.msg_counter += 1

    # ── Lookup ────────────────────────────────────────────────────────────────

    def get_session(self, session_id: str) -> Optional[Session]:
        return self._sessions.get(session_id)

    def get_session_for_peer(self, peer_id: str) -> Optional[Session]:
        sid = self._peer_sessions.get(peer_id)
        return self._sessions.get(sid) if sid else None

    def has_session(self, peer_id: str) -> bool:
        return peer_id in self._peer_sessions

    def create_group_session(self, group_id: str, shared_key: bytes) -> Session:
        """Simple shared group key (pre-agreed, not full MLS)."""
        sid = hashlib.sha256(group_id.encode()).hexdigest()
        sess = Session(
            session_id = sid,
            peer_id    = group_id,
            shared_key = shared_key,
            is_group   = True,
            group_id   = group_id,
        )
        self._sessions[sid] = sess
        self._peer_sessions[group_id] = sid
        return sess
