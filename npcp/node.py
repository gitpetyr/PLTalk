"""
Node — top-level orchestrator for the NPCP protocol stack.

Manages:
  - Identity keypair persistence
  - Discovery (UDP broadcast)
  - Transport (TCP)
  - Sessions (X3DH handshake + AES-GCM)
  - Ledger (SQLite DAG)
  - Store-and-forward
  - Event dispatching to the UI layer
"""
import base64
import hashlib
import json
import logging
import os
import threading
import time
import uuid
from typing import Callable, Dict, List, Optional

from . import crypto
from .config import Config
from .discovery import Discovery
from .ledger import Ledger
from .packet import (
    MsgType, build_packet, deserialize, packet_content_hash, parse_hello_payload,
    serialize, validate_packet, build_hello_payload,
)
from .session import Session, SessionManager
from .store_forward import StoreAndForward

logger = logging.getLogger(__name__)

_CHUNK_SIZE = 60 * 1024  # 60 KB per file chunk


class Node:
    def __init__(self, config: Config):
        self.config = config
        self._event_listeners: Dict[str, List[Callable]] = {}

        # ── Identity ──────────────────────────────────────────────────────────
        self._ed_priv, self._ed_pub = self._load_or_generate_identity()
        self.node_id = crypto.node_id_from_pubkey(self._ed_pub)

        # ── X25519 keys (for X3DH) ────────────────────────────────────────────
        self._x_ik_priv, self._x_ik_pub     = self._load_or_generate_x25519("x_ik")
        self._x_spk_priv, self._x_spk_pub   = self._load_or_generate_x25519("x_spk")

        pub_hex    = crypto.serialize_public_key(self._ed_pub).hex()
        ik_hex     = crypto.serialize_x25519_public(self._x_ik_pub).hex()
        spk_hex    = crypto.serialize_x25519_public(self._x_spk_pub).hex()

        # ── Sub-systems ───────────────────────────────────────────────────────
        self._ledger = Ledger(config.ledger_storage_path)
        self._ledger.add_or_update_node(
            self.node_id, pub_hex, config.node_alias, ik_hex, spk_hex
        )

        sf_path = os.path.join(os.path.dirname(config.ledger_storage_path), "store_fwd.db")
        self._sf = StoreAndForward(sf_path, config.enable_store_and_forward)

        self._session_mgr = SessionManager(
            my_node_id  = self.node_id,
            my_ik_priv  = self._x_ik_priv,
            my_ik_pub   = self._x_ik_pub,
            my_spk_priv = self._x_spk_priv,
            my_spk_pub  = self._x_spk_pub,
        )

        from .transport import Transport
        self._transport = Transport(port=config.tcp_listen_port)
        self._transport.add_listener(self._on_packet_received)

        self._discovery = Discovery(
            config         = config,
            node_id        = self.node_id,
            public_key_hex = pub_hex,
            x25519_ik_hex  = ik_hex,
            x25519_spk_hex = spk_hex,
        )
        self._discovery.add_listener(self._on_peer_discovered)

        # Pending handshake state: peer_id → (init_nonce, ek_priv)
        self._pending_hs: Dict[str, tuple] = {}
        self._hs_lock = threading.Lock()

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    def start(self):
        self._transport.start()
        self.config.tcp_listen_port = self._transport.port
        self._discovery.start()
        logger.info("Node %s started on TCP %d", self.node_id[:16], self._transport.port)

    def stop(self):
        self._discovery.stop()
        self._transport.stop()
        self._ledger.close()
        self._sf.close()
        logger.info("Node stopped")

    # ── Identity persistence ──────────────────────────────────────────────────

    def _key_path(self, name: str) -> str:
        return os.path.join(self.config.profile_dir, f"{name}.key")

    def _load_or_generate_identity(self):
        path = self._key_path("ed25519")
        if os.path.exists(path):
            with open(path, "rb") as f:
                raw = f.read()
            priv = crypto.load_private_key(raw)
        else:
            priv, _ = crypto.generate_keypair()
            with open(path, "wb") as f:
                f.write(crypto.serialize_private_key(priv))
        pub = priv.public_key()
        return priv, pub

    def _load_or_generate_x25519(self, name: str):
        path = self._key_path(name)
        if os.path.exists(path):
            with open(path, "rb") as f:
                raw = f.read()
            priv = crypto.load_x25519_private(raw)
        else:
            priv, _ = crypto.generate_x25519_keypair()
            from cryptography.hazmat.primitives import serialization
            raw = priv.private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption(),
            )
            with open(path, "wb") as f:
                f.write(raw)
        return priv, priv.public_key()

    # ── Event system ──────────────────────────────────────────────────────────

    def on(self, event: str, cb: Callable):
        self._event_listeners.setdefault(event, []).append(cb)

    def _emit(self, event: str, *args, **kwargs):
        for cb in self._event_listeners.get(event, []):
            try:
                cb(*args, **kwargs)
            except Exception as e:
                logger.warning("Listener error for %s: %s", event, e)

    # ── Peer discovered ───────────────────────────────────────────────────────

    def _on_peer_discovered(self, peer_info: dict):
        pid = peer_info.get("node_id", "")
        if not pid or pid == self.node_id:
            return

        # Register in ledger
        self._ledger.add_or_update_node(
            pid,
            peer_info.get("public_key_hex", ""),
            peer_info.get("alias", ""),
            peer_info.get("x25519_ik_hex", ""),
            peer_info.get("x25519_spk_hex", ""),
        )

        self._emit("peer_discovered", peer_info)

        # Deliver any stored offline messages
        stored = self._sf.retrieve(pid)
        if stored:
            for pkt in stored:
                self._send_raw(peer_info["ip"], peer_info["tcp_port"], pkt)

        # Initiate session if none exists
        if not self._session_mgr.has_session(pid):
            self._initiate_handshake(peer_info)

    # ── Handshake ─────────────────────────────────────────────────────────────

    def _initiate_handshake(self, peer_info: dict):
        pid = peer_info["node_id"]
        ik_hex  = peer_info.get("x25519_ik_hex", "")
        spk_hex = peer_info.get("x25519_spk_hex", "")
        if not ik_hex or not spk_hex:
            return

        their_ik  = crypto.load_x25519_public(bytes.fromhex(ik_hex))
        their_spk = crypto.load_x25519_public(bytes.fromhex(spk_hex))

        ek_priv, ek_pub = crypto.generate_x25519_keypair()
        init_nonce = os.urandom(16)

        from cryptography.hazmat.primitives import serialization as _ser
        ek_priv_raw = ek_priv.private_bytes(
            encoding=_ser.Encoding.Raw,
            format=_ser.PrivateFormat.Raw,
            encryption_algorithm=_ser.NoEncryption(),
        )

        shared_secret = crypto.x3dh_initiator(
            my_ik_priv    = self._x_ik_priv,
            my_ek_priv    = ek_priv,
            their_ik_pub  = their_ik,
            their_spk_pub = their_spk,
        )

        tmp_sid = hashlib.sha256(
            init_nonce + b"\x00" * 16 + self.node_id.encode() + pid.encode()
        ).hexdigest()

        with self._hs_lock:
            self._pending_hs[pid] = (init_nonce, ek_priv_raw, shared_secret, tmp_sid)

        hs_data = {
            "init_nonce":  init_nonce.hex(),
            "ek_pub_hex":  crypto.serialize_x25519_public(ek_pub).hex(),
        }
        payload_b64 = base64.b64encode(json.dumps(hs_data).encode()).decode()
        pkt = build_packet(
            msg_type    = MsgType.HANDSHAKE,
            sender_id   = self.node_id,
            receiver_id = pid,
            session_id  = tmp_sid,
            payload_b64 = payload_b64,
            signature   = "",
        )
        self._send_raw(peer_info["ip"], peer_info["tcp_port"], pkt)

    def _handle_handshake(self, pkt: dict, addr: tuple):
        pid = pkt["sender_id"]
        node_rec = self._ledger.get_node(pid)
        if not node_rec:
            return

        hs_data = json.loads(base64.b64decode(pkt["payload"]).decode())
        init_nonce = bytes.fromhex(hs_data["init_nonce"])
        their_ek   = crypto.load_x25519_public(bytes.fromhex(hs_data["ek_pub_hex"]))
        their_ik   = crypto.load_x25519_public(bytes.fromhex(node_rec["x25519_ik_hex"]))

        resp_nonce = os.urandom(16)
        shared_secret = crypto.x3dh_responder(
            my_ik_priv  = self._x_ik_priv,
            my_spk_priv = self._x_spk_priv,
            their_ik_pub= their_ik,
            their_ek_pub= their_ek,
        )
        sid = hashlib.sha256(
            init_nonce + resp_nonce + pid.encode() + self.node_id.encode()
        ).hexdigest()

        from .session import Session as _Sess
        sess = _Sess(session_id=sid, peer_id=pid, shared_key=shared_secret)
        self._session_mgr._sessions[sid] = sess
        self._session_mgr._peer_sessions[pid] = sid

        resp_data = {"resp_nonce": resp_nonce.hex(), "init_nonce": init_nonce.hex()}
        payload_b64 = base64.b64encode(json.dumps(resp_data).encode()).decode()
        resp_pkt = build_packet(
            msg_type    = MsgType.HANDSHAKE,
            sender_id   = self.node_id,
            receiver_id = pid,
            session_id  = sid,
            payload_b64 = payload_b64,
            signature   = "",
            extra       = {"hs_role": "responder"},
        )
        
        peer_address = self._peer_addr(pid)
        if peer_address:
            self._send_raw(peer_address[0], peer_address[1], resp_pkt)
        self._emit("session_established", pid, sid)

    def _handle_handshake_response(self, pkt: dict):
        pid = pkt["sender_id"]
        hs_data = json.loads(base64.b64decode(pkt["payload"]).decode())
        init_nonce = bytes.fromhex(hs_data["init_nonce"])
        resp_nonce = bytes.fromhex(hs_data["resp_nonce"])

        with self._hs_lock:
            pending = self._pending_hs.pop(pid, None)
        if not pending:
            return

        _, _, shared_secret, old_sid = pending
        sid = hashlib.sha256(
            init_nonce + resp_nonce + self.node_id.encode() + pid.encode()
        ).hexdigest()

        from .session import Session as _Sess
        sess = _Sess(session_id=sid, peer_id=pid, shared_key=shared_secret)
        self._session_mgr._sessions[sid] = sess
        self._session_mgr._peer_sessions[pid] = sid

        self._emit("session_established", pid, sid)

    # ── Packet dispatch ───────────────────────────────────────────────────────

    def _on_packet_received(self, pkt: dict, addr: tuple):
        if not validate_packet(pkt):
            return
        t = pkt.get("type")
        if t == MsgType.HANDSHAKE.value:
            if pkt.get("hs_role") == "responder":
                self._handle_handshake_response(pkt)
            else:
                self._handle_handshake(pkt, addr)
        elif t in (MsgType.P2P_MSG.value, MsgType.GROUP_MSG.value):
            self._handle_message(pkt)
        elif t == MsgType.FILE_CHUNK.value:
            self._handle_file_chunk(pkt)
        elif t == MsgType.PKI_SYNC.value:
            self._handle_pki_sync(pkt)

    # ── Message handling ──────────────────────────────────────────────────────

    def _handle_message(self, pkt: dict):
        pid     = pkt["sender_id"]
        sid     = pkt["session_id"]
        sess    = self._session_mgr.get_session(sid)
        if not sess:
            return

        # Verify signature
        node_rec = self._ledger.get_node(pid)
        if node_rec:
            try:
                pub = crypto.load_public_key(bytes.fromhex(node_rec["public_key_hex"]))
                ok  = crypto.verify_context(
                    pub, pkt["signature"],
                    pkt["sender_id"], pkt["receiver_id"],
                    pkt["session_id"], pkt["msg_id"],
                    pkt.get("prev_hash", "0" * 64), pkt["payload"],
                )
                if not ok:
                    logger.warning("Signature verification failed for msg %s", pkt["msg_id"])
                    return
            except Exception as e:
                logger.warning("Sig error: %s", e)

        try:
            plaintext = self._session_mgr.decrypt_message(sess, pkt["payload"])
        except Exception as e:
            logger.warning("Decryption failed: %s", e)
            return

        # Hash-chain
        content_hash = packet_content_hash(pkt)
        self._ledger.add_message_hash(
            pkt["msg_id"], pid, pkt["receiver_id"],
            sid, pkt.get("prev_hash", ""), content_hash,
        )
        self._session_mgr.update_hash_chain(sess, content_hash)

        content_str = plaintext.decode("utf-8")
        is_broadcast = content_str.startswith("BCAST:")

        self._ledger.save_message(
            msg_id=pkt["msg_id"],
            sender_id=pid,
            target_id="#BROADCAST" if is_broadcast else pkt["receiver_id"],
            content=content_str,
            is_file=False,
            file_path="",
            file_name="",
            is_broadcast=is_broadcast,
            timestamp=pkt["timestamp"],
        )

        # Handle Sync Request internally
        if content_str == "__SYNC_REQ__":
            self._handle_sync_req(pid)
            return
        elif content_str.startswith("__SYNC_REP__:"):
            self._handle_sync_rep(pid, content_str[13:])
            return

        self._emit("message_received", {
            "msg_id":    pkt["msg_id"],
            "sender_id": pid,
            "session_id": sid,
            "timestamp": pkt["timestamp"],
            "content":   content_str,
            "is_group":  pkt["type"] == MsgType.GROUP_MSG.value,
            "receiver_id": pkt["receiver_id"],
        })

    def _handle_sync_req(self, peer_id: str):
        # We received a sync request from peer_id. Send them our history with them and the broadcast history.
        # This implementation simplifies by only syncing P2P messages with this peer to avoid massive blobs.
        history = self._ledger.get_chat_history(self.node_id, peer_id, 200)
        resp_data = json.dumps(history)
        self.send_message(peer_id, f"__SYNC_REP__:{resp_data}")

    def _handle_sync_rep(self, peer_id: str, payload: str):
        try:
            history = json.loads(payload)
            for m in history:
                self._ledger.save_message(
                    msg_id=m["msg_id"],
                    sender_id=m["sender_id"],
                    target_id=m["target_id"],
                    content=m["content"],
                    is_file=m["is_file"],
                    file_path=m["file_path"],
                    file_name=m["file_name"],
                    is_broadcast=m["is_broadcast"],
                    timestamp=m["timestamp"]
                )
            self._emit("sync_completed", peer_id)
        except Exception as e:
            logger.warning("Failed to parse sync rep: %s", e)

    # ── File chunk handling ───────────────────────────────────────────────────

    def _handle_file_chunk(self, pkt: dict):
        pid  = pkt["sender_id"]
        sid  = pkt["session_id"]
        sess = self._session_mgr.get_session(sid)
        if not sess:
            return
        try:
            raw = self._session_mgr.decrypt_message(sess, pkt["payload"])
            meta_len = int.from_bytes(raw[:4], "big")
            meta = json.loads(raw[4:4+meta_len])
            data = raw[4+meta_len:]
        except Exception as e:
            logger.warning("File chunk decrypt error: %s", e)
            return
        self._emit("file_chunk_received", pkt["sender_id"], meta, data)

    # ── PKI sync ──────────────────────────────────────────────────────────────

    def _handle_pki_sync(self, pkt: dict):
        try:
            nodes = json.loads(base64.b64decode(pkt["payload"]).decode())
            for n in nodes:
                self._ledger.add_or_update_node(
                    n["node_id"], n["public_key_hex"], n.get("alias", ""),
                    n.get("x25519_ik_hex",""), n.get("x25519_spk_hex",""),
                )
        except Exception as e:
            logger.debug("PKI sync error: %s", e)

    # ── Send helpers ──────────────────────────────────────────────────────────

    def _send_raw(self, ip: str, tcp_port: int, pkt: dict):
        self._transport.send_packet(ip, tcp_port, pkt)

    def _peer_addr(self, peer_id: str) -> Optional[tuple]:
        peers = self._discovery.get_peers()
        p = peers.get(peer_id)
        if p:
            return p["ip"], p["tcp_port"]
        node = self._ledger.get_node(peer_id)
        return None

    # ── Public API ────────────────────────────────────────────────────────────

    def send_message(self, peer_id: str, content: str) -> bool:
        sess = self._session_mgr.get_session_for_peer(peer_id)
        if not sess:
            self._queue_message(peer_id, content)
            return False

        payload_b64, prev_hash = self._session_mgr.encrypt_message(
            sess, content.encode("utf-8")
        )
        msg_id = str(uuid.uuid4())
        sig = crypto.sign_context(
            self._ed_priv, self.node_id, peer_id,
            sess.session_id, msg_id, prev_hash, payload_b64,
        )
        pkt = build_packet(
            msg_type    = MsgType.GROUP_MSG if sess.is_group else MsgType.P2P_MSG,
            sender_id   = self.node_id,
            receiver_id = peer_id,
            session_id  = sess.session_id,
            payload_b64 = payload_b64,
            signature   = sig,
            prev_hash   = prev_hash,
            msg_id      = msg_id,
        )
        content_hash = packet_content_hash(pkt)
        self._ledger.add_message_hash(msg_id, self.node_id, peer_id,
                                      sess.session_id, prev_hash, content_hash)
        self._session_mgr.update_hash_chain(sess, content_hash)

        is_broadcast = content.startswith("BCAST:")
        self._ledger.save_message(
            msg_id=msg_id,
            sender_id=self.node_id,
            target_id="#BROADCAST" if is_broadcast else peer_id,
            content=content,
            is_file=False,
            file_path="",
            file_name="",
            is_broadcast=is_broadcast,
            timestamp=int(time.time()),
        )

        addr = self._peer_addr(peer_id)
        if addr:
            return self._send_raw(addr[0], addr[1], pkt) or True
        else:
            self._sf.store(peer_id, pkt)
            return False

    def _queue_message(self, peer_id: str, content: str):
        """Hold message until session is established."""
        def _wait():
            for _ in range(30):
                time.sleep(1)
                sess = self._session_mgr.get_session_for_peer(peer_id)
                if sess:
                    self.send_message(peer_id, content)
                    return
        threading.Thread(target=_wait, daemon=True).start()

    def send_file(self, peer_id: str, file_path: str, progress_cb: Optional[Callable] = None, is_broadcast: bool = False) -> bool:
        sess = self._session_mgr.get_session_for_peer(peer_id)
        if not sess:
            return False

        filename = os.path.basename(file_path)
        file_size = os.path.getsize(file_path)
        file_id   = str(uuid.uuid4())
        total_chunks = (file_size + _CHUNK_SIZE - 1) // _CHUNK_SIZE

        self._ledger.save_message(
            msg_id=file_id,
            sender_id=self.node_id,
            target_id="#BROADCAST" if is_broadcast else peer_id,
            content=f"发送文件: {filename}",
            is_file=True,
            file_path=file_path,
            file_name=filename,
            is_broadcast=is_broadcast,
            timestamp=int(time.time()),
        )

        def _send():
            with open(file_path, "rb") as f:
                for chunk_idx in range(total_chunks):
                    chunk_data = f.read(_CHUNK_SIZE)
                    meta = {
                        "file_id": file_id,
                        "filename": filename,
                        "file_size": file_size,
                        "chunk_idx": chunk_idx,
                        "total_chunks": total_chunks,
                        "is_broadcast": is_broadcast,
                    }
                    meta_bytes = json.dumps(meta).encode()
                    payload_bytes = (len(meta_bytes).to_bytes(4, "big")
                                     + meta_bytes + chunk_data)

                    payload_b64, prev_hash = self._session_mgr.encrypt_message(
                        sess, payload_bytes
                    )
                    pkt = build_packet(
                        msg_type    = MsgType.FILE_CHUNK,
                        sender_id   = self.node_id,
                        receiver_id = peer_id,
                        session_id  = sess.session_id,
                        payload_b64 = payload_b64,
                        signature   = "",
                        prev_hash   = prev_hash,
                    )
                    addr = self._peer_addr(peer_id)
                    if addr:
                        self._send_raw(addr[0], addr[1], pkt)
                    if progress_cb:
                        progress_cb(chunk_idx + 1, total_chunks)

        threading.Thread(target=_send, daemon=True).start()
        return True

    def get_peers(self) -> Dict[str, dict]:
        return self._discovery.get_peers()

    def get_all_known_nodes(self) -> list:
        return self._ledger.get_all_nodes()

    def get_fingerprint_text(self) -> str:
        return crypto.fingerprint(self._ed_pub)

    def get_my_alias(self) -> str:
        return self.config.node_alias

    def add_trust(self, target_id: str) -> bool:
        target_node = self._ledger.get_node(target_id)
        if not target_node:
            return False
        msg = f"TRUST:{self.node_id}:{target_id}:{int(time.time())}"
        sig = crypto.sign_context(
            self._ed_priv, self.node_id, target_id,
            "trust", "trust", "0" * 64, base64.b64encode(msg.encode()).decode()
        )
        self._ledger.add_trust_sig(self.node_id, target_id, sig)
        return True

    def broadcast_pki(self):
        """Send our ledger to all peers (PKI sync)."""
        nodes = self._ledger.get_all_nodes()
        payload = base64.b64encode(json.dumps(nodes).encode()).decode()
        pkt = build_packet(
            msg_type    = MsgType.PKI_SYNC,
            sender_id   = self.node_id,
            receiver_id = "broadcast",
            session_id  = self.config.network_id_hash[:16],
            payload_b64 = payload,
            signature   = "",
        )
        for peer_id, peer in self._discovery.get_peers().items():
            self._send_raw(peer["ip"], peer["tcp_port"], pkt)
