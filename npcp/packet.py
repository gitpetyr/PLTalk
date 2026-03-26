"""
NPCP Packet Schema V2 — build, parse, and validate JSON packets.
"""
import base64
import hashlib
import json
import time
import uuid
from enum import Enum
from typing import Optional


class MsgType(str, Enum):
    HELLO       = "HELLO"
    P2P_MSG     = "P2P_MSG"
    GROUP_MSG   = "GROUP_MSG"
    PKI_SYNC    = "PKI_SYNC"
    FILE_CHUNK  = "FILE_CHUNK"
    ACK         = "ACK"
    HANDSHAKE   = "HANDSHAKE"
    STORE_FWD   = "STORE_FWD"


def build_packet(
    msg_type: MsgType,
    sender_id: str,
    receiver_id: str,
    session_id: str,
    payload_b64: str,
    signature: str,
    prev_hash: str = "0" * 64,
    msg_id: Optional[str] = None,
    extra: Optional[dict] = None,
) -> dict:
    pkt = {
        "version":     "2.0",
        "msg_id":      msg_id or str(uuid.uuid4()),
        "session_id":  session_id,
        "sender_id":   sender_id,
        "receiver_id": receiver_id,
        "timestamp":   int(time.time()),
        "type":        msg_type.value if isinstance(msg_type, MsgType) else msg_type,
        "prev_hash":   prev_hash,
        "payload":     payload_b64,
        "signature":   signature,
    }
    if extra:
        pkt.update(extra)
    return pkt


def serialize(pkt: dict) -> bytes:
    return json.dumps(pkt, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def deserialize(data: bytes) -> dict:
    return json.loads(data.decode("utf-8"))


def packet_content_hash(pkt: dict) -> str:
    """SHA-256 of the canonical packet (used for hash-chain)."""
    canonical = json.dumps(
        {k: pkt[k] for k in sorted(pkt.keys())},
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def validate_packet(pkt: dict) -> bool:
    required = {"version", "msg_id", "session_id", "sender_id",
                "receiver_id", "timestamp", "type", "payload", "signature"}
    return required.issubset(pkt.keys())


def build_hello_payload(
    node_id: str,
    public_key_hex: str,
    alias: str,
    network_id_hash: str,
    tcp_port: int,
    x25519_ik_hex: str = "",
    x25519_spk_hex: str = "",
) -> str:
    """Build Base64-encoded HELLO payload (plaintext — no sensitive data)."""
    data = {
        "node_id":         node_id,
        "public_key_hex":  public_key_hex,
        "alias":           alias,
        "network_id_hash": network_id_hash,
        "tcp_port":        tcp_port,
        "x25519_ik_hex":   x25519_ik_hex,
        "x25519_spk_hex":  x25519_spk_hex,
    }
    return base64.b64encode(json.dumps(data).encode()).decode()


def parse_hello_payload(payload_b64: str) -> dict:
    return json.loads(base64.b64decode(payload_b64).decode())
