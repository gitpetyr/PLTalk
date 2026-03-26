"""
Cryptographic primitives for NPCP.

Provides:
  - Ed25519 keypair generation & signing (context-bound)
  - X3DH async key exchange
  - AES-256-GCM symmetric encryption
  - SHA-256 helpers
  - Human-readable public-key fingerprint
"""
import base64
import hashlib
import os
from typing import Tuple

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


# ─── Helpers ─────────────────────────────────────────────────────────────────

def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_bytes(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


# ─── Ed25519 Identity Keys ────────────────────────────────────────────────────

def generate_keypair() -> Tuple[Ed25519PrivateKey, Ed25519PublicKey]:
    """Generate a new Ed25519 identity keypair."""
    priv = Ed25519PrivateKey.generate()
    return priv, priv.public_key()


def serialize_private_key(priv: Ed25519PrivateKey) -> bytes:
    return priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )


def serialize_public_key(pub: Ed25519PublicKey) -> bytes:
    return pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def load_private_key(raw: bytes) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(raw)


def load_public_key(raw: bytes) -> Ed25519PublicKey:
    return Ed25519PublicKey.from_public_bytes(raw)


def node_id_from_pubkey(pub: Ed25519PublicKey) -> str:
    """NodeID = SHA-256 hex of raw public key bytes."""
    return sha256_hex(serialize_public_key(pub))


def fingerprint(pub: Ed25519PublicKey) -> str:
    """
    Human-readable fingerprint for out-of-band verification.
    Format: 'XX:XX:XX:...' (32 bytes → 64 hex chars grouped by 2 with colon).
    """
    raw = sha256_bytes(serialize_public_key(pub))
    return ":".join(f"{b:02X}" for b in raw)


# ─── Context-Bound Signature ──────────────────────────────────────────────────

def _build_context(
    sender_id: str,
    receiver_id: str,
    session_id: str,
    msg_id: str,
    prev_hash: str,
    payload_b64: str,
) -> bytes:
    ctx = f"{sender_id}|{receiver_id}|{session_id}|{msg_id}|{prev_hash}|{payload_b64}"
    return sha256_bytes(ctx.encode("utf-8"))


def sign_context(
    priv: Ed25519PrivateKey,
    sender_id: str,
    receiver_id: str,
    session_id: str,
    msg_id: str,
    prev_hash: str,
    payload_b64: str,
) -> str:
    """Returns Base64-encoded Ed25519 signature over SHA-256(context string)."""
    ctx_hash = _build_context(sender_id, receiver_id, session_id, msg_id, prev_hash, payload_b64)
    sig = priv.sign(ctx_hash)          # Ed25519 signs the 32-byte hash directly
    return base64.b64encode(sig).decode()


def verify_context(
    pub: Ed25519PublicKey,
    signature_b64: str,
    sender_id: str,
    receiver_id: str,
    session_id: str,
    msg_id: str,
    prev_hash: str,
    payload_b64: str,
) -> bool:
    """Verify a context-bound signature. Returns True on success."""
    try:
        ctx_hash = _build_context(sender_id, receiver_id, session_id, msg_id, prev_hash, payload_b64)
        sig = base64.b64decode(signature_b64)
        pub.verify(sig, ctx_hash)
        return True
    except Exception:
        return False


# ─── AES-256-GCM ─────────────────────────────────────────────────────────────

def aes_gcm_encrypt(key: bytes, plaintext: bytes) -> Tuple[bytes, bytes]:
    """
    Encrypt plaintext with AES-256-GCM.
    Returns (ciphertext_with_tag, nonce). Key must be 32 bytes.
    """
    nonce = os.urandom(12)
    aesgcm = AESGCM(key)
    ct = aesgcm.encrypt(nonce, plaintext, None)
    return ct, nonce


def aes_gcm_decrypt(key: bytes, ciphertext: bytes, nonce: bytes) -> bytes:
    """Decrypt AES-256-GCM ciphertext. Raises on authentication failure."""
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, None)


def encode_payload(ciphertext: bytes, nonce: bytes) -> str:
    """Pack (nonce || ciphertext) and return as Base64 string."""
    return base64.b64encode(nonce + ciphertext).decode()


def decode_payload(payload_b64: str) -> Tuple[bytes, bytes]:
    """Unpack Base64 payload → (ciphertext, nonce)."""
    raw = base64.b64decode(payload_b64)
    nonce = raw[:12]
    ciphertext = raw[12:]
    return ciphertext, nonce


# ─── X3DH (Extended Triple Diffie-Hellman) ───────────────────────────────────
# Simplified X3DH for async E2EE key agreement.
# Each node has an identity key (Ed25519→X25519 converted) + signed pre-key.

def _ed25519_raw_to_x25519_private(raw32: bytes) -> X25519PrivateKey:
    """Derive X25519 private key from Ed25519 seed (first 32 bytes)."""
    return X25519PrivateKey.from_private_bytes(raw32)


def _hkdf_derive(ikm: bytes, length: int = 32, info: bytes = b"NPCP-X3DH") -> bytes:
    h = HKDF(algorithm=hashes.SHA256(), length=length, salt=None, info=info)
    return h.derive(ikm)


def generate_x25519_keypair() -> Tuple[X25519PrivateKey, X25519PublicKey]:
    """Generate an ephemeral X25519 keypair (for X3DH sessions)."""
    priv = X25519PrivateKey.generate()
    return priv, priv.public_key()


def serialize_x25519_public(pub: X25519PublicKey) -> bytes:
    return pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def load_x25519_public(raw: bytes) -> X25519PublicKey:
    return X25519PublicKey.from_public_bytes(raw)


def load_x25519_private(raw: bytes) -> X25519PrivateKey:
    return X25519PrivateKey.from_private_bytes(raw)


def x3dh_initiator(
    my_ik_priv: X25519PrivateKey,   # my identity key (X25519)
    my_ek_priv: X25519PrivateKey,   # my ephemeral key
    their_ik_pub: X25519PublicKey,  # their identity key
    their_spk_pub: X25519PublicKey, # their signed pre-key
) -> bytes:
    """X3DH initiator side. Returns 32-byte shared secret."""
    dh1 = my_ik_priv.exchange(their_spk_pub)
    dh2 = my_ek_priv.exchange(their_ik_pub)
    dh3 = my_ek_priv.exchange(their_spk_pub)
    return _hkdf_derive(dh1 + dh2 + dh3)


def x3dh_responder(
    my_ik_priv: X25519PrivateKey,
    my_spk_priv: X25519PrivateKey,
    their_ik_pub: X25519PublicKey,
    their_ek_pub: X25519PublicKey,
) -> bytes:
    """X3DH responder side. Returns 32-byte shared secret."""
    dh1 = my_spk_priv.exchange(their_ik_pub)
    dh2 = my_ik_priv.exchange(their_ek_pub)
    dh3 = my_spk_priv.exchange(their_ek_pub)
    return _hkdf_derive(dh1 + dh2 + dh3)
