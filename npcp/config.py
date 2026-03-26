"""
Runtime configuration for PLTalk / NPCP.
All settings are persisted to ~/.pltalk/<profile>/config.json
"""
import hashlib
import json
import os
import shutil
import tempfile
import atexit
from dataclasses import asdict, dataclass, field
from typing import Callable, List

_TMP_DIR = tempfile.mkdtemp(prefix=".pltalk_tmp_", dir=os.getcwd())
_DEFAULT_PROFILE = os.environ.get("PLTALK_PROFILE", "default")
_DEFAULT_BASE    = _TMP_DIR

def _cleanup_base():
    shutil.rmtree(_TMP_DIR, ignore_errors=True)

atexit.register(_cleanup_base)


@dataclass
class Config:
    # ── Identity ─────────────────────────────────────────────────────────────
    node_alias: str = "Anonymous"
    # Stored as plain text; hashed on load into network_id_hash
    network_id: str = "PLTalk_Default"

    # ── Network / Discovery ───────────────────────────────────────────────────
    udp_discovery_port: int = 9527
    tcp_listen_port: int    = 9528
    broadcast_interval: int = 5          # seconds

    # ── Security / Storage ────────────────────────────────────────────────────
    enable_store_and_forward: bool = False
    ledger_storage_path: str       = ""  # filled in by load()

    # ── Derived (not persisted) ───────────────────────────────────────────────
    network_id_hash: str = field(default="", init=False, repr=False)
    profile: str         = field(default=_DEFAULT_PROFILE, init=False, repr=False)
    profile_dir: str     = field(default="", init=False, repr=False)

    # ── Change listeners ──────────────────────────────────────────────────────
    _listeners: List[Callable] = field(default_factory=list, init=False, repr=False)

    # ─────────────────────────────────────────────────────────────────────────
    def __post_init__(self):
        self._recompute_hash()

    def _recompute_hash(self):
        self.network_id_hash = hashlib.sha256(
            self.network_id.encode("utf-8")
        ).hexdigest()

    # ── Persistence ───────────────────────────────────────────────────────────
    @classmethod
    def load(cls, profile: str = _DEFAULT_PROFILE) -> "Config":
        profile_dir = os.path.join(_DEFAULT_BASE, profile)
        os.makedirs(profile_dir, exist_ok=True)
        path = os.path.join(profile_dir, "config.json")

        cfg = cls()
        cfg.profile     = profile
        cfg.profile_dir = profile_dir

        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            _PERSISTED = {
                "node_alias", "network_id", "udp_discovery_port",
                "tcp_listen_port", "broadcast_interval",
                "enable_store_and_forward", "ledger_storage_path",
            }
            for k, v in data.items():
                if k in _PERSISTED:
                    setattr(cfg, k, v)

        if not cfg.ledger_storage_path:
            cfg.ledger_storage_path = os.path.join(profile_dir, "ledger.db")

        cfg._recompute_hash()
        return cfg

    def save(self):
        path = os.path.join(self.profile_dir, "config.json")
        os.makedirs(self.profile_dir, exist_ok=True)
        data = {
            "node_alias":              self.node_alias,
            "network_id":              self.network_id,
            "udp_discovery_port":      self.udp_discovery_port,
            "tcp_listen_port":         self.tcp_listen_port,
            "broadcast_interval":      self.broadcast_interval,
            "enable_store_and_forward":self.enable_store_and_forward,
            "ledger_storage_path":     self.ledger_storage_path,
        }
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

    # ── Live update ───────────────────────────────────────────────────────────
    def update(self, **kwargs):
        """Update fields at runtime and notify listeners."""
        for k, v in kwargs.items():
            if hasattr(self, k):
                setattr(self, k, v)
        if "network_id" in kwargs:
            self._recompute_hash()
        self.save()
        for cb in self._listeners:
            try:
                cb(self)
            except Exception:
                pass

    def add_listener(self, cb: Callable):
        self._listeners.append(cb)
