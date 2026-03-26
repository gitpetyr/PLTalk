"""
Public API facade for the UI layer.
"""
from typing import Callable, List, Dict, Optional
from .node import Node
from .config import Config


class API:
    def __init__(self, config: Config):
        self.config = config
        self._node  = Node(config)

    # ── Lifecycle ─────────────────────────────────────────────────────────────
    def start(self):  self._node.start()
    def stop(self):   self._node.stop()

    # ── Properties ────────────────────────────────────────────────────────────
    @property
    def node_id(self) -> str:      return self._node.node_id
    @property
    def alias(self) -> str:        return self.config.node_alias
    @property
    def fingerprint(self) -> str:  return self._node.get_fingerprint_text()

    # ── Events (subscribe) ────────────────────────────────────────────────────
    def on(self, event: str, cb: Callable):
        """
        Available events:
          peer_discovered(peer_info: dict)
          session_established(peer_id: str, session_id: str)
          message_received(msg: dict)
          file_chunk_received(sender_id: str, meta: dict, data: bytes)
        """
        self._node.on(event, cb)

    # ── Messaging ─────────────────────────────────────────────────────────────
    def send_message(self, peer_id: str, content: str) -> bool:
        return self._node.send_message(peer_id, content)

    def send_file(self, peer_id: str, file_path: str,
                  progress_cb: Optional[Callable] = None) -> bool:
        return self._node.send_file(peer_id, file_path, progress_cb)

    # ── Peers ─────────────────────────────────────────────────────────────────
    def get_peers(self) -> Dict[str, dict]:
        return self._node.get_peers()

    def get_all_known_nodes(self) -> list:
        return self._node.get_all_known_nodes()

    # ── Trust ─────────────────────────────────────────────────────────────────
    def add_trust(self, target_id: str) -> bool:
        return self._node.add_trust(target_id)

    # ── Config ────────────────────────────────────────────────────────────────
    def update_config(self, **kwargs):
        self.config.update(**kwargs)

    # ── PKI ───────────────────────────────────────────────────────────────────
    def broadcast_pki(self):
        self._node.broadcast_pki()
