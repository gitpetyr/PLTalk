"""
UDP-based LAN discovery with Network_ID filtering.

- Broadcasts HELLO packets every `broadcast_interval` seconds.
- Silently drops any packet whose network_id_hash != local config.
- Fires on_peer_discovered(peer_info: dict) callback for new nodes.
"""
import json
import socket
import struct
import threading
import time
import logging
from typing import Callable, Dict, Optional

from .packet import build_hello_payload, build_packet, MsgType, parse_hello_payload, serialize, deserialize
from .config import Config

logger = logging.getLogger(__name__)

BROADCAST_ADDR = "255.255.255.255"
MAX_UDP_SIZE   = 65507


class Discovery:
    def __init__(self, config: Config, node_id: str, public_key_hex: str,
                 x25519_ik_hex: str = "", x25519_spk_hex: str = ""):
        self.config         = config
        self.node_id        = node_id
        self.public_key_hex = public_key_hex
        self.x25519_ik_hex  = x25519_ik_hex
        self.x25519_spk_hex = x25519_spk_hex

        self._running       = False
        self._peers: Dict[str, dict] = {}  # node_id → peer_info
        self._listeners: list = []

        self._tx_sock: Optional[socket.socket] = None
        self._rx_sock: Optional[socket.socket] = None

    # ── Public API ─────────────────────────────────────────────────────────────

    def add_listener(self, cb: Callable[[dict], None]):
        self._listeners.append(cb)

    def get_peers(self) -> Dict[str, dict]:
        now = time.time()
        timeout = max(15, self.config.broadcast_interval * 3)
        self._peers = {k: v for k, v in self._peers.items() if (now - v.get("last_seen", now)) < timeout}
        return dict(self._peers)

    def start(self):
        self._running = True
        self._setup_sockets()
        threading.Thread(target=self._rx_loop, daemon=True, name="npcp-udp-rx").start()
        threading.Thread(target=self._tx_loop, daemon=True, name="npcp-udp-tx").start()
        logger.info("Discovery started on UDP port %d", self.config.udp_discovery_port)

    def stop(self):
        self._running = False
        if self._rx_sock:
            try: self._rx_sock.close()
            except Exception: pass
        if self._tx_sock:
            try: self._tx_sock.close()
            except Exception: pass

    # ── Socket Setup ───────────────────────────────────────────────────────────

    def _setup_sockets(self):
        port = self.config.udp_discovery_port

        # TX socket (broadcast)
        self._tx_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._tx_sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        self._tx_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            self._tx_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        except AttributeError:
            pass

        # RX socket (listen)
        self._rx_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._rx_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            self._rx_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        except AttributeError:
            pass
        self._rx_sock.bind(("", port))
        self._rx_sock.settimeout(2.0)

    # ── TX loop ────────────────────────────────────────────────────────────────

    def _build_hello_packet(self) -> bytes:
        payload = build_hello_payload(
            node_id         = self.node_id,
            public_key_hex  = self.public_key_hex,
            alias           = self.config.node_alias,
            network_id_hash = self.config.network_id_hash,
            tcp_port        = self.config.tcp_listen_port,
            x25519_ik_hex   = self.x25519_ik_hex,
            x25519_spk_hex  = self.x25519_spk_hex,
        )
        pkt = build_packet(
            msg_type    = MsgType.HELLO,
            sender_id   = self.node_id,
            receiver_id = "broadcast",
            session_id  = self.config.network_id_hash[:16],
            payload_b64 = payload,
            signature   = "",          # HELLO packets are unauthenticated (public info)
        )
        return serialize(pkt)

    def _tx_loop(self):
        port = self.config.udp_discovery_port
        while self._running:
            try:
                data = self._build_hello_packet()
                self._tx_sock.sendto(data, (BROADCAST_ADDR, port))
            except Exception as e:
                logger.debug("Discovery TX error: %s", e)
            time.sleep(self.config.broadcast_interval)

    # ── RX loop ────────────────────────────────────────────────────────────────

    def _rx_loop(self):
        while self._running:
            try:
                data, addr = self._rx_sock.recvfrom(MAX_UDP_SIZE)
                self._handle_packet(data, addr)
            except socket.timeout:
                continue
            except OSError:
                break
            except Exception as e:
                logger.debug("Discovery RX error: %s", e)

    def _handle_packet(self, data: bytes, addr):
        try:
            pkt = deserialize(data)
        except Exception:
            return  # malformed — drop silently

        if pkt.get("type") != MsgType.HELLO.value:
            return

        try:
            info = parse_hello_payload(pkt["payload"])
        except Exception:
            return

        # ── Network isolation filter ──────────────────────────────────────────
        if info.get("network_id_hash") != self.config.network_id_hash:
            return  # different network — drop silently

        peer_id = info.get("node_id", "")
        if not peer_id or peer_id == self.node_id:
            return  # ignore self

        is_new = peer_id not in self._peers
        self._peers[peer_id] = {
            **info,
            "ip": addr[0],
            "last_seen": time.time(),
        }

        if is_new:
            logger.info("Discovered peer: %s (%s)", info.get("alias", "?"), addr[0])
            for cb in self._listeners:
                try:
                    cb(self._peers[peer_id])
                except Exception:
                    pass
        else:
            # Update last_seen, fire again for keepalive purposes
            for cb in self._listeners:
                try:
                    cb(self._peers[peer_id])
                except Exception:
                    pass
