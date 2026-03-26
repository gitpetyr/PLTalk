"""
TCP transport layer for NPCP.

- Listens for inbound TCP connections.
- Maintains a pool of outbound connections.
- Delivers deserialized packets to on_packet_received callbacks.
"""
import json
import logging
import socket
import struct
import threading
from typing import Callable, Dict, Optional, Tuple

from .packet import deserialize, serialize

logger = logging.getLogger(__name__)

# 4-byte big-endian length prefix
_HDR = "!I"
_HDR_SIZE = struct.calcsize(_HDR)


def _send_framed(sock: socket.socket, data: bytes):
    sock.sendall(struct.pack(_HDR, len(data)) + data)


def _recv_framed(sock: socket.socket) -> bytes:
    hdr = _recv_exact(sock, _HDR_SIZE)
    length = struct.unpack(_HDR, hdr)[0]
    return _recv_exact(sock, length)


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Connection closed")
        buf += chunk
    return buf


class Transport:
    def __init__(self, host: str = "0.0.0.0", port: int = 9528):
        self.host = host
        self.port = port
        self._running = False
        self._server_sock: Optional[socket.socket] = None
        self._connections: Dict[str, socket.socket] = {}  # addr → sock
        self._lock = threading.Lock()
        self._listeners: list = []

    def add_listener(self, cb: Callable[[dict, Tuple[str, int]], None]):
        self._listeners.append(cb)

    def start(self):
        self._running = True
        self._server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server_sock.bind((self.host, self.port))
        self.port = self._server_sock.getsockname()[1]
        self._server_sock.listen(20)
        self._server_sock.settimeout(2.0)
        threading.Thread(target=self._accept_loop, daemon=True, name="npcp-tcp-accept").start()
        logger.info("Transport listening on TCP %s:%d", self.host, self.port)

    def stop(self):
        self._running = False
        if self._server_sock:
            try: self._server_sock.close()
            except Exception: pass
        with self._lock:
            for s in self._connections.values():
                try: s.close()
                except Exception: pass
            self._connections.clear()

    def send_packet(self, peer_ip: str, peer_tcp_port: int, pkt: dict) -> bool:
        addr_key = f"{peer_ip}:{peer_tcp_port}"
        data = serialize(pkt)
        with self._lock:
            sock = self._connections.get(addr_key)
            if sock:
                try:
                    _send_framed(sock, data)
                    return True
                except Exception:
                    sock.close()
                    del self._connections[addr_key]
        # Identify if target is localhost to bypass Mac Application Firewall blocking LAN IP
        connect_ip = peer_ip
        if peer_ip != "127.0.0.1":
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.connect(("8.8.8.8", 80))
                my_ip = s.getsockname()[0]
                s.close()
                if peer_ip == my_ip:
                    connect_ip = "127.0.0.1"
            except Exception:
                pass
                
        # Establish new connection
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5.0)
            sock.connect((connect_ip, peer_tcp_port))
            sock.settimeout(None)
            _send_framed(sock, data)
            with self._lock:
                self._connections[addr_key] = sock
            threading.Thread(
                target=self._handle_conn,
                args=(sock, (peer_ip, peer_tcp_port)),
                daemon=True,
                name=f"npcp-tcp-{addr_key}",
            ).start()
            return True
        except Exception as e:
            logger.debug("Cannot connect to %s: %s", addr_key, e)
            return False

    def _accept_loop(self):
        while self._running:
            try:
                conn, addr = self._server_sock.accept()
                threading.Thread(
                    target=self._handle_conn,
                    args=(conn, addr),
                    daemon=True,
                    name=f"npcp-tcp-{addr[0]}:{addr[1]}",
                ).start()
            except socket.timeout:
                continue
            except OSError:
                break
            except Exception as e:
                logger.debug("Accept error: %s", e)

    def _handle_conn(self, sock: socket.socket, addr: tuple):
        try:
            while self._running:
                data = _recv_framed(sock)
                try:
                    pkt = deserialize(data)
                    for cb in self._listeners:
                        try:
                            cb(pkt, addr)
                        except Exception:
                            pass
                except Exception as e:
                    logger.debug("Bad packet from %s: %s", addr, e)
        except Exception:
            pass
        finally:
            try: sock.close()
            except Exception: pass
